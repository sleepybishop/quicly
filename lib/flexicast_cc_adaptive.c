/*
 * Copyright (c) 2026 Joseph Calderon
 * SPDX-License-Identifier: MIT
 */
#include "flexicast_cc_internal.h"
#include "flexicast_member_map.h"

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define LOSS_SCALE 1000000U
#define EXTERNAL_LOAD_CLEAR_PPM 100000U
#define EXTERNAL_LOAD_CLEAR_EPOCHS 3U
#define STARTUP_PROBES 5U

typedef struct st_adaptive_member_t {
    uint64_t id;
    uint64_t last_feedback_epoch;
    uint32_t minimum_rtt;
    uint32_t previous_rtt;
    uint32_t rising_delay_epochs;
    uint64_t previous_rtt_epoch;
    uint32_t baseline_loss_ppm;
    uint32_t flat_loss_epochs;
    uint32_t baseline_delivery_ratio_ppm;
    uint64_t recent_delivery_rate;
    uint64_t last_delivery_sample_epoch;
    uint32_t recent_delivery_ratio_ppm;
    uint32_t degraded_delivery_epochs;
    int active;
} adaptive_member_t;

typedef struct st_adaptive_state_t {
    quicly_flexicast_cc_config_t config;
    quicly_flexicast_cc_hints_t hints;
    adaptive_member_t *members;
    size_t num_members;
    size_t num_active_members;
    flexicast_member_map_t member_map;
    uint64_t rate;
    uint64_t last_growth_epoch;
    uint64_t last_reduction_epoch;
    int64_t growth_blocked_until;
    int64_t next_timeout;
    uint32_t startup_probes;
    uint32_t unanswered_probes;
    uint64_t last_external_load_epoch;
    uint32_t external_load_clear_epochs;
    int external_load_seen;
} adaptive_state_t;

static adaptive_member_t *find_member(adaptive_state_t *state, uint64_t id)
{
    int slot = flexicast_member_map_find(&state->member_map, id);
    return slot >= 0 ? state->members + slot : NULL;
}

static adaptive_member_t *add_member(adaptive_state_t *state, uint64_t id)
{
    adaptive_member_t *member = find_member(state, id);
    if (member == NULL) {
        if (state->num_members == state->config.maximum_members)
            return NULL;
        flexicast_member_map_set(&state->member_map, id, state->num_members);
        member = state->members + state->num_members++;
        member->id = id;
    }
    if (!member->active) {
        member->active = 1;
        ++state->num_active_members;
    }
    return member;
}

static uint64_t control_interval(const adaptive_state_t *state)
{
    uint64_t interval = state->config.feedback_timeout_msec / 4;
    return interval < 25 ? 25 : interval;
}

static uint64_t control_epoch(const adaptive_state_t *state, int64_t now)
{
    return now < 0 ? 0 : (uint64_t)now / control_interval(state) + 1;
}

static int64_t deadline(int64_t now, uint64_t delay)
{
    if (now < 0)
        now = 0;
    return delay > (uint64_t)(INT64_MAX - now) ? INT64_MAX : now + (int64_t)delay;
}

static void update_output(adaptive_state_t *state, uint64_t member_id, uint32_t reason, quicly_flexicast_cc_output_t *output)
{
    /* The aggregate limit remains in effect across feedback and recovery
     * events. Keep the controller's rate bounded as well as its output. */
    state->rate = clamp_rate(&state->config, state->rate);
    if (state->hints.aggregate_rate_limit_bytes_per_second != 0 &&
        state->rate > state->hints.aggregate_rate_limit_bytes_per_second) {
        state->rate = state->hints.aggregate_rate_limit_bytes_per_second;
        reason |= QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT;
    }
    output->rate_bytes_per_second = state->rate;
    output->burst_bytes = burst_size(&state->config, state->rate);
    output->inflight_bytes = output->burst_bytes;
    output->limiting_member_id = member_id;
    output->next_timeout = state->num_active_members == 0 ? INT64_MAX : state->next_timeout;
    output->reason = reason;
}

static int adaptive_init(void *_state, const quicly_flexicast_cc_config_t *config, int64_t now,
                         quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    state->config = *config;
    if ((state->members = calloc(config->maximum_members, sizeof(*state->members))) == NULL ||
        flexicast_member_map_init(&state->member_map, config->maximum_members) != 0)
        return -1;
    state->rate = config->startup_rate_bytes_per_second;
    state->next_timeout = deadline(now, config->feedback_timeout_msec);
    update_output(state, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
    return 0;
}

static void adaptive_dispose(void *_state)
{
    adaptive_state_t *state = _state;
    flexicast_member_map_dispose(&state->member_map);
    free(state->members);
}

static void adaptive_on_member_added(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    (void)add_member(state, member_id);
    if (state->next_timeout <= now || state->next_timeout == INT64_MAX)
        state->next_timeout = deadline(now, state->config.feedback_timeout_msec);
    update_output(state, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static void suspend_member(adaptive_state_t *state, adaptive_member_t *member)
{
    if (!member->active)
        return;
    member->active = 0;
    --state->num_active_members;
    if (state->num_active_members == 0) {
        state->next_timeout = INT64_MAX;
        state->unanswered_probes = 0;
    }
}

static void adaptive_on_member_suspended(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    adaptive_member_t *member = find_member(state, member_id);
    (void)now;
    if (member != NULL)
        suspend_member(state, member);
    update_output(state, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static void adaptive_on_member_removed(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    adaptive_member_t *member = find_member(state, member_id);
    (void)now;
    if (member != NULL) {
        size_t slot = (size_t)(member - state->members), last = state->num_members - 1;
        suspend_member(state, member);
        flexicast_member_map_remove(&state->member_map, member_id);
        if (slot != last) {
            state->members[slot] = state->members[last];
            flexicast_member_map_set(&state->member_map, state->members[slot].id, slot);
        }
        memset(state->members + last, 0, sizeof(state->members[last]));
        --state->num_members;
    }
    update_output(state, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static void adaptive_on_epoch_reset(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    for (size_t i = 0; i != state->num_members; ++i) {
        state->members[i].last_feedback_epoch = 0;
        state->members[i].flat_loss_epochs = 0;
        state->members[i].degraded_delivery_epochs = 0;
        state->members[i].last_delivery_sample_epoch = 0;
        state->members[i].previous_rtt = 0;
        state->members[i].previous_rtt_epoch = 0;
        state->members[i].rising_delay_epochs = 0;
    }
    state->unanswered_probes = 0;
    state->last_growth_epoch = 0;
    state->last_reduction_epoch = 0;
    state->growth_blocked_until = now;
    state->next_timeout = deadline(now, state->config.feedback_timeout_msec);
    update_output(state, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static int update_delivery_ratio(adaptive_state_t *state, adaptive_member_t *member, const quicly_flexicast_feedback_t *feedback,
                                 int *fresh)
{
    uint32_t divisor = state->hints.delivery_rate_divisor != 0 ? state->hints.delivery_rate_divisor : 1;
    uint64_t expected = state->rate / divisor;
    if (expected == 0 || feedback->delivery_rate_bytes_per_second == 0)
        return 0;
    uint64_t sample_epoch = feedback->delivery_rate_sample_epoch != 0 ? feedback->delivery_rate_sample_epoch
                            : feedback->now > 0                       ? (uint64_t)feedback->now
                                                                      : feedback->epoch;
    *fresh = sample_epoch == 0 || sample_epoch > member->last_delivery_sample_epoch;
    if (*fresh) {
        uint64_t sample_rate = feedback->delivery_rate_bytes_per_second;
        if (member->recent_delivery_rate == 0)
            member->recent_delivery_rate = sample_rate;
        else
            member->recent_delivery_rate = member->recent_delivery_rate / 4 * 3 + sample_rate / 4 +
                                           (member->recent_delivery_rate % 4 * 3 + sample_rate % 4) / 4;
        member->last_delivery_sample_epoch = sample_epoch;
    }
    /* Smooth bytes/second, then normalize against the current physical rate.
     * Averaging ratios with old denominators repeats an already-applied cut. */
    uint32_t sample = member->recent_delivery_rate >= expected
                          ? LOSS_SCALE
                          : (uint32_t)((double)member->recent_delivery_rate / (double)expected * LOSS_SCALE);
    if (member->baseline_delivery_ratio_ppm == 0) {
        member->baseline_delivery_ratio_ppm = LOSS_SCALE;
    }
    member->recent_delivery_ratio_ppm = sample;
    uint32_t margin = member->baseline_delivery_ratio_ppm / 10;
    if (margin < 50000)
        margin = 50000;
    if ((uint64_t)member->recent_delivery_ratio_ppm + margin < member->baseline_delivery_ratio_ppm) {
        if (*fresh && member->degraded_delivery_epochs < 4)
            ++member->degraded_delivery_epochs;
    } else {
        member->degraded_delivery_epochs = 0;
    }
    return 1;
}

static void learn_clean_delivery_ratio(adaptive_member_t *member)
{
    if (member->baseline_delivery_ratio_ppm == 0 || member->recent_delivery_ratio_ppm == 0)
        return;
    if (member->degraded_delivery_epochs >= 4) {
        /* Stable delivery loss without queue growth is the radio baseline.
         * Neither repairs nor a congestion sample may teach this baseline. */
        member->baseline_delivery_ratio_ppm = member->recent_delivery_ratio_ppm;
        member->degraded_delivery_epochs = 0;
    } else if (member->degraded_delivery_epochs == 0) {
        uint32_t weight = member->recent_delivery_ratio_ppm > member->baseline_delivery_ratio_ppm ? 7 : 49;
        member->baseline_delivery_ratio_ppm =
            (uint32_t)(((uint64_t)member->baseline_delivery_ratio_ppm * weight + member->recent_delivery_ratio_ppm) / (weight + 1));
    }
}

static uint32_t loss_ppm(const quicly_flexicast_feedback_t *feedback)
{
    double total = (double)feedback->acked_packets + (double)feedback->lost_packets;
    return total == 0 ? 0 : (uint32_t)((double)feedback->lost_packets / total * LOSS_SCALE);
}

static int external_load(const adaptive_state_t *state)
{
    return state->external_load_seen || state->hints.external_load_queued_bytes != 0 ||
           state->hints.external_load_oldest_age_msec != 0;
}

static void grow_once(adaptive_state_t *state, int64_t now)
{
    uint32_t senders = state->hints.active_senders != 0 ? state->hints.active_senders : 1;
    uint64_t increase = (uint64_t)((double)state->rate / (8 * sqrt((double)senders)));
    if (increase < state->config.maximum_datagram_size)
        increase = state->config.maximum_datagram_size;
    uint64_t median = state->hints.median_sender_rate_bytes_per_second;
    if (median > state->rate && increase > median - state->rate)
        increase = median - state->rate;
    state->rate = increase_rate(state->rate, increase);
    state->last_growth_epoch = control_epoch(state, now);
}

static void adaptive_on_feedback(void *_state, const quicly_flexicast_feedback_t *feedback, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    adaptive_member_t *member = add_member(state, feedback->member_id);
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (member == NULL)
        return;
    if (feedback->epoch != 0 && member->last_feedback_epoch != 0 && feedback->epoch <= member->last_feedback_epoch) {
        update_output(state, feedback->member_id, reason, output);
        return;
    }
    if (feedback->epoch != 0)
        member->last_feedback_epoch = feedback->epoch;
    if (feedback->minimum_rtt_msec != 0)
        member->minimum_rtt = feedback->minimum_rtt_msec;
    state->unanswered_probes = 0;
    state->next_timeout = deadline(feedback->now, state->config.feedback_timeout_msec);
    uint64_t epoch = control_epoch(state, feedback->now);
    int fresh_delivery = 0;
    int has_delivery = update_delivery_ratio(state, member, feedback, &fresh_delivery);
    int delay_grew = queue_delay_grew(member->minimum_rtt, feedback->latest_rtt_msec);
    if (epoch > member->previous_rtt_epoch) {
        uint32_t margin = member->minimum_rtt / 20;
        if (margin < 1)
            margin = 1;
        if (member->previous_rtt != 0 && (uint64_t)feedback->latest_rtt_msec > (uint64_t)member->previous_rtt + margin) {
            if (member->rising_delay_epochs < 2)
                ++member->rising_delay_epochs;
        } else {
            member->rising_delay_epochs = 0;
        }
        member->previous_rtt = feedback->latest_rtt_msec;
        member->previous_rtt_epoch = epoch;
    }
    uint32_t observed_loss = loss_ppm(feedback);
    int congested = feedback->ecn_ce_count != 0 ||
                    (delay_grew && ((has_delivery && member->degraded_delivery_epochs != 0) || member->rising_delay_epochs >= 2 ||
                                    observed_loss > member->baseline_loss_ppm + 20000));

    if (congested || delay_grew) {
        /* Any member can veto growth. One sender clock bounds correlated
         * receiver reports, but persistent congestion can reduce again on the
         * next clock tick without first requiring an impossible clean queue. */
        state->growth_blocked_until = deadline(feedback->now, control_interval(state) * 2);
        state->startup_probes = STARTUP_PROBES;
        member->flat_loss_epochs = 0;
        reason = feedback->ecn_ce_count != 0 ? QUICLY_FLEXICAST_CC_REASON_ECN : QUICLY_FLEXICAST_CC_REASON_RTT;
        if (congested && epoch > state->last_reduction_epoch) {
            uint32_t factor = 850000;
            if (feedback->ecn_ce_count == 0) {
                factor =
                    has_delivery && member->degraded_delivery_epochs != 0
                        ? (uint32_t)((uint64_t)member->recent_delivery_ratio_ppm * LOSS_SCALE / member->baseline_delivery_ratio_ppm)
                        : 900000;
                if (factor < 500000)
                    factor = 500000;
                if (factor > 900000)
                    factor = 900000;
            }
            state->rate = scale_rate(state->rate, factor, LOSS_SCALE);
            state->last_reduction_epoch = epoch;
        }
    } else if (observed_loss > member->baseline_loss_ppm + 20000) {
        if (++member->flat_loss_epochs >= 3) {
            member->baseline_loss_ppm =
                member->baseline_loss_ppm == 0 ? observed_loss : (member->baseline_loss_ppm * 7 + observed_loss) / 8;
            member->flat_loss_epochs = 0;
        }
        reason = QUICLY_FLEXICAST_CC_REASON_LOSS;
    } else if (feedback->acked_packets != 0) {
        member->flat_loss_epochs = 0;
        reason = QUICLY_FLEXICAST_CC_REASON_ACK;
        int delivery_supports_growth = has_delivery && member->degraded_delivery_epochs == 0;
        int startup_probe = !has_delivery && state->startup_probes < STARTUP_PROBES;
        if (epoch > state->last_growth_epoch && epoch > state->last_reduction_epoch &&
            feedback->now >= state->growth_blocked_until && (delivery_supports_growth || startup_probe)) {
            if (external_load(state)) {
                reason |= QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD | QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN;
            } else {
                grow_once(state, feedback->now);
                if (startup_probe)
                    ++state->startup_probes;
            }
        }
    }
    if (fresh_delivery && !external_load(state) && !congested && !delay_grew)
        learn_clean_delivery_ratio(member);
    update_output(state, feedback->member_id, reason, output);
}

static void adaptive_on_timeout(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (state->num_active_members != 0 && now >= state->next_timeout) {
        if (++state->unanswered_probes >= 3) {
            state->rate /= 2;
            state->unanswered_probes = 0;
            state->startup_probes = STARTUP_PROBES;
            state->last_reduction_epoch = control_epoch(state, now);
            state->growth_blocked_until = deadline(now, control_interval(state) * 2);
        }
        /* At the floor, ordinary pacing still permits bounded probe traffic.
         * Silence never authorizes a rate increase or disables congestion. */
        state->next_timeout = deadline(now, state->config.feedback_timeout_msec);
        reason = QUICLY_FLEXICAST_CC_REASON_TIMEOUT;
    }
    update_output(state, 0, reason, output);
}

static void adaptive_set_hints(void *_state, const quicly_flexicast_cc_hints_t *hints, int64_t now,
                               quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_HINT;
    (void)now;
    int fresh_load_epoch = hints->external_load_epoch != 0 && hints->external_load_epoch > state->last_external_load_epoch;
    quicly_flexicast_cc_hints_t previous_hints = state->hints;
    state->hints = *hints;
    if (hints->external_load_epoch != 0 && !fresh_load_epoch) {
        /* A repeated or reordered measurement cannot change the load episode
         * or supply another recovery observation. Other hints remain live. */
        state->hints.external_load_epoch = previous_hints.external_load_epoch;
        state->hints.external_load_queued_bytes = previous_hints.external_load_queued_bytes;
        state->hints.external_load_oldest_age_msec = previous_hints.external_load_oldest_age_msec;
        state->hints.external_load_fraction_ppm = previous_hints.external_load_fraction_ppm;
    }
    if (hints->aggregate_rate_limit_bytes_per_second != 0 && state->rate > hints->aggregate_rate_limit_bytes_per_second) {
        state->rate = hints->aggregate_rate_limit_bytes_per_second;
        reason |= QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT;
    }
    int queued = hints->external_load_queued_bytes != 0 || hints->external_load_oldest_age_msec != 0;
    if (fresh_load_epoch) {
        state->last_external_load_epoch = hints->external_load_epoch;
        if (queued || hints->external_load_fraction_ppm > EXTERNAL_LOAD_CLEAR_PPM) {
            state->external_load_seen = 1;
            state->external_load_clear_epochs = 0;
        } else if (state->external_load_seen && ++state->external_load_clear_epochs >= EXTERNAL_LOAD_CLEAR_EPOCHS) {
            state->external_load_seen = 0;
            state->external_load_clear_epochs = 0;
        }
    } else if (hints->external_load_epoch == 0 && queued) {
        state->external_load_seen = 1;
        state->external_load_clear_epochs = 0;
    }
    if (external_load(state))
        reason |= QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD;
    update_output(state, 0, reason, output);
}

quicly_flexicast_cc_type_t quicly_flexicast_cc_type_adaptive = {
    .name = "adaptive",
    .state_size = sizeof(adaptive_state_t),
    .init = adaptive_init,
    .dispose = adaptive_dispose,
    .on_member_added = adaptive_on_member_added,
    .on_member_removed = adaptive_on_member_removed,
    .on_member_suspended = adaptive_on_member_suspended,
    .on_epoch_reset = adaptive_on_epoch_reset,
    .on_feedback = adaptive_on_feedback,
    .on_timeout = adaptive_on_timeout,
    .set_hints = adaptive_set_hints,
};
