/*
 * Copyright (c) 2026 Joseph Calderon
 * SPDX-License-Identifier: MIT
 */
#include "quicly/flexicast_cc.h"
#include "flexicast_cc_member_map.h"

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define LOSS_SCALE 1000000U
#define EXTERNAL_LOAD_CLEAR_PPM 100000U
#define EXTERNAL_LOAD_CLEAR_EPOCHS 3U
#define RTT_CONGESTION_EPOCHS 3U
#define RTT_CLEAR_EPOCHS 3U
#define FLOOR_RECOVERY_HOLD_EPOCHS 10U
#define FLOOR_RECOVERY_RAMP_EPOCHS 2U
#define STARTUP_GROWTH_EPOCHS 5U

typedef struct st_adaptive_member_t {
    uint64_t id;
    uint32_t baseline_loss_ppm;
    uint32_t flat_loss_epochs;
    uint32_t minimum_rtt;
    uint32_t smoothed_rtt;
    int64_t last_feedback;
    uint32_t elevated_rtt_epochs;
    uint32_t clear_rtt_epochs;
    uint32_t baseline_delivery_ratio_ppm;
    uint32_t recent_delivery_ratio_ppm;
    uint32_t degraded_delivery_epochs;
    uint64_t last_feedback_epoch;
    int rtt_congested;
} adaptive_member_t;

typedef struct st_adaptive_state_t {
    quicly_flexicast_cc_config_t config;
    quicly_flexicast_cc_hints_t hints;
    adaptive_member_t *members;
    size_t num_members;
    flexicast_cc_member_map_t member_map;
    uint64_t rate;
    uint64_t last_growth_epoch;
    uint64_t last_growth_freeze_epoch;
    uint32_t startup_growth_epochs;
    int startup_complete;
    int64_t last_rtt_reduction_at;
    uint64_t last_rtt_clear_epoch;
    uint32_t rtt_clear_epochs;
    uint64_t rtt_episode_member_id;
    int rtt_episode_active;
    int64_t next_recovery_probe;
    int64_t last_timeout_reduction;
    uint32_t unanswered_recovery_probes;
    uint32_t floor_recovery_epochs;
    uint64_t last_floor_recovery_epoch;
    uint64_t last_external_load_epoch;
    uint32_t external_load_clear_epochs;
    int external_load_seen;
} adaptive_state_t;

static uint64_t clamp_rate(const adaptive_state_t *state, uint64_t rate)
{
    if (rate < state->config.minimum_rate_bytes_per_second)
        rate = state->config.minimum_rate_bytes_per_second;
    if (state->config.maximum_rate_bytes_per_second != 0 && rate > state->config.maximum_rate_bytes_per_second)
        rate = state->config.maximum_rate_bytes_per_second;
    return rate;
}

static adaptive_member_t *find_member(adaptive_state_t *state, uint64_t id)
{
    size_t slot;
    return flexicast_cc_member_map_find(&state->member_map, id, &slot) == 0 ? state->members + slot : NULL;
}

static adaptive_member_t *add_member(adaptive_state_t *state, uint64_t id, int64_t now)
{
    adaptive_member_t *member = find_member(state, id);
    if (member != NULL)
        return member;
    if (state->num_members == state->config.maximum_members ||
        flexicast_cc_member_map_insert(&state->member_map, id, state->num_members) != 0)
        return NULL;
    member = state->members + state->num_members++;
    member->id = id;
    member->last_feedback = now;
    return member;
}

static uint32_t active_senders(const adaptive_state_t *state)
{
    return state->hints.active_senders != 0 ? state->hints.active_senders : 1;
}

static int64_t recovery_deadline(const adaptive_state_t *state, int64_t now)
{
    uint64_t interval = state->config.feedback_timeout_msec;
    uint64_t delay, remaining;
    if (now < 0)
        now = 0;
    if (interval > 2000)
        interval = 2000;
    uint64_t seed = (uint64_t)now ^ state->rate ^ ((uint64_t)active_senders(state) << 32);
    uint64_t jitter = interval != 0 ? (seed * UINT64_C(11400714819323198485) >> 56) * interval / 1280 : 0;
    delay = interval + jitter;
    remaining = (uint64_t)(INT64_MAX - now);
    return delay > remaining ? INT64_MAX : now + (int64_t)delay;
}

static void update_output(adaptive_state_t *state, int64_t now, uint64_t limiting_member, uint32_t reason,
                          quicly_flexicast_cc_output_t *output)
{
    state->rate = clamp_rate(state, state->rate);
    uint64_t minimum_burst = (uint64_t)state->config.maximum_datagram_size * 4;
    uint64_t maximum_burst = (uint64_t)state->config.maximum_datagram_size * 10;
    uint64_t burst = state->rate / 20;
    if (burst < minimum_burst)
        burst = minimum_burst;
    if (burst > maximum_burst)
        burst = maximum_burst;
    output->rate_bytes_per_second = state->rate;
    output->burst_bytes = burst;
    output->inflight_bytes = burst;
    output->limiting_member_id = limiting_member;
    output->next_timeout = state->next_recovery_probe != 0 ? state->next_recovery_probe : recovery_deadline(state, now);
    output->reason = reason;
}

static int adaptive_init(void *_state, const quicly_flexicast_cc_config_t *config, int64_t now,
                         quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    state->config = *config;
    if ((state->members = calloc(config->maximum_members, sizeof(*state->members))) == NULL ||
        flexicast_cc_member_map_init(&state->member_map, config->maximum_members) != 0) {
        free(state->members);
        state->members = NULL;
        return -1;
    }
    state->rate = config->startup_rate_bytes_per_second;
    state->next_recovery_probe = recovery_deadline(state, now);
    update_output(state, now, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
    return 0;
}

static void adaptive_dispose(void *_state)
{
    adaptive_state_t *state = _state;
    flexicast_cc_member_map_dispose(&state->member_map);
    free(state->members);
    state->members = NULL;
    state->num_members = 0;
}

static void adaptive_on_member_added(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    (void)add_member(state, member_id, now);
    update_output(state, now, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static void adaptive_on_member_removed(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    adaptive_member_t *member = find_member(state, member_id);
    if (member != NULL) {
        size_t slot = (size_t)(member - state->members), last = state->num_members - 1;
        flexicast_cc_member_map_remove(&state->member_map, member_id);
        if (slot != last) {
            state->members[slot] = state->members[last];
            flexicast_cc_member_map_update(&state->member_map, state->members[slot].id, slot);
        }
        memset(state->members + last, 0, sizeof(state->members[last]));
        --state->num_members;
    }
    if (state->rtt_episode_active && state->rtt_episode_member_id == member_id) {
        state->rtt_episode_active = 0;
        state->rtt_episode_member_id = 0;
        state->rtt_clear_epochs = 0;
    }
    update_output(state, now, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static void adaptive_on_epoch_reset(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    for (size_t i = 0; i != state->num_members; ++i) {
        state->members[i].last_feedback = now;
        state->members[i].last_feedback_epoch = 0;
    }
    state->unanswered_recovery_probes = 0;
    state->last_timeout_reduction = 0;
    state->rtt_episode_active = 0;
    state->rtt_episode_member_id = 0;
    state->rtt_clear_epochs = 0;
    state->next_recovery_probe = recovery_deadline(state, now);
    update_output(state, now, 0, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static int queue_delay_grew(const adaptive_member_t *member, const quicly_flexicast_feedback_t *feedback)
{
    uint32_t floor = feedback->minimum_rtt_msec != 0 ? feedback->minimum_rtt_msec : member->minimum_rtt;
    uint32_t margin = floor / 4;
    if (margin < 5)
        margin = 5;
    return floor != 0 && feedback->latest_rtt_msec > floor + margin;
}

static int rtt_reduction_is_due(const adaptive_state_t *state, int64_t now)
{
    uint64_t horizon = state->config.feedback_timeout_msec != 0 ? state->config.feedback_timeout_msec : 1000;
    if (horizon <= UINT64_MAX / 2)
        horizon *= 2;
    return state->last_rtt_reduction_at == 0 || now < state->last_rtt_reduction_at ||
           (uint64_t)(now - state->last_rtt_reduction_at) >= horizon;
}

static int update_delivery_ratio(adaptive_state_t *state, adaptive_member_t *member, const quicly_flexicast_feedback_t *feedback)
{
    if (state->rate == 0 || feedback->delivery_rate_bytes_per_second == 0)
        return 0;
    uint32_t sample = feedback->delivery_rate_bytes_per_second >= state->rate
                          ? LOSS_SCALE
                          : (uint32_t)((double)feedback->delivery_rate_bytes_per_second / (double)state->rate * LOSS_SCALE);
    if (member->baseline_delivery_ratio_ppm == 0) {
        /* The advertised rate is the initial reference. A receiver that joins
         * an already-impaired path must not make its first low sample the
         * permanent normal and thereby mask startup congestion. Stable loss
         * without delay is learned below after four fresh observations. */
        member->baseline_delivery_ratio_ppm = LOSS_SCALE;
        member->recent_delivery_ratio_ppm = sample;
        member->degraded_delivery_epochs = 0;
        return 1;
    }
    member->recent_delivery_ratio_ppm = (uint32_t)(((uint64_t)member->recent_delivery_ratio_ppm * 3 + sample) / 4);
    uint32_t margin = member->baseline_delivery_ratio_ppm / 10;
    if (margin < 50000)
        margin = 50000;
    if ((uint64_t)member->recent_delivery_ratio_ppm + margin < member->baseline_delivery_ratio_ppm)
        ++member->degraded_delivery_epochs;
    else
        member->degraded_delivery_epochs = 0;
    return 1;
}

static int delivery_ratio_degraded(const adaptive_member_t *member)
{
    return member->baseline_delivery_ratio_ppm != 0 && member->degraded_delivery_epochs != 0;
}

static int delivery_ratio_supports_growth(const adaptive_member_t *member)
{
    if (member->baseline_delivery_ratio_ppm == 0 || member->recent_delivery_ratio_ppm == 0)
        return 0;
    uint32_t margin = member->baseline_delivery_ratio_ppm / 10;
    if (margin < 50000)
        margin = 50000;
    return (uint64_t)member->recent_delivery_ratio_ppm + margin >= member->baseline_delivery_ratio_ppm;
}

static void learn_clean_delivery_ratio(adaptive_member_t *member)
{
    if (member->baseline_delivery_ratio_ppm == 0 || member->recent_delivery_ratio_ppm == 0)
        return;
    if (member->degraded_delivery_epochs >= 4) {
        /* A lasting delivery change without queue growth is more likely a new
         * radio-loss regime than congestion. Adopt it instead of repeatedly
         * penalizing a stable lossy path. */
        member->baseline_delivery_ratio_ppm = member->recent_delivery_ratio_ppm;
        member->degraded_delivery_epochs = 0;
    } else if (member->degraded_delivery_epochs == 0) {
        if (member->recent_delivery_ratio_ppm > member->baseline_delivery_ratio_ppm)
            member->baseline_delivery_ratio_ppm =
                (uint32_t)(((uint64_t)member->baseline_delivery_ratio_ppm * 7 + member->recent_delivery_ratio_ppm) / 8);
        else
            member->baseline_delivery_ratio_ppm =
                (uint32_t)(((uint64_t)member->baseline_delivery_ratio_ppm * 49 + member->recent_delivery_ratio_ppm) / 50);
    }
}

static uint64_t scale_rate_ppm(uint64_t rate, uint32_t factor)
{
    return rate / LOSS_SCALE * factor + rate % LOSS_SCALE * factor / LOSS_SCALE;
}

static uint32_t loss_ppm(const quicly_flexicast_feedback_t *feedback)
{
    uint64_t total = feedback->acked_packets + feedback->lost_packets;
    if (total == 0)
        return 0;
    return feedback->lost_packets > UINT64_MAX / LOSS_SCALE ? LOSS_SCALE : (uint32_t)(feedback->lost_packets * LOSS_SCALE / total);
}

static int below_median(const adaptive_state_t *state)
{
    return state->hints.median_sender_rate_bytes_per_second != 0 &&
           state->rate < state->hints.median_sender_rate_bytes_per_second - state->hints.median_sender_rate_bytes_per_second / 10;
}

static uint64_t external_load_recovery_ceiling(const adaptive_state_t *state)
{
    uint64_t ceiling =
        state->config.minimum_rate_bytes_per_second > UINT64_MAX / 8 ? UINT64_MAX : state->config.minimum_rate_bytes_per_second * 8;
    if (state->config.startup_rate_bytes_per_second != 0 && ceiling > state->config.startup_rate_bytes_per_second)
        ceiling = state->config.startup_rate_bytes_per_second;
    return ceiling < state->config.minimum_rate_bytes_per_second ? state->config.minimum_rate_bytes_per_second : ceiling;
}

static int has_recent_feedback(const adaptive_state_t *state, int64_t now)
{
    uint64_t horizon = state->config.feedback_timeout_msec != 0 ? state->config.feedback_timeout_msec : 1000;
    if (horizon <= UINT64_MAX / 2)
        horizon *= 2;
    for (size_t i = 0; i != state->num_members; ++i) {
        int64_t last = state->members[i].last_feedback;
        if (last > 0 && now >= last && (uint64_t)(now - last) <= horizon)
            return 1;
    }
    return 0;
}

static uint64_t sender_epoch(const adaptive_state_t *state, int64_t now)
{
    uint64_t interval = state->config.feedback_timeout_msec != 0 ? state->config.feedback_timeout_msec : 1000;
    return now < 0 ? 0 : (uint64_t)now / interval + 1;
}

static uint64_t growth_epoch(const adaptive_state_t *state, int64_t now)
{
    /* Missing-feedback recovery and positive-feedback growth are different
     * clocks. NORM's sender-local epoch follows its probe/feedback cadence,
     * while a substantially longer timeout detects a silent representative.
     * Keep the same separation without importing receiver sequence numbers. */
    uint64_t interval = state->config.feedback_timeout_msec != 0 ? state->config.feedback_timeout_msec : 1000;
    interval /= 4;
    if (interval < 25)
        interval = 25;
    return now < 0 ? 0 : (uint64_t)now / interval + 1;
}

static uint64_t floor_recovery_limit(const adaptive_state_t *state)
{
    uint64_t limit = state->config.minimum_rate_bytes_per_second;
    return limit > UINT64_MAX / 8 ? UINT64_MAX : limit * 8;
}

static int near_floor(const adaptive_state_t *state, uint64_t rate)
{
    uint64_t minimum = state->config.minimum_rate_bytes_per_second;
    return minimum != 0 && (minimum > UINT64_MAX / 3 || rate <= minimum * 3);
}

static void apply_floor_recovery_growth(adaptive_state_t *state)
{
    double divisor = sqrt((double)active_senders(state));
    uint64_t increase = divisor > 0 ? (uint64_t)((double)state->rate / divisor) : state->rate;
    uint64_t candidate = UINT64_MAX - state->rate < increase ? UINT64_MAX : state->rate + increase;
    uint64_t limit = floor_recovery_limit(state);
    if (candidate > limit)
        candidate = limit;
    if (candidate > state->rate)
        state->rate = candidate;
}

static void start_floor_recovery(adaptive_state_t *state, uint64_t epoch)
{
    state->floor_recovery_epochs = FLOOR_RECOVERY_RAMP_EPOCHS + FLOOR_RECOVERY_HOLD_EPOCHS;
    state->last_floor_recovery_epoch = epoch;
    apply_floor_recovery_growth(state);
}

static void advance_floor_recovery(adaptive_state_t *state, uint64_t epoch)
{
    if (state->floor_recovery_epochs == 0 || epoch <= state->last_floor_recovery_epoch)
        return;
    state->last_floor_recovery_epoch = epoch;
    if (state->floor_recovery_epochs > FLOOR_RECOVERY_HOLD_EPOCHS)
        apply_floor_recovery_growth(state);
    --state->floor_recovery_epochs;
}

static int grow_once(adaptive_state_t *state, int64_t now)
{
    uint64_t epoch = growth_epoch(state, now);
    int external_load = state->hints.external_load_queued_bytes != 0 || state->hints.external_load_oldest_age_msec != 0 ||
                        state->external_load_seen;
    uint64_t recovery_ceiling = external_load_recovery_ceiling(state);
    if (epoch <= state->last_growth_epoch)
        return 0;
    if (external_load && state->rate >= recovery_ceiling) {
        if (epoch <= state->last_growth_freeze_epoch)
            return 0;
        state->last_growth_freeze_epoch = epoch;
        return -1;
    }
    state->last_growth_epoch = epoch;
    /* Grow conservatively because one clean feedback epoch can precede the
     * receiver repair signal that reveals an overdriven multicast link. Flat
     * radio loss is still learned rather than treated as congestion, but it
     * must not combine with exponential startup growth to create avoidable
     * repair airtime. */
    double divisor = 8 * sqrt((double)active_senders(state));
    uint64_t increase = divisor > 0 ? (uint64_t)((double)state->rate / divisor) : state->rate;
    if (increase < state->config.maximum_datagram_size)
        increase = state->config.maximum_datagram_size;
    if (state->hints.median_sender_rate_bytes_per_second != 0 && below_median(state) &&
        increase > state->hints.median_sender_rate_bytes_per_second - state->rate)
        increase = state->hints.median_sender_rate_bytes_per_second - state->rate;
    state->rate = UINT64_MAX - state->rate < increase ? UINT64_MAX : state->rate + increase;
    /* Repair work is charged to this pacer and is not independent evidence of
     * congestion. Clean feedback may lift a timeout-reduced flow out of an
     * unusable floor tail, but only to a bounded recovery service rate. */
    if (external_load && state->rate > recovery_ceiling)
        state->rate = recovery_ceiling;
    return 1;
}

static void adaptive_on_feedback(void *_state, const quicly_flexicast_feedback_t *feedback, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    adaptive_member_t *member = add_member(state, feedback->member_id, feedback->now);
    uint32_t observed_loss, reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    int congested, delay_grew, has_delivery_sample;
    if (member == NULL)
        return;
    if (feedback->epoch != 0 && member->last_feedback_epoch != 0 && feedback->epoch <= member->last_feedback_epoch) {
        update_output(state, feedback->now, feedback->member_id, QUICLY_FLEXICAST_CC_REASON_NONE, output);
        return;
    }
    if (feedback->epoch != 0)
        member->last_feedback_epoch = feedback->epoch;
    if (feedback->minimum_rtt_msec != 0)
        member->minimum_rtt = feedback->minimum_rtt_msec;
    if (feedback->smoothed_rtt_msec != 0)
        member->smoothed_rtt = feedback->smoothed_rtt_msec;
    member->last_feedback = feedback->now;
    state->unanswered_recovery_probes = 0;
    state->next_recovery_probe = recovery_deadline(state, feedback->now);
    observed_loss = loss_ppm(feedback);
    has_delivery_sample = update_delivery_ratio(state, member, feedback);
    delay_grew = queue_delay_grew(member, feedback);
    uint64_t feedback_growth_epoch = growth_epoch(state, feedback->now);
    if (state->rtt_episode_active) {
        if (delay_grew || state->external_load_seen || feedback->ecn_ce_count != 0) {
            state->rtt_clear_epochs = 0;
            state->last_rtt_clear_epoch = feedback_growth_epoch;
        } else if (feedback->member_id == state->rtt_episode_member_id && feedback->acked_packets != 0 &&
                   feedback_growth_epoch > state->last_rtt_clear_epoch) {
            state->last_rtt_clear_epoch = feedback_growth_epoch;
            if (++state->rtt_clear_epochs >= RTT_CLEAR_EPOCHS) {
                state->rtt_episode_active = 0;
                state->rtt_episode_member_id = 0;
                state->rtt_clear_epochs = 0;
                for (size_t i = 0; i != state->num_members; ++i) {
                    state->members[i].elevated_rtt_epochs = 0;
                    state->members[i].clear_rtt_epochs = 0;
                    state->members[i].rtt_congested = 0;
                }
            }
        }
    }
    /* Completion of repair work can acknowledge an old original packet, so
     * its RTT includes repair scheduling age and is not a fresh path-queue
     * sample. Explicit ECN remains authoritative. While generic external work
     * is outstanding, hold delay-based decisions and preserve enough service
     * rate for that work to drain; otherwise repair-aged ACKs can drive a
     * circular reduction to the floor. */
    congested = feedback->ecn_ce_count != 0 ||
                (!state->external_load_seen && delay_grew && has_delivery_sample && delivery_ratio_degraded(member));

    if (state->floor_recovery_epochs != 0) {
        if (feedback->ecn_ce_count != 0) {
            /* An explicit congestion mark vetoes the liveness sampling epoch;
             * ordinary loss or delay is deliberately held until the bounded
             * sample has had time to produce useful feedback. */
            state->floor_recovery_epochs = 0;
            state->last_floor_recovery_epoch = 0;
        } else {
            advance_floor_recovery(state, sender_epoch(state, feedback->now));
            update_output(state, feedback->now, feedback->member_id, QUICLY_FLEXICAST_CC_REASON_ACK, output);
            return;
        }
    }

    if (congested) {
        state->startup_complete = 1;
        member->clear_rtt_epochs = 0;
        if (feedback->ecn_ce_count != 0) {
            member->elevated_rtt_epochs = 0;
            if (!below_median(state)) {
                state->rate = state->rate * 85 / 100;
            }
        } else if (++member->elevated_rtt_epochs >= RTT_CONGESTION_EPOCHS) {
            /* Receiver reports for one multicast queue episode are highly
             * correlated. Apply one aggregate reduction, then require the
             * limiting receiver to report sustained clean epochs before
             * rearming. This preserves an independently paced sender clock
             * without multiplying one shared queue event by the group size. */
            if (has_delivery_sample && !state->rtt_episode_active && !below_median(state) &&
                rtt_reduction_is_due(state, feedback->now)) {
                uint32_t factor = 900000;
                if (delivery_ratio_degraded(member)) {
                    factor = member->baseline_delivery_ratio_ppm != 0 ? (uint32_t)((uint64_t)member->recent_delivery_ratio_ppm *
                                                                                   LOSS_SCALE / member->baseline_delivery_ratio_ppm)
                                                                      : factor;
                    if (factor < 500000)
                        factor = 500000;
                    if (factor > 900000)
                        factor = 900000;
                }
                state->rate = scale_rate_ppm(state->rate, factor);
                state->last_rtt_reduction_at = feedback->now;
                state->rtt_episode_active = 1;
                state->rtt_episode_member_id = feedback->member_id;
                state->rtt_clear_epochs = 0;
                state->last_rtt_clear_epoch = feedback_growth_epoch;
            }
            member->elevated_rtt_epochs = 0;
            member->rtt_congested = 1;
        }
        reason |= feedback->ecn_ce_count != 0 ? QUICLY_FLEXICAST_CC_REASON_ECN : QUICLY_FLEXICAST_CC_REASON_RTT;
        member->flat_loss_epochs = 0;
    } else if (!state->external_load_seen && delay_grew) {
        /* A standing TDMA or local pacing queue can raise RTT while delivered
         * throughput remains stable. Hold growth, but require the learned
         * delivery ratio to degrade before treating delay as congestion. */
        member->clear_rtt_epochs = 0;
        ++member->elevated_rtt_epochs;
        member->flat_loss_epochs = 0;
        reason |= QUICLY_FLEXICAST_CC_REASON_RTT;
    } else if (observed_loss > member->baseline_loss_ppm + 20000) {
        member->elevated_rtt_epochs = 0;
        member->clear_rtt_epochs = 0;
        member->rtt_congested = 0;
        /* Ambiguous flat loss is held first, then incorporated gradually as a
         * radio-loss baseline rather than immediately reducing the flow. */
        if (++member->flat_loss_epochs >= 3) {
            member->baseline_loss_ppm =
                member->baseline_loss_ppm == 0 ? observed_loss : (member->baseline_loss_ppm * 7 + observed_loss) / 8;
            member->flat_loss_epochs = 0;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_LOSS;
    } else if (feedback->acked_packets != 0) {
        int startup_probe = !state->startup_complete && state->startup_growth_epochs < STARTUP_GROWTH_EPOCHS;
        member->elevated_rtt_epochs = 0;
        member->flat_loss_epochs = 0;
        reason |= QUICLY_FLEXICAST_CC_REASON_ACK;
        if (member->rtt_congested && ++member->clear_rtt_epochs < RTT_CLEAR_EPOCHS) {
            /* A single low sample does not rearm delay reduction or immediately
             * grow into the same queue. Sustained clean feedback ends the
             * congestion episode and can then raise a flow off its floor. */
        } else if (state->rtt_episode_active) {
            /* Only sustained clean feedback from the limiting receiver can
             * end the aggregate queue episode. An unrelated clean member
             * proves its own liveness, but must not grow the shared sender
             * back into the episode before that rearm completes. */
        } else if ((!has_delivery_sample || !delivery_ratio_supports_growth(member)) && !startup_probe) {
            /* Outside bounded startup, an ACK proves liveness but not that the
             * advertised rate was delivered. Hold while a stable radio-loss
             * baseline is still being learned. */
        } else {
            int growth;
            member->rtt_congested = 0;
            member->clear_rtt_epochs = 0;
            growth = grow_once(state, feedback->now);
            if (growth > 0 && startup_probe && ++state->startup_growth_epochs >= STARTUP_GROWTH_EPOCHS)
                state->startup_complete = 1;
            if (growth < 0)
                reason |= QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD | QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN;
        }
    }
    if (has_delivery_sample && !state->external_load_seen && feedback->ecn_ce_count == 0 && !delay_grew)
        learn_clean_delivery_ratio(member);
    update_output(state, feedback->now, feedback->member_id, reason, output);
}

static void adaptive_on_timeout(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (state->next_recovery_probe != 0 && now >= state->next_recovery_probe) {
        ++state->unanswered_recovery_probes;
        if (state->floor_recovery_epochs != 0) {
            advance_floor_recovery(state, sender_epoch(state, now));
        } else if (state->unanswered_recovery_probes >= 3 &&
                   (state->last_timeout_reduction == 0 ||
                    now - state->last_timeout_reduction >= state->config.feedback_timeout_msec)) {
            uint64_t previous_rate = state->rate;
            state->startup_complete = 1;
            state->rate /= 2;
            state->last_timeout_reduction = now;
            state->unanswered_recovery_probes = 0;
            if (near_floor(state, previous_rate)) {
                state->rate = previous_rate;
                start_floor_recovery(state, sender_epoch(state, now));
            }
        }
        state->next_recovery_probe = recovery_deadline(state, now);
        reason = QUICLY_FLEXICAST_CC_REASON_TIMEOUT;
    }
    update_output(state, now, 0, reason, output);
}

static void adaptive_set_hints(void *_state, const quicly_flexicast_cc_hints_t *hints, int64_t now,
                               quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_HINT;
    state->hints = *hints;
    if (hints->aggregate_rate_limit_bytes_per_second != 0 && state->rate > hints->aggregate_rate_limit_bytes_per_second) {
        state->rate = hints->aggregate_rate_limit_bytes_per_second;
        reason |= QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT;
    }
    if (hints->external_load_epoch != 0 && hints->external_load_epoch != state->last_external_load_epoch) {
        state->last_external_load_epoch = hints->external_load_epoch;
        if (hints->external_load_queued_bytes != 0 || hints->external_load_oldest_age_msec != 0 ||
            hints->external_load_fraction_ppm > EXTERNAL_LOAD_CLEAR_PPM) {
            /* External work is already charged to this flow's physical pacer.
             * Treat it as a reason to stop increasing the path rate, not as
             * independent evidence that the path is congested. Reducing the
             * total rate here also reduces repair service and can create a
             * self-sustaining trip to the minimum rate. */
            state->external_load_seen = 1;
            state->startup_complete = 1;
            state->external_load_clear_epochs = 0;
            reason |= QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD;
        } else if (state->external_load_seen && ++state->external_load_clear_epochs >= EXTERNAL_LOAD_CLEAR_EPOCHS) {
            state->external_load_seen = 0;
            state->external_load_clear_epochs = 0;
        }
    } else if (hints->external_load_queued_bytes != 0 || hints->external_load_oldest_age_msec != 0) {
        state->external_load_seen = 1;
        state->external_load_clear_epochs = 0;
        reason |= QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD;
    }
    if (state->floor_recovery_epochs == 0 &&
        (hints->external_load_queued_bytes != 0 || hints->external_load_oldest_age_msec != 0) &&
        state->rate < external_load_recovery_ceiling(state) && has_recent_feedback(state, now)) {
        uint64_t increase = state->rate;
        uint64_t ceiling = external_load_recovery_ceiling(state);
        state->rate = UINT64_MAX - state->rate < increase ? UINT64_MAX : state->rate + increase;
        if (state->rate > ceiling)
            state->rate = ceiling;
        reason |= QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD;
    }
    update_output(state, now, 0, reason, output);
}

quicly_flexicast_cc_type_t quicly_flexicast_cc_type_adaptive = {
    .name = "adaptive",
    .state_size = sizeof(adaptive_state_t),
    .init = adaptive_init,
    .dispose = adaptive_dispose,
    .on_member_added = adaptive_on_member_added,
    .on_member_removed = adaptive_on_member_removed,
    .on_epoch_reset = adaptive_on_epoch_reset,
    .on_feedback = adaptive_on_feedback,
    .on_timeout = adaptive_on_timeout,
    .set_hints = adaptive_set_hints,
};
