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
#define DRAIN_OBSERVING 1U
#define DRAIN_ACTIVE 2U

typedef struct st_adaptive_drain_t {
    uint32_t phase;
    uint64_t member_id;
    uint64_t ceiling;
    uint64_t target;
    int64_t started_at;
    int64_t deadline;
    int64_t ended_at;
    int needs_growth;
} adaptive_drain_t;

typedef struct st_adaptive_member_t {
    uint64_t id;
    uint64_t last_feedback_epoch;
    uint32_t minimum_rtt;
    uint32_t previous_rtt;
    uint32_t rising_delay_epochs;
    uint64_t last_rtt_sample_epoch;
    int64_t previous_rtt_at;
    uint32_t baseline_loss_ppm;
    uint32_t flat_loss_epochs;
    uint32_t baseline_delivery_ratio_ppm;
    uint64_t recent_delivery_rate;
    uint64_t last_delivery_sample_epoch;
    uint64_t delivery_reference_rate;
    uint32_t delivery_reference_fanout;
    uint32_t recent_delivery_ratio_ppm;
    uint32_t degraded_delivery_epochs;
    int active;
    uint64_t delivery_ceiling;
    uint32_t delivery_ceiling_eligible;
    uint32_t delivery_sample_post_cut;
    uint32_t delivery_sample_ratio_ppm;
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
    int64_t last_growth_at;
    int64_t last_reduction_at;
    int64_t growth_blocked_until;
    int64_t next_timeout;
    uint32_t startup_probes;
    uint32_t unanswered_probes;
    uint64_t last_external_load_epoch;
    uint32_t external_load_clear_epochs;
    int external_load_seen;
    adaptive_drain_t drain;
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

/* Decisions are separated by elapsed time, not by wall-clock bucket edges. */
static int control_due(const adaptive_state_t *state, int64_t now, int64_t previous, uint64_t previous_epoch)
{
    return previous_epoch == 0 || now >= deadline(previous, control_interval(state));
}

static uint32_t end_drain(adaptive_state_t *state, int64_t now, uint32_t reason)
{
    state->drain.phase = 0;
    state->drain.ended_at = now;
    state->drain.needs_growth = 1;
    return reason;
}

static uint32_t expire_drain(adaptive_state_t *state, int64_t now)
{
    return state->drain.phase != 0 && now >= state->drain.deadline ? end_drain(state, now, QUICLY_FLEXICAST_CC_REASON_DRAIN_EXPIRE)
                                                                   : 0;
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
    if (state->drain.phase != 0 && output->next_timeout > state->drain.deadline)
        output->next_timeout = state->drain.deadline;
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
    uint32_t reason = expire_drain(state, now);
    (void)add_member(state, member_id);
    if (state->next_timeout <= now || state->next_timeout == INT64_MAX)
        state->next_timeout = deadline(now, state->config.feedback_timeout_msec);
    update_output(state, 0, reason, output);
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
    uint32_t reason = expire_drain(state, now);
    if (state->drain.phase != 0 && state->drain.member_id == member_id)
        reason |= end_drain(state, now, QUICLY_FLEXICAST_CC_REASON_DRAIN_CLEAR);
    if (member != NULL)
        suspend_member(state, member);
    update_output(state, 0, reason, output);
}

static void adaptive_on_member_removed(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    adaptive_member_t *member = find_member(state, member_id);
    uint32_t reason = expire_drain(state, now);
    if (state->drain.phase != 0 && state->drain.member_id == member_id)
        reason |= end_drain(state, now, QUICLY_FLEXICAST_CC_REASON_DRAIN_CLEAR);
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
    update_output(state, 0, reason, output);
}

static void adaptive_on_epoch_reset(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    uint32_t reason = state->drain.phase != 0 ? QUICLY_FLEXICAST_CC_REASON_DRAIN_CLEAR : 0;
    memset(&state->drain, 0, sizeof(state->drain));
    for (size_t i = 0; i != state->num_members; ++i) {
        state->members[i].last_feedback_epoch = 0;
        state->members[i].flat_loss_epochs = 0;
        state->members[i].degraded_delivery_epochs = 0;
        state->members[i].last_delivery_sample_epoch = 0;
        state->members[i].previous_rtt = 0;
        state->members[i].last_rtt_sample_epoch = 0;
        state->members[i].previous_rtt_at = 0;
        state->members[i].recent_delivery_rate = 0;
        state->members[i].delivery_reference_rate = 0;
        state->members[i].delivery_reference_fanout = 0;
        state->members[i].rising_delay_epochs = 0;
        state->members[i].delivery_ceiling = 0;
        state->members[i].delivery_ceiling_eligible = 0;
        state->members[i].delivery_sample_post_cut = 0;
        state->members[i].delivery_sample_ratio_ppm = 0;
    }
    state->unanswered_probes = 0;
    state->last_growth_epoch = 0;
    state->last_reduction_epoch = 0;
    state->last_growth_at = state->last_reduction_at = 0;
    state->growth_blocked_until = now;
    state->next_timeout = deadline(now, state->config.feedback_timeout_msec);
    update_output(state, 0, reason, output);
}

/* The ceiling is in physical bytes/second. Cap before every potentially
 * overflowing product: delivery * fanout / clean_fraction cannot exceed the
 * historical pacing rate, even for extreme direct-controller inputs. */
static uint64_t delivery_rate_ceiling(uint64_t delivery, uint32_t fanout, uint32_t clean_fraction, uint64_t reference)
{
    if (delivery > reference / fanout)
        return reference;
    uint64_t physical = delivery * fanout;
    uint64_t quotient = physical / clean_fraction;
    if (quotient > reference / LOSS_SCALE)
        return reference;
    uint64_t whole = quotient * LOSS_SCALE;
    uint64_t remainder = physical % clean_fraction * LOSS_SCALE / clean_fraction;
    return remainder > reference - whole ? reference : whole + remainder;
}

static int update_delivery_ratio(adaptive_state_t *state, adaptive_member_t *member, const quicly_flexicast_feedback_t *feedback,
                                 int *fresh)
{
    int explicit_context = (feedback->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_PRESENT) != 0;
    uint64_t sample_epoch = feedback->delivery_rate_sample_epoch;
    if (!explicit_context && sample_epoch == 0)
        sample_epoch = feedback->now > 0 ? (uint64_t)feedback->now : feedback->epoch;
    if (sample_epoch == 0 || sample_epoch <= member->last_delivery_sample_epoch)
        return 0;
    member->last_delivery_sample_epoch = sample_epoch;

    uint32_t divisor = state->hints.delivery_rate_divisor != 0 ? state->hints.delivery_rate_divisor : 1;
    uint64_t reference_rate = state->rate;
    if (explicit_context) {
        uint32_t invalid =
            QUICLY_FLEXICAST_SAMPLE_APP_LIMITED | QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED | QUICLY_FLEXICAST_SAMPLE_MIXED;
        if (!(feedback->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_VALID) ||
            (feedback->delivery_sample_flags & invalid) != 0 || feedback->delivery_sample_fanout == 0 ||
            feedback->delivery_sample_bytes == 0 || feedback->delivery_sample_sent_at_start < 0 ||
            feedback->delivery_sample_sent_at_end < feedback->delivery_sample_sent_at_start ||
            feedback->delivery_sample_acked_at_end <= feedback->delivery_sample_acked_at_start ||
            feedback->delivery_sample_sent_at_end > feedback->delivery_sample_acked_at_end ||
            feedback->delivery_sample_acked_at_end > feedback->now ||
            feedback->now > deadline(feedback->delivery_sample_acked_at_end, state->config.feedback_timeout_msec)) {
            /* Unknown or limited sending cannot distinguish available capacity
             * from offered load. */
            member->recent_delivery_rate = 0;
            member->delivery_reference_rate = 0;
            member->degraded_delivery_epochs = 0;
            return 0;
        }
        divisor = feedback->delivery_sample_fanout;
        reference_rate = feedback->delivery_sample_pacing_rate_bytes_per_second;
        if (reference_rate != member->delivery_reference_rate || divisor != member->delivery_reference_fanout) {
            member->recent_delivery_rate = 0;
            member->degraded_delivery_epochs = 0;
        }
        member->delivery_reference_rate = reference_rate;
        member->delivery_reference_fanout = divisor;
    }
    uint64_t expected = reference_rate / divisor;
    if (expected == 0 || feedback->delivery_rate_bytes_per_second == 0)
        return 0;
    uint64_t sample_rate = feedback->delivery_rate_bytes_per_second;
    if (explicit_context) {
        uint32_t clean_fraction = member->baseline_delivery_ratio_ppm != 0 ? member->baseline_delivery_ratio_ppm : LOSS_SCALE;
        member->delivery_ceiling = delivery_rate_ceiling(sample_rate, divisor, clean_fraction, reference_rate);
        member->delivery_ceiling_eligible = 1;
        member->delivery_sample_ratio_ppm =
            sample_rate >= expected ? LOSS_SCALE : (uint32_t)((double)sample_rate / (double)expected * LOSS_SCALE);
        member->delivery_sample_post_cut =
            state->last_reduction_epoch == 0 || feedback->delivery_sample_sent_at_start >= state->last_reduction_at;
        if (!member->delivery_sample_post_cut) {
            /* Old sending can still bound capacity, but cannot justify growth or
             * teach a clean baseline for the new rate. Keep that history separate. */
            member->recent_delivery_rate = 0;
            member->degraded_delivery_epochs = 0;
            return 0;
        }
    }
    *fresh = 1;
    if (member->recent_delivery_rate == 0)
        member->recent_delivery_rate = sample_rate;
    else
        member->recent_delivery_rate =
            member->recent_delivery_rate / 4 * 3 + sample_rate / 4 + (member->recent_delivery_rate % 4 * 3 + sample_rate % 4) / 4;
    /* Native samples use the rate and fanout at submission. Legacy direct
     * callers retain their current-rate convention. Never blend native rates
     * from different sending contexts or count repeated publications twice. */
    uint32_t sample = member->recent_delivery_rate >= expected
                          ? LOSS_SCALE
                          : (uint32_t)((double)member->recent_delivery_rate / (double)expected * LOSS_SCALE);
    if (member->baseline_delivery_ratio_ppm == 0)
        member->baseline_delivery_ratio_ppm = LOSS_SCALE;
    member->recent_delivery_ratio_ppm = sample;
    uint32_t margin = member->baseline_delivery_ratio_ppm / 10;
    if (margin < 50000)
        margin = 50000;
    if ((uint64_t)sample + margin < member->baseline_delivery_ratio_ppm) {
        if (member->degraded_delivery_epochs < 4)
            ++member->degraded_delivery_epochs;
    } else {
        member->degraded_delivery_epochs = 0;
    }
    return 1;
}

static int update_rtt(adaptive_state_t *state, adaptive_member_t *member, const quicly_flexicast_feedback_t *feedback)
{
    int explicit_context = (feedback->rtt_sample_flags & QUICLY_FLEXICAST_RTT_PRESENT) != 0;
    uint64_t sample_epoch = feedback->rtt_sample_epoch;
    if (!explicit_context)
        sample_epoch = feedback->now > 0 ? (uint64_t)feedback->now : feedback->epoch;
    if (sample_epoch == 0 || sample_epoch <= member->last_rtt_sample_epoch)
        return 0;
    member->last_rtt_sample_epoch = sample_epoch;
    if (feedback->latest_rtt_msec == 0 ||
        (explicit_context && (!(feedback->rtt_sample_flags & QUICLY_FLEXICAST_RTT_VALID) ||
                              (feedback->rtt_sample_flags & QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT) ||
                              feedback->rtt_sample_at <= 0 || feedback->rtt_sample_at > feedback->now ||
                              feedback->now > deadline(feedback->rtt_sample_at, state->config.feedback_timeout_msec))))
        return 0;
    if (feedback->minimum_rtt_msec != 0)
        member->minimum_rtt = feedback->minimum_rtt_msec;
    int64_t sampled_at = explicit_context ? feedback->rtt_sample_at : feedback->now;
    if (member->previous_rtt == 0 || sampled_at >= deadline(member->previous_rtt_at, control_interval(state))) {
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
        member->previous_rtt_at = sampled_at;
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

/* Observe for one sender interval before using a single current capacity
 * sample. The short impulse is an experiment, not a persistent rate cap:
 * neither later samples nor correlated receivers can move its target/deadline. */
static uint32_t update_drain(adaptive_state_t *state, const adaptive_member_t *member, const quicly_flexicast_feedback_t *feedback,
                             int fresh_native_rtt, int delay_grew, int delivery_congested)
{
    adaptive_drain_t *drain = &state->drain;
    if (drain->phase != 0 && drain->member_id == feedback->member_id && fresh_native_rtt &&
        feedback->rtt_sample_at >= drain->started_at && !delay_grew && feedback->ecn_ce_count == 0 &&
        (drain->phase == DRAIN_OBSERVING || feedback->now >= state->growth_blocked_until))
        return end_drain(state, feedback->now, QUICLY_FLEXICAST_CC_REASON_DRAIN_CLEAR);

    int eligible = member->delivery_ceiling_eligible && fresh_native_rtt && delay_grew && feedback->ecn_ce_count == 0 &&
                   !external_load(state) &&
                   (drain->ended_at == 0 || (feedback->delivery_sample_sent_at_start >= state->last_growth_at &&
                                             feedback->rtt_sample_at >= state->last_growth_at));
    if (!eligible)
        return 0;
    if (drain->phase == 0 && !drain->needs_growth && delivery_congested) {
        drain->phase = DRAIN_OBSERVING;
        drain->member_id = feedback->member_id;
        drain->ceiling = drain->target = 0;
        drain->started_at = feedback->now;
        drain->deadline = deadline(feedback->now, control_interval(state) * 2);
    } else if (drain->phase == DRAIN_OBSERVING && feedback->now >= deadline(drain->started_at, control_interval(state)) &&
               control_due(state, feedback->now, state->last_reduction_at, state->last_reduction_epoch)) {
        uint64_t target = clamp_rate(&state->config, scale_rate(member->delivery_ceiling, 800000, LOSS_SCALE));
        if (target < state->rate) {
            drain->phase = DRAIN_ACTIVE;
            drain->member_id = feedback->member_id;
            drain->ceiling = member->delivery_ceiling;
            drain->target = target;
            drain->started_at = feedback->now;
            drain->deadline = deadline(feedback->now, control_interval(state) * 4);
            return QUICLY_FLEXICAST_CC_REASON_DRAIN_ENTER;
        }
    }
    return 0;
}

static void grow_once(adaptive_state_t *state, int64_t now, uint32_t growth_divisor)
{
    uint32_t senders = state->hints.active_senders != 0 ? state->hints.active_senders : 1;
    uint64_t increase = (uint64_t)((double)state->rate / (growth_divisor * sqrt((double)senders)));
    if (increase < state->config.maximum_datagram_size)
        increase = state->config.maximum_datagram_size;
    uint64_t median = state->hints.median_sender_rate_bytes_per_second;
    if (median > state->rate && increase > median - state->rate)
        increase = median - state->rate;
    state->rate = increase_rate(state->rate, increase);
    state->last_growth_epoch = control_epoch(state, now);
    state->last_growth_at = now;
}

static void adaptive_on_feedback(void *_state, const quicly_flexicast_feedback_t *feedback, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    adaptive_member_t *member = add_member(state, feedback->member_id);
    uint32_t reason = expire_drain(state, feedback->now);
    if (member == NULL) {
        if (reason != 0)
            update_output(state, feedback->member_id, reason, output);
        return;
    }
    member->delivery_ceiling = 0;
    member->delivery_ceiling_eligible = 0;
    member->delivery_sample_post_cut = 0;
    member->delivery_sample_ratio_ppm = 0;
    if (feedback->epoch != 0 && member->last_feedback_epoch != 0 && feedback->epoch <= member->last_feedback_epoch) {
        update_output(state, feedback->member_id, reason, output);
        return;
    }
    if (feedback->epoch != 0)
        member->last_feedback_epoch = feedback->epoch;
    state->unanswered_probes = 0;
    state->next_timeout = deadline(feedback->now, state->config.feedback_timeout_msec);
    uint64_t epoch = control_epoch(state, feedback->now);
    int fresh_delivery = 0;
    int has_delivery = update_delivery_ratio(state, member, feedback, &fresh_delivery);
    int fresh_rtt = update_rtt(state, member, feedback);
    int delay_grew = fresh_rtt && queue_delay_grew(member->minimum_rtt, feedback->latest_rtt_msec);
    uint32_t observed_loss = loss_ppm(feedback);
    uint32_t clean_fraction = member->baseline_delivery_ratio_ppm != 0 ? member->baseline_delivery_ratio_ppm : LOSS_SCALE;
    uint32_t margin = clean_fraction / 10;
    if (margin < 50000)
        margin = 50000;
    int native_sample = (feedback->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_PRESENT) != 0;
    int delivery_congested = native_sample ? member->delivery_ceiling_eligible && member->delivery_ceiling < state->rate &&
                                                 (uint64_t)member->delivery_sample_ratio_ppm + margin < clean_fraction
                                           : has_delivery && member->degraded_delivery_epochs != 0;
    int fresh_native_rtt = fresh_rtt && (feedback->rtt_sample_flags & QUICLY_FLEXICAST_RTT_PRESENT) != 0;
    reason |= update_drain(state, member, feedback, fresh_native_rtt, delay_grew, delivery_congested);
    /* New external-load hints cannot renew an active impulse or veto fresh
     * congestion evidence. Explicitly limited delivery remains ineligible. */
    int drain_step = state->drain.phase == DRAIN_ACTIVE && state->rate > state->drain.target && member->delivery_ceiling_eligible &&
                     fresh_native_rtt && delay_grew;
    int congested =
        feedback->ecn_ce_count != 0 || (delay_grew && (delivery_congested || drain_step || member->rising_delay_epochs >= 2 ||
                                                       observed_loss > member->baseline_loss_ppm + 20000));

    if (congested || delay_grew) {
        /* Any member can veto growth. One sender clock bounds correlated
         * receiver reports, but persistent congestion can reduce again on the
         * next clock tick without first requiring an impossible clean queue. */
        state->growth_blocked_until = deadline(feedback->now, control_interval(state) * 2);
        state->startup_probes = STARTUP_PROBES;
        member->flat_loss_epochs = 0;
        reason |= feedback->ecn_ce_count != 0 ? QUICLY_FLEXICAST_CC_REASON_ECN : QUICLY_FLEXICAST_CC_REASON_RTT;
        if (congested && control_due(state, feedback->now, state->last_reduction_at, state->last_reduction_epoch)) {
            if (feedback->ecn_ce_count != 0) {
                state->rate = scale_rate(state->rate, 850000, LOSS_SCALE);
            } else if (delivery_congested || drain_step) {
                /* Native history sets an absolute ceiling. Legacy callers
                 * without submission context retain their EWMA ratio policy. */
                uint64_t next = state->rate;
                if (delivery_congested)
                    next = native_sample ? member->delivery_ceiling
                                         : scale_rate(state->rate,
                                                      (uint32_t)((uint64_t)member->recent_delivery_ratio_ppm * LOSS_SCALE /
                                                                 member->baseline_delivery_ratio_ppm),
                                                      LOSS_SCALE);
                if (drain_step && state->drain.target < next) {
                    next = state->drain.target;
                    reason |= QUICLY_FLEXICAST_CC_REASON_DRAIN_CUT;
                }
                uint64_t minimum = scale_rate(state->rate, 500000, LOSS_SCALE);
                uint64_t maximum = scale_rate(state->rate, 900000, LOSS_SCALE);
                state->rate = next < minimum ? minimum : next > maximum ? maximum : next;
            } else {
                state->rate = scale_rate(state->rate, 900000, LOSS_SCALE);
            }
            state->last_reduction_epoch = epoch;
            state->last_reduction_at = feedback->now;
        }
    } else if (observed_loss > member->baseline_loss_ppm + 20000) {
        if (++member->flat_loss_epochs >= 3) {
            member->baseline_loss_ppm =
                member->baseline_loss_ppm == 0 ? observed_loss : (member->baseline_loss_ppm * 7 + observed_loss) / 8;
            member->flat_loss_epochs = 0;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_LOSS;
    } else if (feedback->acked_packets != 0) {
        member->flat_loss_epochs = 0;
        reason |= QUICLY_FLEXICAST_CC_REASON_ACK;
        int delivery_supports_growth = has_delivery && member->degraded_delivery_epochs == 0;
        int startup_probe = !has_delivery && state->startup_probes < STARTUP_PROBES &&
                            (!native_sample || (feedback->delivery_rate_sample_epoch == 0 && fresh_rtt));
        if (state->drain.phase == DRAIN_ACTIVE) {
            reason |= QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN;
        } else if (control_due(state, feedback->now, state->last_growth_at, state->last_growth_epoch) &&
                   control_due(state, feedback->now, state->last_reduction_at, state->last_reduction_epoch) &&
                   feedback->now >= state->growth_blocked_until && (delivery_supports_growth || startup_probe)) {
            if (external_load(state)) {
                reason |= QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD | QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN;
            } else {
                uint64_t previous = state->rate;
                grow_once(state, feedback->now, native_sample && delivery_supports_growth ? 16 : 8);
                uint64_t effective = clamp_rate(&state->config, state->rate);
                if (state->hints.aggregate_rate_limit_bytes_per_second != 0 &&
                    effective > state->hints.aggregate_rate_limit_bytes_per_second)
                    effective = state->hints.aggregate_rate_limit_bytes_per_second;
                if (effective > previous) {
                    if (state->drain.phase == DRAIN_OBSERVING)
                        reason |= end_drain(state, feedback->now, QUICLY_FLEXICAST_CC_REASON_DRAIN_CLEAR);
                    state->drain.needs_growth = 0;
                }
                if (startup_probe)
                    ++state->startup_probes;
            }
        }
    }
    int native_context = (feedback->rtt_sample_flags & QUICLY_FLEXICAST_RTT_PRESENT) != 0 ||
                         (feedback->delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_PRESENT) != 0;
    int clean_delivery = !external_load(state) && !congested && !delay_grew &&
                         (!native_context || (fresh_rtt && feedback->now >= state->growth_blocked_until));
    if (fresh_delivery && clean_delivery)
        learn_clean_delivery_ratio(member);
    else if (fresh_delivery && native_context)
        member->degraded_delivery_epochs = 0; /* only clean samples can accumulate radio-baseline evidence */
    update_output(state, feedback->member_id, reason, output);
}

static void adaptive_on_timeout(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    uint32_t reason = expire_drain(state, now);
    if (state->num_active_members != 0 && now >= state->next_timeout) {
        if (++state->unanswered_probes >= 3) {
            state->rate /= 2;
            state->unanswered_probes = 0;
            state->startup_probes = STARTUP_PROBES;
            state->last_reduction_epoch = control_epoch(state, now);
            state->last_reduction_at = now;
            state->growth_blocked_until = deadline(now, control_interval(state) * 2);
        }
        /* At the floor, ordinary pacing still permits bounded probe traffic.
         * Silence never authorizes a rate increase or disables congestion. */
        state->next_timeout = deadline(now, state->config.feedback_timeout_msec);
        reason |= QUICLY_FLEXICAST_CC_REASON_TIMEOUT;
    }
    update_output(state, 0, reason, output);
}

static void adaptive_set_hints(void *_state, const quicly_flexicast_cc_hints_t *hints, int64_t now,
                               quicly_flexicast_cc_output_t *output)
{
    adaptive_state_t *state = _state;
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_HINT | expire_drain(state, now);
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

static void adaptive_get_trace_state(const void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_trace_state_t *trace)
{
    const adaptive_state_t *state = _state;
    trace->available = 1;
    trace->control_epoch = control_epoch(state, now);
    trace->control_interval_msec = control_interval(state);
    trace->last_growth_epoch = state->last_growth_epoch;
    trace->last_reduction_epoch = state->last_reduction_epoch;
    trace->last_growth_at = state->last_growth_at;
    trace->last_reduction_at = state->last_reduction_at;
    trace->growth_blocked_until = state->growth_blocked_until;
    trace->next_timeout = state->next_timeout;
    trace->startup_probes = state->startup_probes;
    trace->unanswered_probes = state->unanswered_probes;
    trace->external_load = external_load(state);
    trace->drain_phase = state->drain.phase;
    trace->drain_member_id = state->drain.member_id;
    trace->drain_ceiling_bytes_per_second = state->drain.ceiling;
    trace->drain_target_bytes_per_second = state->drain.target;
    trace->drain_started_at = state->drain.started_at;
    trace->drain_deadline = state->drain.deadline;
    trace->drain_ended_at = state->drain.ended_at;
    uint32_t divisor = state->hints.delivery_rate_divisor != 0 ? state->hints.delivery_rate_divisor : 1;
    trace->expected_delivery_rate = state->rate / divisor;
    int slot = flexicast_member_map_find(&state->member_map, member_id);
    if (slot >= 0) {
        const adaptive_member_t *member = state->members + slot;
        trace->member_present = 1;
        trace->last_feedback_epoch = member->last_feedback_epoch;
        trace->last_delivery_sample_epoch = member->last_delivery_sample_epoch;
        trace->last_rtt_sample_epoch = member->last_rtt_sample_epoch;
        trace->previous_rtt_at = member->previous_rtt_at;
        if (member->delivery_reference_rate != 0 && member->delivery_reference_fanout != 0)
            trace->expected_delivery_rate = member->delivery_reference_rate / member->delivery_reference_fanout;
        trace->recent_delivery_rate = member->recent_delivery_rate;
        trace->baseline_delivery_ratio_ppm = member->baseline_delivery_ratio_ppm;
        trace->recent_delivery_ratio_ppm = member->recent_delivery_ratio_ppm;
        trace->degraded_delivery_epochs = member->degraded_delivery_epochs;
        trace->delivery_ceiling_bytes_per_second = member->delivery_ceiling;
        trace->delivery_ceiling_eligible = member->delivery_ceiling_eligible;
        trace->delivery_sample_post_cut = member->delivery_sample_post_cut;
        trace->delivery_sample_ratio_ppm = member->delivery_sample_ratio_ppm;
        trace->baseline_loss_ppm = member->baseline_loss_ppm;
        trace->flat_loss_epochs = member->flat_loss_epochs;
        trace->minimum_rtt = member->minimum_rtt;
        trace->previous_rtt = member->previous_rtt;
        trace->rising_delay_epochs = member->rising_delay_epochs;
    }
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
    .get_trace_state = adaptive_get_trace_state,
};
