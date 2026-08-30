/*
 * Copyright (c) 2026 Joseph Calderon
 * SPDX-License-Identifier: MIT
 */
#include "quicly/flexicast_cc.h"
#include "flexicast_cc_member_map.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct st_multicast_member_t {
    uint64_t id;
    uint64_t rate;
    uint32_t minimum_rtt;
    uint32_t smoothed_rtt;
    int64_t last_feedback;
    int64_t last_timeout_probe;
    int64_t last_loss_reduction;
    int64_t last_ecn_reduction;
    uint32_t unanswered_feedback_probes;
    int rtt_congested;
    size_t rate_heap_index;
    size_t timeout_heap_index;
} multicast_member_t;

typedef struct st_multicast_state_t {
    quicly_flexicast_cc_config_t config;
    multicast_member_t *members;
    size_t *rate_heap;
    size_t *timeout_heap;
    size_t num_members;
    flexicast_cc_member_map_t member_map;
} multicast_state_t;

typedef enum en_multicast_heap_type_t { MULTICAST_HEAP_RATE, MULTICAST_HEAP_TIMEOUT } multicast_heap_type_t;

static uint64_t clamp_rate(const multicast_state_t *state, uint64_t rate)
{
    if (rate < state->config.minimum_rate_bytes_per_second)
        rate = state->config.minimum_rate_bytes_per_second;
    if (state->config.maximum_rate_bytes_per_second != 0 && rate > state->config.maximum_rate_bytes_per_second)
        rate = state->config.maximum_rate_bytes_per_second;
    return rate;
}

static int64_t member_timeout(const multicast_state_t *state, const multicast_member_t *member)
{
    int64_t base;
    if (member->last_feedback <= 0)
        return INT64_MAX;
    base = member->last_feedback > member->last_timeout_probe ? member->last_feedback : member->last_timeout_probe;
    return base > INT64_MAX - state->config.feedback_timeout_msec ? INT64_MAX : base + state->config.feedback_timeout_msec;
}

static size_t *heap_storage(multicast_state_t *state, multicast_heap_type_t type)
{
    return type == MULTICAST_HEAP_RATE ? state->rate_heap : state->timeout_heap;
}

static size_t *member_heap_index(multicast_member_t *member, multicast_heap_type_t type)
{
    return type == MULTICAST_HEAP_RATE ? &member->rate_heap_index : &member->timeout_heap_index;
}

static int heap_less(const multicast_state_t *state, multicast_heap_type_t type, size_t left_slot, size_t right_slot)
{
    const multicast_member_t *left = state->members + left_slot, *right = state->members + right_slot;
    if (type == MULTICAST_HEAP_RATE) {
        if (left->rate != right->rate)
            return left->rate < right->rate;
    } else {
        int64_t left_timeout = member_timeout(state, left), right_timeout = member_timeout(state, right);
        if (left_timeout != right_timeout)
            return left_timeout < right_timeout;
    }
    return left->id < right->id;
}

static void heap_swap(multicast_state_t *state, multicast_heap_type_t type, size_t left, size_t right)
{
    size_t *heap = heap_storage(state, type), slot = heap[left];
    heap[left] = heap[right];
    heap[right] = slot;
    *member_heap_index(state->members + heap[left], type) = left;
    *member_heap_index(state->members + heap[right], type) = right;
}

static size_t heap_sift_up(multicast_state_t *state, multicast_heap_type_t type, size_t index)
{
    size_t *heap = heap_storage(state, type);
    while (index != 0) {
        size_t parent = (index - 1) / 2;
        if (!heap_less(state, type, heap[index], heap[parent]))
            break;
        heap_swap(state, type, index, parent);
        index = parent;
    }
    return index;
}

static void heap_sift_down(multicast_state_t *state, multicast_heap_type_t type, size_t index, size_t heap_size)
{
    size_t *heap = heap_storage(state, type);
    while (index <= (heap_size - 1) / 2 && index * 2 + 1 < heap_size) {
        size_t child = index * 2 + 1;
        if (child + 1 < heap_size && heap_less(state, type, heap[child + 1], heap[child]))
            ++child;
        if (!heap_less(state, type, heap[child], heap[index]))
            break;
        heap_swap(state, type, index, child);
        index = child;
    }
}

static void heap_insert(multicast_state_t *state, multicast_heap_type_t type, size_t member_slot)
{
    size_t *heap = heap_storage(state, type), index = state->num_members - 1;
    heap[index] = member_slot;
    *member_heap_index(state->members + member_slot, type) = index;
    (void)heap_sift_up(state, type, index);
}

static void heap_update(multicast_state_t *state, multicast_heap_type_t type, multicast_member_t *member)
{
    size_t index = *member_heap_index(member, type);
    index = heap_sift_up(state, type, index);
    heap_sift_down(state, type, index, state->num_members);
}

static void heap_remove(multicast_state_t *state, multicast_heap_type_t type, multicast_member_t *member)
{
    size_t *heap = heap_storage(state, type), index = *member_heap_index(member, type);
    size_t heap_size = state->num_members, replacement = heap[heap_size - 1];
    if (index == heap_size - 1)
        return;
    heap[index] = replacement;
    *member_heap_index(state->members + replacement, type) = index;
    index = heap_sift_up(state, type, index);
    heap_sift_down(state, type, index, heap_size - 1);
}

static multicast_member_t *find_member(multicast_state_t *state, uint64_t id)
{
    size_t slot;
    return flexicast_cc_member_map_find(&state->member_map, id, &slot) == 0 ? state->members + slot : NULL;
}

static multicast_member_t *add_member(multicast_state_t *state, uint64_t id, int64_t now)
{
    multicast_member_t *member = find_member(state, id);
    if (member != NULL)
        return member;
    if (state->num_members == state->config.maximum_members ||
        flexicast_cc_member_map_insert(&state->member_map, id, state->num_members) != 0)
        return NULL;
    member = state->members + state->num_members++;
    member->id = id;
    member->rate = state->config.startup_rate_bytes_per_second;
    member->last_feedback = now;
    heap_insert(state, MULTICAST_HEAP_RATE, (size_t)(member - state->members));
    heap_insert(state, MULTICAST_HEAP_TIMEOUT, (size_t)(member - state->members));
    return member;
}

static void update_output(multicast_state_t *state, int64_t now, uint32_t reason, quicly_flexicast_cc_output_t *output)
{
    multicast_member_t *limiting = state->num_members != 0 ? state->members + state->rate_heap[0] : NULL;
    int64_t next_timeout = state->num_members != 0 ? member_timeout(state, state->members + state->timeout_heap[0]) : INT64_MAX;
    uint64_t rate = limiting != NULL ? limiting->rate : state->config.startup_rate_bytes_per_second;
    rate = clamp_rate(state, rate);
    uint64_t minimum_burst = (uint64_t)state->config.maximum_datagram_size * 4;
    uint64_t maximum_burst = (uint64_t)state->config.maximum_datagram_size * 10;
    uint64_t burst = rate / 20;
    if (burst < minimum_burst)
        burst = minimum_burst;
    if (burst > maximum_burst)
        burst = maximum_burst;
    uint32_t rtt = limiting != NULL && limiting->smoothed_rtt != 0 ? limiting->smoothed_rtt : 100;
    uint64_t inflight = rate > UINT64_MAX / rtt ? UINT64_MAX : rate * rtt / 1000;
    if (inflight < minimum_burst)
        inflight = minimum_burst;
    output->rate_bytes_per_second = rate;
    output->burst_bytes = burst;
    output->inflight_bytes = inflight;
    output->limiting_member_id = limiting != NULL ? limiting->id : 0;
    output->next_timeout = next_timeout > now ? next_timeout : now;
    output->reason = reason;
}

static int multicast_init(void *_state, const quicly_flexicast_cc_config_t *config, int64_t now,
                          quicly_flexicast_cc_output_t *output)
{
    multicast_state_t *state = _state;
    state->config = *config;
    if ((state->members = calloc(config->maximum_members, sizeof(*state->members))) == NULL ||
        (state->rate_heap = malloc(config->maximum_members * sizeof(*state->rate_heap))) == NULL ||
        (state->timeout_heap = malloc(config->maximum_members * sizeof(*state->timeout_heap))) == NULL ||
        flexicast_cc_member_map_init(&state->member_map, config->maximum_members) != 0) {
        free(state->members);
        free(state->rate_heap);
        free(state->timeout_heap);
        state->members = NULL;
        state->rate_heap = NULL;
        state->timeout_heap = NULL;
        return -1;
    }
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE, output);
    return 0;
}

static void multicast_dispose(void *_state)
{
    multicast_state_t *state = _state;
    flexicast_cc_member_map_dispose(&state->member_map);
    free(state->members);
    free(state->rate_heap);
    free(state->timeout_heap);
    state->members = NULL;
    state->rate_heap = NULL;
    state->timeout_heap = NULL;
    state->num_members = 0;
}

static void multicast_on_member_added(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    multicast_state_t *state = _state;
    (void)add_member(state, member_id, now);
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static void multicast_on_member_removed(void *_state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output)
{
    multicast_state_t *state = _state;
    multicast_member_t *member = find_member(state, member_id);
    if (member != NULL) {
        size_t slot = (size_t)(member - state->members), last = state->num_members - 1;
        flexicast_cc_member_map_remove(&state->member_map, member_id);
        heap_remove(state, MULTICAST_HEAP_RATE, member);
        heap_remove(state, MULTICAST_HEAP_TIMEOUT, member);
        if (slot != last) {
            state->members[slot] = state->members[last];
            flexicast_cc_member_map_update(&state->member_map, state->members[slot].id, slot);
            state->rate_heap[state->members[slot].rate_heap_index] = slot;
            state->timeout_heap[state->members[slot].timeout_heap_index] = slot;
        }
        memset(state->members + last, 0, sizeof(state->members[last]));
        --state->num_members;
    }
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static void multicast_on_epoch_reset(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    multicast_state_t *state = _state;
    for (size_t i = 0; i != state->num_members; ++i) {
        state->members[i].last_feedback = now;
        state->members[i].last_timeout_probe = 0;
        state->members[i].unanswered_feedback_probes = 0;
        heap_update(state, MULTICAST_HEAP_TIMEOUT, state->members + i);
    }
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

static int queue_delay_grew(const multicast_member_t *member, const quicly_flexicast_feedback_t *feedback)
{
    uint32_t floor = feedback->minimum_rtt_msec != 0 ? feedback->minimum_rtt_msec : member->minimum_rtt;
    uint32_t margin = floor / 4;
    if (margin < 5)
        margin = 5;
    return floor != 0 && feedback->latest_rtt_msec > floor + margin;
}

static int reduction_epoch_ready(const multicast_state_t *state, int64_t previous, int64_t now)
{
    return previous <= 0 || now < previous || (uint64_t)(now - previous) >= state->config.feedback_timeout_msec;
}

static void multicast_on_feedback(void *_state, const quicly_flexicast_feedback_t *feedback, quicly_flexicast_cc_output_t *output)
{
    multicast_state_t *state = _state;
    multicast_member_t *member = add_member(state, feedback->member_id, feedback->now);
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (member == NULL)
        return;
    if (feedback->minimum_rtt_msec != 0)
        member->minimum_rtt = feedback->minimum_rtt_msec;
    if (feedback->smoothed_rtt_msec != 0)
        member->smoothed_rtt = feedback->smoothed_rtt_msec;
    member->last_feedback = feedback->now;
    member->unanswered_feedback_probes = 0;

    if (feedback->ecn_ce_count != 0) {
        if (reduction_epoch_ready(state, member->last_ecn_reduction, feedback->now)) {
            member->rate = member->rate - member->rate * 15 / 100;
            member->last_ecn_reduction = feedback->now;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_ECN;
    } else if (feedback->lost_packets != 0) {
        if (reduction_epoch_ready(state, member->last_loss_reduction, feedback->now)) {
            member->rate = member->rate * 7 / 10;
            member->last_loss_reduction = feedback->now;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_LOSS;
    } else if (queue_delay_grew(member, feedback)) {
        /* One elevated queue is one congestion episode. Repeated ACKs from
         * that episode freeze growth instead of multiplying the rate down to
         * the floor. A normal RTT sample rearms the detector. */
        if (!member->rtt_congested)
            member->rate = member->rate * 7 / 10;
        member->rtt_congested = 1;
        reason |= QUICLY_FLEXICAST_CC_REASON_RTT;
    } else if (feedback->acked_packets != 0) {
        member->rtt_congested = 0;
        uint32_t rtt = member->smoothed_rtt != 0 ? member->smoothed_rtt : 100;
        uint64_t increase = (uint64_t)state->config.maximum_datagram_size * 1000 / rtt;
        if (increase < member->rate / 20)
            increase = member->rate / 20;
        if (UINT64_MAX - member->rate < increase)
            member->rate = UINT64_MAX;
        else
            member->rate += increase;
        reason |= QUICLY_FLEXICAST_CC_REASON_ACK;
    }
    member->rate = clamp_rate(state, member->rate);
    heap_update(state, MULTICAST_HEAP_RATE, member);
    heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    update_output(state, feedback->now, reason, output);
}

static void multicast_on_timeout(void *_state, int64_t now, quicly_flexicast_cc_output_t *output)
{
    multicast_state_t *state = _state;
    int reduced = 0;
    while (state->num_members != 0) {
        multicast_member_t *member = state->members + state->timeout_heap[0];
        int64_t deadline = member_timeout(state, member);
        if (deadline == INT64_MAX || deadline > now)
            break;
        member->last_timeout_probe = now;
        if (++member->unanswered_feedback_probes >= 3) {
            member->rate = clamp_rate(state, member->rate / 2);
            member->unanswered_feedback_probes = 0;
            heap_update(state, MULTICAST_HEAP_RATE, member);
            reduced = 1;
        }
        heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    }
    update_output(state, now, reduced ? QUICLY_FLEXICAST_CC_REASON_TIMEOUT : QUICLY_FLEXICAST_CC_REASON_NONE, output);
}

quicly_flexicast_cc_type_t quicly_flexicast_cc_type_multicast = {
    .name = "multicast",
    .state_size = sizeof(multicast_state_t),
    .init = multicast_init,
    .dispose = multicast_dispose,
    .on_member_added = multicast_on_member_added,
    .on_member_removed = multicast_on_member_removed,
    .on_epoch_reset = multicast_on_epoch_reset,
    .on_feedback = multicast_on_feedback,
    .on_timeout = multicast_on_timeout,
};
