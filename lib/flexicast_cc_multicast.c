#include "quicly/flexicast_cc.h"
#include "flexicast_member_map.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct st_multicast_member_t {
    uint64_t id;
    uint64_t rate;
    uint32_t minimum_rtt;
    uint32_t smoothed_rtt;
    uint64_t last_feedback_epoch;
    int64_t last_feedback;
    int64_t last_timeout_probe;
    int64_t last_loss_reduction;
    int64_t last_ecn_reduction;
    uint32_t unanswered_feedback_probes;
    int rtt_congested;
    int active;
    size_t rate_heap_index;
    size_t timeout_heap_index;
} multicast_member_t;

typedef struct st_multicast_state_t {
    quicly_flexicast_cc_t super;
    multicast_member_t *members;
    size_t *rate_heap;
    size_t *timeout_heap;
    size_t num_members;
    flexicast_member_map_t member_map;
} multicast_state_t;

typedef enum en_multicast_heap_type_t { MULTICAST_HEAP_RATE, MULTICAST_HEAP_TIMEOUT } multicast_heap_type_t;

static inline uint64_t burst_size(const quicly_flexicast_cc_config_t *config, uint64_t rate)
{
    uint64_t minimum = (uint64_t)config->maximum_datagram_size * 4;
    uint64_t maximum = (uint64_t)config->maximum_datagram_size * 10;
    uint64_t burst = rate / 20;
    return burst < minimum ? minimum : burst > maximum ? maximum : burst;
}

/* scale down without overflowing the intermediate product (numerator <= denominator) */
static inline uint64_t scale_rate(uint64_t rate, uint32_t numerator, uint32_t denominator)
{
    return rate / denominator * numerator + rate % denominator * numerator / denominator;
}

static inline uint64_t increase_rate(uint64_t rate, uint64_t increase)
{
    return UINT64_MAX - rate < increase ? UINT64_MAX : rate + increase;
}

static inline int queue_delay_grew(uint32_t minimum_rtt, uint32_t latest_rtt)
{
    uint32_t margin = minimum_rtt / 4;
    if (margin < 5)
        margin = 5;
    return minimum_rtt != 0 && (uint64_t)latest_rtt > (uint64_t)minimum_rtt + margin;
}

static int64_t member_timeout(const multicast_state_t *state, const multicast_member_t *member)
{
    int64_t base;
    if (!member->active)
        return INT64_MAX;
    base = member->last_feedback > member->last_timeout_probe ? member->last_feedback : member->last_timeout_probe;
    return base > INT64_MAX - state->super.config.feedback_timeout_msec
               ? INT64_MAX
               : base + state->super.config.feedback_timeout_msec;
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
    if (left->active != right->active)
        return left->active;
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
    while (index * 2 + 1 < heap_size) {
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
    int slot = flexicast_member_map_find(&state->member_map, id);
    return slot >= 0 ? state->members + slot : NULL;
}

static void remove_member_slot(multicast_state_t *state, multicast_member_t *member)
{
    size_t slot = (size_t)(member - state->members), last = state->num_members - 1;
    flexicast_member_map_remove(&state->member_map, member->id);
    heap_remove(state, MULTICAST_HEAP_RATE, member);
    heap_remove(state, MULTICAST_HEAP_TIMEOUT, member);
    if (slot != last) {
        state->members[slot] = state->members[last];
        flexicast_member_map_set(&state->member_map, state->members[slot].id, slot);
        state->rate_heap[state->members[slot].rate_heap_index] = slot;
        state->timeout_heap[state->members[slot].timeout_heap_index] = slot;
    }
    memset(state->members + last, 0, sizeof(state->members[last]));
    --state->num_members;
}

static multicast_member_t *add_member(multicast_state_t *state, uint64_t id, int64_t now)
{
    multicast_member_t *member = find_member(state, id);
    if (member != NULL) {
        if (!member->active) {
            member->active = 1;
            member->last_feedback = now;
            member->last_timeout_probe = now;
            member->unanswered_feedback_probes = 0;
            heap_update(state, MULTICAST_HEAP_RATE, member);
            heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
        }
        return member;
    }
    if (state->num_members == state->super.config.maximum_members) {
        for (size_t i = 0; i != state->num_members; ++i) {
            if (!state->members[i].active) {
                remove_member_slot(state, state->members + i);
                break;
            }
        }
        if (state->num_members == state->super.config.maximum_members)
            return NULL;
    }
    flexicast_member_map_set(&state->member_map, id, state->num_members);
    member = state->members + state->num_members++;
    member->id = id;
    member->active = 1;
    member->rate = quicly_flexicast_cc_clamp_rate(&state->super.config, state->super.config.startup_rate_bytes_per_second);
    member->last_feedback = now;
    member->last_timeout_probe = now;
    member->last_loss_reduction = INT64_MIN;
    member->last_ecn_reduction = INT64_MIN;
    heap_insert(state, MULTICAST_HEAP_RATE, (size_t)(member - state->members));
    heap_insert(state, MULTICAST_HEAP_TIMEOUT, (size_t)(member - state->members));
    return member;
}

static void update_output(multicast_state_t *state, int64_t now, uint32_t reason)
{
    quicly_flexicast_cc_output_t *output = &state->super.output;
    multicast_member_t *limiting = state->num_members != 0 ? state->members + state->rate_heap[0] : NULL;
    if (limiting != NULL && !limiting->active)
        limiting = NULL;
    int64_t next_timeout = state->num_members != 0 ? member_timeout(state, state->members + state->timeout_heap[0]) : INT64_MAX;
    uint64_t rate = limiting != NULL          ? limiting->rate
                    : state->num_members != 0 ? output->rate_bytes_per_second
                                              : state->super.config.startup_rate_bytes_per_second;
    rate = quicly_flexicast_cc_clamp_rate(&state->super.config, rate);
    uint64_t burst = burst_size(&state->super.config, rate);
    uint64_t minimum_burst = (uint64_t)state->super.config.maximum_datagram_size * 4;
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

static void multicast_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    (void)add_member(state, member_id, now);
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
}

static void multicast_on_member_removed(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    multicast_member_t *member = find_member(state, member_id);
    if (member != NULL)
        remove_member_slot(state, member);
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
}

static void multicast_on_member_suspended(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    multicast_member_t *member = find_member(state, member_id);
    if (member != NULL && member->active) {
        member->active = 0;
        heap_update(state, MULTICAST_HEAP_RATE, member);
        heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    }
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
}

static void multicast_on_epoch_reset(quicly_flexicast_cc_t *cc, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    for (size_t i = 0; i != state->num_members; ++i) {
        state->members[i].last_feedback = now;
        state->members[i].last_feedback_epoch = 0;
        state->members[i].last_timeout_probe = now;
        state->members[i].last_loss_reduction = INT64_MIN;
        state->members[i].last_ecn_reduction = INT64_MIN;
        state->members[i].rtt_congested = 0;
        state->members[i].unanswered_feedback_probes = 0;
        heap_update(state, MULTICAST_HEAP_TIMEOUT, state->members + i);
    }
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
}

static int reduction_epoch_ready(const multicast_state_t *state, int64_t previous, int64_t now)
{
    return previous == INT64_MIN || now < previous ||
           (uint64_t)now - (uint64_t)previous >= state->super.config.feedback_timeout_msec;
}

static void multicast_on_feedback(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    multicast_member_t *member = add_member(state, feedback->member_id, feedback->now);
    uint32_t reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (member == NULL)
        return;
    if (feedback->epoch != 0 && feedback->epoch <= member->last_feedback_epoch) {
        update_output(state, feedback->now, QUICLY_FLEXICAST_CC_REASON_NONE);
        return;
    }
    if (feedback->epoch != 0)
        member->last_feedback_epoch = feedback->epoch;
    if (feedback->minimum_rtt_msec != 0)
        member->minimum_rtt = feedback->minimum_rtt_msec;
    if (feedback->smoothed_rtt_msec != 0)
        member->smoothed_rtt = feedback->smoothed_rtt_msec;
    member->last_feedback = feedback->now;
    member->unanswered_feedback_probes = 0;

    if (feedback->ecn_ce_count != 0) {
        if (reduction_epoch_ready(state, member->last_ecn_reduction, feedback->now)) {
            member->rate = member->rate - scale_rate(member->rate, 15, 100);
            member->last_ecn_reduction = feedback->now;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_ECN;
    } else if (feedback->lost_packets != 0) {
        if (reduction_epoch_ready(state, member->last_loss_reduction, feedback->now)) {
            member->rate = scale_rate(member->rate, 7, 10);
            member->last_loss_reduction = feedback->now;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_LOSS;
    } else if (queue_delay_grew(member->minimum_rtt, feedback->latest_rtt_msec)) {
        /* treat one elevated queue episode as a single reduction until normal RTT rearms */
        if (!member->rtt_congested)
            member->rate = scale_rate(member->rate, 7, 10);
        member->rtt_congested = 1;
        reason |= QUICLY_FLEXICAST_CC_REASON_RTT;
    } else if (feedback->acked_packets != 0) {
        member->rtt_congested = 0;
        uint32_t rtt = member->smoothed_rtt != 0 ? member->smoothed_rtt : 100;
        uint64_t increase = (uint64_t)state->super.config.maximum_datagram_size * 1000 / rtt;
        if (increase < member->rate / 20)
            increase = member->rate / 20;
        member->rate = increase_rate(member->rate, increase);
        reason |= QUICLY_FLEXICAST_CC_REASON_ACK;
    }
    member->rate = quicly_flexicast_cc_clamp_rate(&state->super.config, member->rate);
    heap_update(state, MULTICAST_HEAP_RATE, member);
    heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    update_output(state, feedback->now, reason);
}

static void multicast_on_timeout(quicly_flexicast_cc_t *cc, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    int reduced = 0;
    while (state->num_members != 0) {
        multicast_member_t *member = state->members + state->timeout_heap[0];
        int64_t deadline = member_timeout(state, member);
        if (deadline == INT64_MAX || deadline > now)
            break;
        member->last_timeout_probe = now;
        if (++member->unanswered_feedback_probes >= 3) {
            member->rate = quicly_flexicast_cc_clamp_rate(&state->super.config, member->rate / 2);
            member->unanswered_feedback_probes = 0;
            heap_update(state, MULTICAST_HEAP_RATE, member);
            reduced = 1;
        }
        heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    }
    update_output(state, now, reduced ? QUICLY_FLEXICAST_CC_REASON_TIMEOUT : QUICLY_FLEXICAST_CC_REASON_NONE);
}

quicly_flexicast_cc_type_t quicly_flexicast_cc_type_multicast = {
    .name = "multicast",
    .on_member_added = multicast_on_member_added,
    .on_member_removed = multicast_on_member_removed,
    .on_member_suspended = multicast_on_member_suspended,
    .on_epoch_reset = multicast_on_epoch_reset,
    .on_feedback = multicast_on_feedback,
    .on_timeout = multicast_on_timeout,
};

quicly_flexicast_cc_t *quicly_flexicast_cc_new_multicast(const quicly_flexicast_cc_config_t *config, int64_t now)
{
    multicast_state_t *state;

    if ((state = calloc(1, sizeof(*state))) == NULL)
        return NULL;
    if (quicly_flexicast_cc_init(&state->super, &quicly_flexicast_cc_type_multicast, config) != 0 ||
        (state->members = calloc(state->super.config.maximum_members, sizeof(*state->members))) == NULL ||
        (state->rate_heap = malloc(state->super.config.maximum_members * sizeof(*state->rate_heap))) == NULL ||
        (state->timeout_heap = malloc(state->super.config.maximum_members * sizeof(*state->timeout_heap))) == NULL ||
        flexicast_member_map_init(&state->member_map, state->super.config.maximum_members) != 0) {
        quicly_flexicast_cc_free_multicast(&state->super);
        return NULL;
    }
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
    return &state->super;
}

void quicly_flexicast_cc_free_multicast(quicly_flexicast_cc_t *cc)
{
    if (cc == NULL)
        return;
    multicast_state_t *state = (multicast_state_t *)cc;
    flexicast_member_map_dispose(&state->member_map);
    free(state->members);
    free(state->rate_heap);
    free(state->timeout_heap);
    free(state);
}
