#include "quicly/flexicast.h"
#include "flexicast_member_map.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define MULTICAST_NO_SLOT UINT32_MAX
#define MULTICAST_SENT_RING_SIZE QUICLY_FLEXICAST_SENT_WINDOW
#define MULTICAST_SENT_BLOCK_SIZE 64U
#define MULTICAST_SENT_BLOCK_COUNT (MULTICAST_SENT_RING_SIZE / MULTICAST_SENT_BLOCK_SIZE)

typedef struct st_multicast_sent_block_t {
    uint64_t present;
    int64_t timestamps[MULTICAST_SENT_BLOCK_SIZE];
} multicast_sent_block_t;

typedef struct st_multicast_member_t {
    uint64_t id;
    uint64_t rate;
    uint64_t growth_remainder;
    uint64_t next_unacked_pn;
    int64_t oldest_override_sent_at;
    uint32_t minimum_rtt;
    uint32_t smoothed_rtt;
    uint64_t last_feedback_epoch;
    int64_t last_feedback;
    int64_t last_timeout_probe;
    int64_t last_loss_reduction;
    int64_t last_ecn_reduction;
    uint32_t unanswered_feedback_probes;
    uint32_t prev_inactive;
    uint32_t next_inactive;
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
    size_t member_capacity;
    uint32_t inactive_head;
    uint32_t inactive_tail;
    uint64_t first_sent_pn;
    uint64_t next_expected_pn;
    int64_t first_send_at;
    int64_t max_event_at;
    multicast_sent_block_t *sent_at[MULTICAST_SENT_BLOCK_COUNT];
    int has_sent_packets;
    int any_unanswered_probes;
    int any_override_sent_at;
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

/* compute floor((delivered * gain + *remainder) / window) without 64-bit overflow */
static uint64_t proportional_rate_increase(uint64_t delivered, uint64_t gain, uint64_t window, uint64_t *remainder)
{
    uint64_t whole = delivered / window, rem_delivered = delivered % window;
    if (whole != 0 && gain > UINT64_MAX / whole) {
        *remainder = 0;
        return UINT64_MAX;
    }
    uint64_t base_inc = whole * gain;

#ifdef __SIZEOF_INT128__
    __uint128_t numer = (__uint128_t)rem_delivered * gain + *remainder;
    uint64_t sub_inc = (uint64_t)(numer / window);
    *remainder = (uint64_t)(numer % window);
#else
    /* portable 64-bit fallback when 128-bit integers are unavailable */
    uint64_t q = gain / window, r = gain % window;
    uint64_t sub_inc = rem_delivered * q;
    uint64_t prod_q = 0, prod_r = *remainder % window;
    sub_inc = increase_rate(sub_inc, *remainder / window);
    uint64_t a = rem_delivered, b = r;
    while (a != 0 && b != 0) {
        if (b & 1) {
            if (window - prod_r <= a) {
                ++prod_q;
                prod_r = a - (window - prod_r);
            } else {
                prod_r += a;
            }
        }
        b >>= 1;
        if (b != 0) {
            if (window - a <= a) {
                prod_q += b;
                a = a - (window - a);
            } else {
                a += a;
            }
        }
    }
    sub_inc = increase_rate(sub_inc, prod_q);
    *remainder = prod_r;
#endif
    return increase_rate(base_inc, sub_inc);
}

static inline int queue_delay_grew(uint32_t minimum_rtt, uint32_t latest_rtt)
{
    uint32_t margin = minimum_rtt / 4;
    if (margin < 5)
        margin = 5;
    return minimum_rtt != 0 && (uint64_t)latest_rtt > (uint64_t)minimum_rtt + margin;
}

static inline void note_event_time(multicast_state_t *state, int64_t now)
{
    if (now > state->max_event_at)
        state->max_event_at = now;
}

static int64_t member_timeout_base(const multicast_member_t *member)
{
    return member->last_feedback > member->last_timeout_probe ? member->last_feedback : member->last_timeout_probe;
}

static int member_awaiting_feedback(const multicast_state_t *state, const multicast_member_t *member)
{
    return member->active && state->has_sent_packets && member->next_unacked_pn < state->next_expected_pn;
}

static void clear_sent_timestamps(multicast_state_t *state)
{
    for (size_t i = 0; i != MULTICAST_SENT_BLOCK_COUNT; ++i) {
        free(state->sent_at[i]);
        state->sent_at[i] = NULL;
    }
}

static int64_t get_sent_at(const multicast_state_t *state, uint64_t pn)
{
    size_t slot = pn % MULTICAST_SENT_RING_SIZE;
    const multicast_sent_block_t *block = state->sent_at[slot / MULTICAST_SENT_BLOCK_SIZE];
    size_t offset = slot % MULTICAST_SENT_BLOCK_SIZE;
    if (block == NULL || ((block->present >> offset) & 1) == 0)
        return state->first_send_at;
    return block->timestamps[offset];
}

static void set_sent_at(multicast_state_t *state, uint64_t pn, int64_t now)
{
    size_t slot = pn % MULTICAST_SENT_RING_SIZE;
    multicast_sent_block_t **block = &state->sent_at[slot / MULTICAST_SENT_BLOCK_SIZE];
    /* The controller callback has no error return. Use the same fallback as for older packets if allocation fails. */
    if (*block == NULL && (*block = calloc(1, sizeof(**block))) == NULL)
        return;
    size_t offset = slot % MULTICAST_SENT_BLOCK_SIZE;
    (*block)->timestamps[offset] = now;
    (*block)->present |= UINT64_C(1) << offset;
}

static int64_t member_pkt_sent_at(const multicast_state_t *state, const multicast_member_t *member)
{
    if (member->oldest_override_sent_at != INT64_MIN)
        return member->oldest_override_sent_at;
    if (member->next_unacked_pn <= state->first_sent_pn ||
        state->next_expected_pn - member->next_unacked_pn > MULTICAST_SENT_RING_SIZE)
        return state->first_send_at;
    return get_sent_at(state, member->next_unacked_pn);
}

static int64_t member_effective_base(const multicast_state_t *state, const multicast_member_t *member)
{
    int64_t base = member_timeout_base(member);
    int64_t sent_at = member_pkt_sent_at(state, member);
    return base > sent_at ? base : sent_at;
}

/* caught-up members return INT64_MAX so idle groups schedule zero timer wakeups */
static int64_t member_deadline(const multicast_state_t *state, const multicast_member_t *member)
{
    if (!member_awaiting_feedback(state, member))
        return INT64_MAX;
    int64_t base = member_effective_base(state, member);
    return base > INT64_MAX - state->super.config.feedback_timeout_msec ? INT64_MAX
                                                                        : base + state->super.config.feedback_timeout_msec;
}

static void inactive_push_back(multicast_state_t *state, uint32_t slot)
{
    multicast_member_t *m = state->members + slot;
    m->prev_inactive = state->inactive_tail;
    m->next_inactive = MULTICAST_NO_SLOT;
    if (state->inactive_tail != MULTICAST_NO_SLOT)
        state->members[state->inactive_tail].next_inactive = slot;
    else
        state->inactive_head = slot;
    state->inactive_tail = slot;
}

static void inactive_unlink(multicast_state_t *state, uint32_t slot)
{
    multicast_member_t *m = state->members + slot;
    if (m->prev_inactive != MULTICAST_NO_SLOT)
        state->members[m->prev_inactive].next_inactive = m->next_inactive;
    else if (state->inactive_head == slot)
        state->inactive_head = m->next_inactive;
    if (m->next_inactive != MULTICAST_NO_SLOT)
        state->members[m->next_inactive].prev_inactive = m->prev_inactive;
    else if (state->inactive_tail == slot)
        state->inactive_tail = m->prev_inactive;
    m->prev_inactive = m->next_inactive = MULTICAST_NO_SLOT;
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
    } else if (left->active) {
        int left_awaiting = member_awaiting_feedback(state, left);
        int right_awaiting = member_awaiting_feedback(state, right);
        if (left_awaiting != right_awaiting)
            return left_awaiting;
        if (left_awaiting) {
            int64_t left_eff = member_effective_base(state, left), right_eff = member_effective_base(state, right);
            if (left_eff != right_eff)
                return left_eff < right_eff;
        }
        if (left->next_unacked_pn != right->next_unacked_pn)
            return left->next_unacked_pn < right->next_unacked_pn;
        int64_t left_base = member_timeout_base(left), right_base = member_timeout_base(right);
        if (left_base != right_base)
            return left_base < right_base;
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

static void timeout_heap_rebuild(multicast_state_t *state)
{
    for (size_t i = state->num_members / 2; i > 0;) {
        --i;
        heap_sift_down(state, MULTICAST_HEAP_TIMEOUT, i, state->num_members);
    }
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
    if (!member->active)
        inactive_unlink(state, (uint32_t)slot);
    flexicast_member_map_remove(&state->member_map, member->id);
    heap_remove(state, MULTICAST_HEAP_RATE, member);
    heap_remove(state, MULTICAST_HEAP_TIMEOUT, member);
    if (slot != last) {
        int moved_inactive = !state->members[last].active;
        uint32_t prev = state->members[last].prev_inactive, next = state->members[last].next_inactive;
        state->members[slot] = state->members[last];
        if (moved_inactive) {
            if (prev != MULTICAST_NO_SLOT)
                state->members[prev].next_inactive = (uint32_t)slot;
            else
                state->inactive_head = (uint32_t)slot;
            if (next != MULTICAST_NO_SLOT)
                state->members[next].prev_inactive = (uint32_t)slot;
            else
                state->inactive_tail = (uint32_t)slot;
        }
        flexicast_member_map_set(&state->member_map, state->members[slot].id, slot);
        state->rate_heap[state->members[slot].rate_heap_index] = slot;
        state->timeout_heap[state->members[slot].timeout_heap_index] = slot;
    }
    memset(state->members + last, 0, sizeof(state->members[last]));
    --state->num_members;
}

static int grow_multicast_members(multicast_state_t *state)
{
    size_t capacity = state->member_capacity != 0 ? state->member_capacity * 2 : 8;
    if (capacity > state->super.config.maximum_members)
        capacity = state->super.config.maximum_members;
    multicast_member_t *members = malloc(capacity * sizeof(*members));
    size_t *rate_heap = malloc(capacity * sizeof(*rate_heap)), *timeout_heap = malloc(capacity * sizeof(*timeout_heap));
    if (members == NULL || rate_heap == NULL || timeout_heap == NULL ||
        flexicast_member_map_reserve(&state->member_map, capacity) != 0) {
        free(members);
        free(rate_heap);
        free(timeout_heap);
        return -1;
    }
    if (state->num_members != 0) {
        memcpy(members, state->members, state->num_members * sizeof(*members));
        memcpy(rate_heap, state->rate_heap, state->num_members * sizeof(*rate_heap));
        memcpy(timeout_heap, state->timeout_heap, state->num_members * sizeof(*timeout_heap));
    }
    free(state->members);
    free(state->rate_heap);
    free(state->timeout_heap);
    state->members = members;
    state->rate_heap = rate_heap;
    state->timeout_heap = timeout_heap;
    state->member_capacity = capacity;
    return 0;
}

static multicast_member_t *add_member(multicast_state_t *state, uint64_t id, int64_t now)
{
    multicast_member_t *member = find_member(state, id);
    note_event_time(state, now);
    if (member != NULL) {
        if (!member->active) {
            inactive_unlink(state, (uint32_t)(member - state->members));
            member->active = 1;
            member->next_unacked_pn = state->next_expected_pn;
            member->oldest_override_sent_at = INT64_MIN;
            member->last_feedback = now;
            member->last_timeout_probe = now;
            member->unanswered_feedback_probes = 0;
            heap_update(state, MULTICAST_HEAP_RATE, member);
            heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
        }
        return member;
    }
    if (state->num_members == state->super.config.maximum_members) {
        if (state->inactive_head == MULTICAST_NO_SLOT)
            return NULL;
        remove_member_slot(state, state->members + state->inactive_head);
    } else if (state->num_members == state->member_capacity && grow_multicast_members(state) != 0) {
        return NULL;
    }
    flexicast_member_map_set(&state->member_map, id, state->num_members);
    member = state->members + state->num_members++;
    memset(member, 0, sizeof(*member));
    member->id = id;
    member->active = 1;
    member->prev_inactive = member->next_inactive = MULTICAST_NO_SLOT;
    member->next_unacked_pn = state->next_expected_pn;
    member->oldest_override_sent_at = INT64_MIN;
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
    int64_t next_timeout = state->num_members != 0 ? member_deadline(state, state->members + state->timeout_heap[0]) : INT64_MAX;
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
    output->next_timeout = next_timeout == INT64_MAX ? INT64_MAX : (next_timeout > now ? next_timeout : now);
    output->reason = reason;
}

static int multicast_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    multicast_member_t *member = add_member(state, member_id, now);
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
    return member != NULL ? 0 : -1;
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
        member->oldest_override_sent_at = INT64_MIN;
        inactive_push_back(state, (uint32_t)(member - state->members));
        heap_update(state, MULTICAST_HEAP_RATE, member);
        heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    }
    update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
}

static void multicast_on_epoch_reset(quicly_flexicast_cc_t *cc, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    clear_sent_timestamps(state);
    state->has_sent_packets = 0;
    state->any_unanswered_probes = 0;
    state->any_override_sent_at = 0;
    state->first_sent_pn = 0;
    state->next_expected_pn = 0;
    state->first_send_at = 0;
    state->max_event_at = now;
    for (size_t i = 0; i != state->num_members; ++i) {
        state->members[i].growth_remainder = 0;
        state->members[i].next_unacked_pn = 0;
        state->members[i].oldest_override_sent_at = INT64_MIN;
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

static void multicast_on_packet_sent(quicly_flexicast_cc_t *cc, uint64_t packet_number, size_t packet_size, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    int rearm = !state->has_sent_packets || state->super.output.next_timeout == INT64_MAX;
    int64_t send_at = now >= state->max_event_at ? now : state->max_event_at;
    (void)packet_size;
    state->max_event_at = send_at;
    if (!state->has_sent_packets) {
        state->has_sent_packets = 1;
        state->first_sent_pn = packet_number;
        state->first_send_at = send_at;
        set_sent_at(state, packet_number, send_at);
        state->next_expected_pn = packet_number < UINT64_MAX ? packet_number + 1 : UINT64_MAX;
    } else if (packet_number >= state->next_expected_pn) {
        uint64_t fill_from = state->next_expected_pn;
        if (packet_number - fill_from >= MULTICAST_SENT_RING_SIZE)
            fill_from = packet_number - (MULTICAST_SENT_RING_SIZE - 1);
        for (uint64_t pn = fill_from;; ++pn) {
            set_sent_at(state, pn, send_at);
            if (pn == packet_number)
                break;
        }
        state->next_expected_pn = packet_number < UINT64_MAX ? packet_number + 1 : UINT64_MAX;
    }
    if (rearm)
        update_output(state, now, state->super.output.reason);
}

static void apply_member_pending_state(multicast_state_t *state, multicast_member_t *member, int has_pending,
                                       uint64_t oldest_pending_pn, int64_t oldest_sent_at)
{
    if (!has_pending) {
        member->next_unacked_pn = state->next_expected_pn;
        member->oldest_override_sent_at = INT64_MIN;
        member->unanswered_feedback_probes = 0;
        return;
    }
    int64_t prev_sent_at = member_pkt_sent_at(state, member);
    if (oldest_pending_pn != member->next_unacked_pn || (oldest_sent_at > 0 && oldest_sent_at > prev_sent_at)) {
        member->unanswered_feedback_probes = 0;
        if (oldest_sent_at > 0 && member->last_timeout_probe < oldest_sent_at)
            member->last_timeout_probe = oldest_sent_at;
    }
    member->next_unacked_pn = oldest_pending_pn;
    if (oldest_sent_at > 0) {
        note_event_time(state, oldest_sent_at);
        member->oldest_override_sent_at = oldest_sent_at;
        state->any_override_sent_at = 1;
    } else {
        member->oldest_override_sent_at = INT64_MIN;
    }
}

static void multicast_on_member_pending_updated(quicly_flexicast_cc_t *cc, uint64_t member_id, int has_pending,
                                                uint64_t oldest_pending_pn, int64_t oldest_sent_at, int64_t now)
{
    multicast_state_t *state = (multicast_state_t *)cc;
    if (member_id == 0) {
        if (!state->has_sent_packets || oldest_pending_pn >= state->next_expected_pn)
            return;
        int64_t prev_max_event_at = state->max_event_at;
        if (now != INT64_MIN)
            note_event_time(state, now);
        if (has_pending && oldest_sent_at > 0) {
            note_event_time(state, oldest_sent_at);
            int in_ring = oldest_pending_pn >= state->first_sent_pn &&
                          state->next_expected_pn - oldest_pending_pn <= MULTICAST_SENT_RING_SIZE;
            int64_t prev_ring_at =
                oldest_pending_pn == state->first_sent_pn
                    ? state->first_send_at
                    : (in_ring ? get_sent_at(state, oldest_pending_pn) : state->first_send_at);
            if (oldest_pending_pn == state->first_sent_pn)
                state->first_send_at = oldest_sent_at;
            if (in_ring)
                set_sent_at(state, oldest_pending_pn, oldest_sent_at);
            if (state->any_unanswered_probes && oldest_sent_at > prev_ring_at) {
                int still_probing = 0;
                for (size_t i = 0; i != state->num_members; ++i) {
                    multicast_member_t *m = state->members + i;
                    if (m->active && m->next_unacked_pn == oldest_pending_pn && m->oldest_override_sent_at == INT64_MIN) {
                        m->unanswered_feedback_probes = 0;
                        if (m->last_timeout_probe < oldest_sent_at)
                            m->last_timeout_probe = oldest_sent_at;
                    }
                    if (m->active && m->unanswered_feedback_probes != 0)
                        still_probing = 1;
                }
                state->any_unanswered_probes = still_probing;
            }
            if (oldest_sent_at != prev_ring_at &&
                (oldest_pending_pn + 1 != state->next_expected_pn || prev_max_event_at > prev_ring_at ||
                 oldest_sent_at < prev_ring_at || state->any_override_sent_at))
                timeout_heap_rebuild(state);
        }
        update_output(state, now != INT64_MIN && now > state->max_event_at ? now : state->max_event_at, state->super.output.reason);
        return;
    }
    multicast_member_t *member = find_member(state, member_id);
    if (member == NULL)
        return;
    if (now != INT64_MIN)
        note_event_time(state, now);
    apply_member_pending_state(state, member, has_pending, oldest_pending_pn, oldest_sent_at);
    heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    update_output(state, now != INT64_MIN && now > state->max_event_at ? now : state->max_event_at, state->super.output.reason);
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
    if (feedback->pending_valid) {
        apply_member_pending_state(state, member, feedback->has_pending, feedback->oldest_pending_pn,
                                   feedback->oldest_pending_sent_at);
    } else if (cc->bound_flow == NULL &&
               (feedback->acked_packets != 0 || feedback->lost_packets != 0 || feedback->ecn_ce_count != 0)) {
        uint64_t next_pn = feedback->largest_acknowledged < UINT64_MAX ? feedback->largest_acknowledged + 1 : UINT64_MAX;
        if (next_pn > member->next_unacked_pn)
            member->next_unacked_pn = next_pn;
    }
    if (feedback->minimum_rtt_msec != 0)
        member->minimum_rtt = feedback->minimum_rtt_msec;
    if (feedback->smoothed_rtt_msec != 0)
        member->smoothed_rtt = feedback->smoothed_rtt_msec;
    member->last_feedback = feedback->now;
    note_event_time(state, feedback->now);
    member->unanswered_feedback_probes = 0;

    if (feedback->ecn_ce_count != 0) {
        if (reduction_epoch_ready(state, member->last_ecn_reduction, feedback->now)) {
            member->rate = member->rate - scale_rate(member->rate, 15, 100);
            member->growth_remainder = 0;
            member->last_ecn_reduction = feedback->now;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_ECN;
    } else if (feedback->lost_packets != 0) {
        if (reduction_epoch_ready(state, member->last_loss_reduction, feedback->now)) {
            member->rate = scale_rate(member->rate, 7, 10);
            member->growth_remainder = 0;
            member->last_loss_reduction = feedback->now;
        }
        reason |= QUICLY_FLEXICAST_CC_REASON_LOSS;
    } else if (queue_delay_grew(member->minimum_rtt, feedback->latest_rtt_msec)) {
        /* treat one elevated queue episode as a single reduction until normal RTT rearms */
        if (!member->rtt_congested) {
            member->rate = scale_rate(member->rate, 7, 10);
            member->growth_remainder = 0;
        }
        member->rtt_congested = 1;
        reason |= QUICLY_FLEXICAST_CC_REASON_RTT;
    } else if (feedback->acked_packets != 0) {
        member->rtt_congested = 0;
        uint64_t mss = state->super.config.maximum_datagram_size;
        uint64_t delivered = feedback->acked_bytes != 0                   ? feedback->acked_bytes
                             : feedback->acked_packets > UINT64_MAX / mss ? UINT64_MAX
                                                                          : feedback->acked_packets * mss;
        int sample_limited =
            feedback->delivery_rate_sample_epoch != 0 &&
            (feedback->delivery_sample_flags & (QUICLY_FLEXICAST_SAMPLE_APP_LIMITED | QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED)) != 0 &&
            feedback->delivery_rate_bytes_per_second < member->rate;
        if (delivered != 0 && !sample_limited) {
            uint32_t rtt = member->smoothed_rtt != 0 ? member->smoothed_rtt : 100;
            uint64_t min_window = mss * 4;
            uint64_t window = member->rate > UINT64_MAX / rtt ? UINT64_MAX : member->rate * rtt / 1000;
            if (window < min_window)
                window = min_window;
            uint64_t gain = mss * 1000 / rtt;
            if (gain < member->rate / 20)
                gain = member->rate / 20;
            uint64_t inc = proportional_rate_increase(delivered, gain, window, &member->growth_remainder);
            member->rate = increase_rate(member->rate, inc);
        }
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
    if (!state->has_sent_packets) {
        update_output(state, now, QUICLY_FLEXICAST_CC_REASON_NONE);
        return;
    }
    note_event_time(state, now);
    while (state->num_members != 0) {
        multicast_member_t *member = state->members + state->timeout_heap[0];
        int64_t deadline = member_deadline(state, member);
        if (deadline == INT64_MAX || deadline > now)
            break;
        member->last_timeout_probe = now;
        state->any_unanswered_probes = 1;
        if (++member->unanswered_feedback_probes >= 3) {
            member->rate = quicly_flexicast_cc_clamp_rate(&state->super.config, member->rate / 2);
            member->growth_remainder = 0;
            member->unanswered_feedback_probes = 0;
            heap_update(state, MULTICAST_HEAP_RATE, member);
            reduced = 1;
        }
        heap_update(state, MULTICAST_HEAP_TIMEOUT, member);
    }
    update_output(state, now, reduced ? QUICLY_FLEXICAST_CC_REASON_TIMEOUT : QUICLY_FLEXICAST_CC_REASON_NONE);
}

static quicly_flexicast_cc_type_t quicly_flexicast_cc_type_multicast = {
    .name = "multicast",
    .on_member_added = multicast_on_member_added,
    .on_member_removed = multicast_on_member_removed,
    .on_member_suspended = multicast_on_member_suspended,
    .on_epoch_reset = multicast_on_epoch_reset,
    .on_packet_sent = multicast_on_packet_sent,
    .on_feedback = multicast_on_feedback,
    .on_timeout = multicast_on_timeout,
    .on_member_pending_updated = multicast_on_member_pending_updated,
};

quicly_flexicast_cc_t *quicly_flexicast_cc_new_multicast(const quicly_flexicast_cc_config_t *config, int64_t now)
{
    multicast_state_t *state;

    if ((state = calloc(1, sizeof(*state))) == NULL)
        return NULL;
    state->inactive_head = state->inactive_tail = MULTICAST_NO_SLOT;
    state->max_event_at = now;
    if (quicly_flexicast_cc_init(&state->super, &quicly_flexicast_cc_type_multicast, config) != 0) {
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
    clear_sent_timestamps(state);
    flexicast_member_map_dispose(&state->member_map);
    free(state->members);
    free(state->rate_heap);
    free(state->timeout_heap);
    free(state);
}
