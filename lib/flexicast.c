#include "quicly/flexicast.h"
#include "flexicast_member_map.h"

#include <limits.h>
#include <stdlib.h>

#define FLEXICAST_NO_SLOT UINT32_MAX
#define MAX_SUBMISSION_TIMESTAMPS 4096
#define FLEXICAST_LIM_INLINE_CAPACITY 4U
#define FLEXICAST_LIM_MAX_CAPACITY 1024U
#define FLEXICAST_SENT_BLOCK_SIZE 64U
#define FLEXICAST_SENT_BLOCK_COUNT (QUICLY_FLEXICAST_SENT_WINDOW / FLEXICAST_SENT_BLOCK_SIZE)

typedef struct st_flexicast_lim_span_t {
    int64_t start;
    int64_t end;
    uint64_t last_pn;
    uint32_t flags;
} flexicast_lim_span_t;

typedef struct st_flexicast_lim_ring_t {
    flexicast_lim_span_t inline_entries[FLEXICAST_LIM_INLINE_CAPACITY];
    flexicast_lim_span_t *ext_entries;
    int64_t max_end;
    uint16_t capacity;
    uint16_t head;
    uint16_t count;
    uint8_t non_monotone;
} flexicast_lim_ring_t;

typedef struct st_quicly_flexicast_sent_t {
    uint64_t packet_number;
    uint64_t checked_suspend_epoch;
    size_t pending_count;
    size_t packet_size;
    int64_t sent_at;
    quicly_flexicast_send_context_t context;
    int has_submission;
    int rtt_untracked;
} quicly_flexicast_sent_t;

typedef struct st_flexicast_sent_block_t {
    quicly_flexicast_sent_t packets[FLEXICAST_SENT_BLOCK_SIZE];
    /* One row per packet, each containing flow->member_word_count words. */
    uint64_t pending[];
} flexicast_sent_block_t;

typedef struct st_flexicast_submission_t {
    uint64_t packet_number;
    int64_t submitted_at;
    quicly_flexicast_send_context_t context;
    uint32_t member_slot_plus_one;
} flexicast_submission_t;

typedef struct st_flexicast_retired_key_t {
    uint8_t secret_hash[PTLS_MAX_DIGEST_SIZE];
    uint64_t encrypted_packets;
    uint64_t decryption_attempts;
    int occupied;
} flexicast_retired_key_t;

typedef struct st_flexicast_delivery_sample_t {
    uint64_t bytes;
    uint64_t rate;
    int64_t sent_at_start, sent_at_end;
    int64_t acked_at_start, acked_at_end;
    quicly_flexicast_send_context_t context;
    int timestamps_valid;
    int end_timestamp_valid;
} flexicast_delivery_sample_t;

typedef struct st_quicly_flexicast_member_t {
    uint64_t loss_cursor;
    uint64_t cc_pending_cursor;
    uint64_t path_sample_floor;
    uint64_t active_since_pn;
    uint64_t suspended_at_pn;
    uint64_t excluded_packets;
    uint64_t retired_packets;
    quicly_ranges_t ecn_unreported_retired;
    flexicast_lim_ring_t limitations;
    flexicast_delivery_sample_t rate_sample;
    flexicast_delivery_sample_t published_rate_sample;
    uint64_t rate_sample_epoch;
    uint64_t rtt_sample_epoch;
    int64_t rtt_sample_at;
    uint32_t raw_rtt_msec, rtt_ack_delay_msec, applied_ack_delay_msec, rtt_sample_flags;
    uint32_t prev_inactive;
    uint32_t next_inactive;
    quicly_flexicast_member_stats_t stats;
    int has_rtt_sample;
    int active;
} quicly_flexicast_member_t;

struct st_quicly_flexicast_flow_t {
    quicly_flexicast_flow_id_t flow_id;
    ptls_cipher_suite_t *cipher_suite;
    quicly_crypto_engine_t *crypto_engine;
    quicly_conn_t *crypto_conn;
    struct {
        ptls_cipher_context_t *header_protection;
        ptls_aead_context_t *aead;
    } egress, ingress;
    struct {
        uint8_t secret_hash[PTLS_MAX_DIGEST_SIZE];
        flexicast_retired_key_t *retired_keys;
        size_t retired_key_capacity;
        size_t num_retired_keys;
        uint64_t encrypted_packets;
        uint64_t max_packets_per_key;
        uint64_t decryption_attempts;
        uint64_t max_decryption_attempts;
        uint64_t authentication_failures;
        uint64_t max_authentication_failures;
        int has_key;
    } crypto;
    uint64_t next_packet_number;
    uint64_t first_packet_number;
    uint64_t suspend_epoch;
    size_t max_packet_size;
    uint16_t packet_reordering_threshold;
    struct {
        uint64_t largest;
        uint64_t history_lower_bound;
        uint64_t bootstrap_floor;
        uint64_t mask;
        quicly_ranges_t ack_ranges;
        size_t ack_eliciting_since_ack;
        size_t ack_ranges_since_ack;
        uint64_t ack_frames_sent;
        uint64_t ecn_counts[3];
        int64_t ack_pending_since;
        int64_t largest_received_at;
        uint32_t ack_delay_msec;
        uint16_t ack_frequency;
        int initialized;
    } received;
    quicly_flexicast_cc_t *cc;
    size_t max_members;
    size_t member_capacity;
    size_t member_word_count;
    /* sender-side structures allocated lazily on first attach */
    flexicast_sent_block_t **sent;
    quicly_flexicast_member_t *members;
    uint32_t *free_member_slots;
    size_t num_free_member_slots;
    size_t member_slot_watermark;
    size_t num_members;
    uint32_t inactive_head;
    uint32_t inactive_tail;
    flexicast_member_map_t member_map;
    uint64_t *active_member_words;
    flexicast_submission_t *submissions;
    size_t submission_capacity;
    size_t num_submissions;
    flexicast_lim_ring_t limitations;
};

static size_t retired_key_hash(const uint8_t *secret_hash)
{
    const uint8_t *p = secret_hash;
    return (size_t)quicly_decode64(&p);
}

static flexicast_retired_key_t *find_retired_key_slot(flexicast_retired_key_t *entries, size_t capacity, const uint8_t *secret_hash,
                                                      size_t digest_size)
{
    size_t mask = capacity - 1, slot = retired_key_hash(secret_hash) & mask;
    while (entries[slot].occupied && !ptls_mem_equal(entries[slot].secret_hash, secret_hash, digest_size))
        slot = (slot + 1) & mask;
    return entries + slot;
}

static flexicast_retired_key_t *find_retired_key(const quicly_flexicast_flow_t *flow, const uint8_t *secret_hash,
                                                 size_t digest_size)
{
    if (flow->crypto.retired_key_capacity == 0)
        return NULL;
    flexicast_retired_key_t *entry =
        find_retired_key_slot(flow->crypto.retired_keys, flow->crypto.retired_key_capacity, secret_hash, digest_size);
    return entry->occupied ? entry : NULL;
}

static int ensure_retired_key_slot(quicly_flexicast_flow_t *flow, const uint8_t *secret_hash, size_t digest_size)
{
    if (find_retired_key(flow, secret_hash, digest_size) != NULL)
        return QUICLY_FLEXICAST_OK;
    if (flow->crypto.num_retired_keys >= QUICLY_FLEXICAST_MAX_RETIRED_KEYS)
        return QUICLY_FLEXICAST_ERROR_STATE_EXHAUSTION;
    if (flow->crypto.retired_key_capacity == 0 || flow->crypto.num_retired_keys * 2 >= flow->crypto.retired_key_capacity) {
        size_t capacity = flow->crypto.retired_key_capacity != 0 ? flow->crypto.retired_key_capacity * 2 : 8;
        flexicast_retired_key_t *entries = calloc(capacity, sizeof(*entries));
        if (entries == NULL)
            return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
        for (size_t i = 0; i != flow->crypto.retired_key_capacity; ++i) {
            if (flow->crypto.retired_keys[i].occupied) {
                *find_retired_key_slot(entries, capacity, flow->crypto.retired_keys[i].secret_hash, digest_size) =
                    flow->crypto.retired_keys[i];
            }
        }
        if (flow->crypto.retired_keys != NULL) {
            ptls_clear_memory(flow->crypto.retired_keys, flow->crypto.retired_key_capacity * sizeof(*flow->crypto.retired_keys));
            free(flow->crypto.retired_keys);
        }
        flow->crypto.retired_keys = entries;
        flow->crypto.retired_key_capacity = capacity;
    }
    return QUICLY_FLEXICAST_OK;
}

static void save_retired_key(quicly_flexicast_flow_t *flow, const uint8_t *secret_hash, size_t digest_size,
                             uint64_t encrypted_packets, uint64_t decryption_attempts)
{
    flexicast_retired_key_t *entry =
        find_retired_key_slot(flow->crypto.retired_keys, flow->crypto.retired_key_capacity, secret_hash, digest_size);
    if (!entry->occupied) {
        memcpy(entry->secret_hash, secret_hash, digest_size);
        entry->occupied = 1;
        ++flow->crypto.num_retired_keys;
    }
    entry->encrypted_packets = encrypted_packets;
    entry->decryption_attempts = decryption_attempts;
}

static void inactive_member_push_back(quicly_flexicast_flow_t *flow, uint32_t slot)
{
    quicly_flexicast_member_t *member = flow->members + slot;
    member->prev_inactive = flow->inactive_tail;
    member->next_inactive = FLEXICAST_NO_SLOT;
    if (flow->inactive_tail != FLEXICAST_NO_SLOT)
        flow->members[flow->inactive_tail].next_inactive = slot;
    else
        flow->inactive_head = slot;
    flow->inactive_tail = slot;
}

static void inactive_member_unlink(quicly_flexicast_flow_t *flow, uint32_t slot)
{
    quicly_flexicast_member_t *member = flow->members + slot;
    if (member->prev_inactive != FLEXICAST_NO_SLOT)
        flow->members[member->prev_inactive].next_inactive = member->next_inactive;
    else if (flow->inactive_head == slot)
        flow->inactive_head = member->next_inactive;
    if (member->next_inactive != FLEXICAST_NO_SLOT)
        flow->members[member->next_inactive].prev_inactive = member->prev_inactive;
    else if (flow->inactive_tail == slot)
        flow->inactive_tail = member->prev_inactive;
    member->prev_inactive = member->next_inactive = FLEXICAST_NO_SLOT;
}

static size_t submission_hash(uint64_t packet_number, uint32_t member_slot_plus_one)
{
    return flexicast_member_hash(packet_number ^ (UINT64_C(0x9e3779b97f4a7c15) * member_slot_plus_one));
}

static flexicast_submission_t *find_submission(quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t member_slot)
{
    if (flow->num_submissions == 0)
        return NULL;
    uint32_t key = (uint32_t)member_slot + 1;
    size_t slot = submission_hash(packet_number, key) & (flow->submission_capacity - 1);
    while (flow->submissions[slot].member_slot_plus_one != 0) {
        flexicast_submission_t *entry = flow->submissions + slot;
        if (entry->packet_number == packet_number && entry->member_slot_plus_one == key)
            return entry;
        slot = (slot + 1) & (flow->submission_capacity - 1);
    }
    return NULL;
}

static void insert_submission(flexicast_submission_t *entries, size_t capacity, flexicast_submission_t entry)
{
    size_t slot = submission_hash(entry.packet_number, entry.member_slot_plus_one) & (capacity - 1);
    while (entries[slot].member_slot_plus_one != 0)
        slot = (slot + 1) & (capacity - 1);
    entries[slot] = entry;
}

static int save_submission(quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t member_slot, int64_t now,
                           const quicly_flexicast_send_context_t *context)
{
    flexicast_submission_t *existing = find_submission(flow, packet_number, member_slot);
    if (existing != NULL) {
        existing->submitted_at = now;
        existing->context = *context;
        return 1;
    }
    if (flow->num_submissions == MAX_SUBMISSION_TIMESTAMPS)
        return 0;
    if (flow->submission_capacity == 0 || flow->num_submissions * 2 >= flow->submission_capacity) {
        size_t capacity = flow->submission_capacity != 0 ? flow->submission_capacity * 2 : 32;
        flexicast_submission_t *entries = calloc(capacity, sizeof(*entries));
        if (entries == NULL)
            return 0;
        for (size_t i = 0; i != flow->submission_capacity; ++i)
            if (flow->submissions[i].member_slot_plus_one != 0)
                insert_submission(entries, capacity, flow->submissions[i]);
        free(flow->submissions);
        flow->submissions = entries;
        flow->submission_capacity = capacity;
    }
    insert_submission(flow->submissions, flow->submission_capacity,
                      (flexicast_submission_t){.packet_number = packet_number,
                                               .submitted_at = now,
                                               .context = *context,
                                               .member_slot_plus_one = (uint32_t)member_slot + 1});
    ++flow->num_submissions;
    return 1;
}

static void remove_submission(quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t member_slot)
{
    flexicast_submission_t *entry = find_submission(flow, packet_number, member_slot);
    if (entry == NULL)
        return;
    size_t mask = flow->submission_capacity - 1, hole = (size_t)(entry - flow->submissions);
    for (size_t i = (hole + 1) & mask; flow->submissions[i].member_slot_plus_one != 0; i = (i + 1) & mask) {
        size_t home = submission_hash(flow->submissions[i].packet_number, flow->submissions[i].member_slot_plus_one) & mask;
        if (((hole - home) & mask) < ((i - home) & mask)) {
            flow->submissions[hole] = flow->submissions[i];
            hole = i;
        }
    }
    flow->submissions[hole] = (flexicast_submission_t){0};
    --flow->num_submissions;
}

static size_t sent_block_index(uint64_t pn)
{
    return pn % QUICLY_FLEXICAST_SENT_WINDOW / FLEXICAST_SENT_BLOCK_SIZE;
}

static size_t sent_block_size(size_t member_words)
{
    return sizeof(flexicast_sent_block_t) + FLEXICAST_SENT_BLOCK_SIZE * member_words * sizeof(uint64_t);
}

static quicly_flexicast_sent_t *get_sent(const quicly_flexicast_flow_t *flow, uint64_t pn)
{
    flexicast_sent_block_t *block = flow->sent[sent_block_index(pn)];
    return block != NULL ? &block->packets[pn % FLEXICAST_SENT_BLOCK_SIZE] : NULL;
}

static uint64_t *sent_member_words(quicly_flexicast_flow_t *flow, const quicly_flexicast_sent_t *sent)
{
    uint64_t pn = sent->packet_number;
    return flow->sent[sent_block_index(pn)]->pending + pn % FLEXICAST_SENT_BLOCK_SIZE * flow->member_word_count;
}

static int sent_has_member(quicly_flexicast_flow_t *flow, const quicly_flexicast_sent_t *sent, size_t member_index)
{
    return (sent_member_words(flow, sent)[member_index / 64] & (UINT64_C(1) << (member_index % 64))) != 0;
}

static int sent_clear_member(quicly_flexicast_flow_t *flow, quicly_flexicast_sent_t *sent, size_t member_index)
{
    uint64_t *word = sent_member_words(flow, sent) + member_index / 64;
    uint64_t bit = UINT64_C(1) << (member_index % 64);
    if ((*word & bit) == 0)
        return 0;
    *word &= ~bit;
    remove_submission(flow, sent->packet_number, member_index);
    --sent->pending_count;
    ++flow->members[member_index].retired_packets;
    return 1;
}

static uint64_t member_pending_packets(const quicly_flexicast_flow_t *flow, const quicly_flexicast_member_t *member)
{
    uint64_t active_end = member->active ? flow->next_packet_number : member->suspended_at_pn;
    uint64_t sent_while_attached = active_end - flow->first_packet_number;
    uint64_t total_assigned = sent_while_attached - member->excluded_packets;
    return total_assigned > member->retired_packets ? total_assigned - member->retired_packets : 0;
}

static void dispose_ecn_unreported(quicly_ranges_t *ranges)
{
    if (ranges->ranges != NULL)
        quicly_ranges_clear(ranges);
    *ranges = (quicly_ranges_t){0};
}

static void record_ecn_unreported_retirement(quicly_flexicast_member_t *member, uint64_t start_pn, uint64_t end_pn)
{
    if (start_pn >= end_pn)
        return;
    if (member->ecn_unreported_retired.ranges == NULL)
        quicly_ranges_init(&member->ecn_unreported_retired);
    (void)quicly_ranges_add(&member->ecn_unreported_retired, start_pn, end_pn);
    if (member->ecn_unreported_retired.num_ranges > 64) {
        quicly_ranges_drop_by_range_indices(&member->ecn_unreported_retired, 0, member->ecn_unreported_retired.num_ranges - 64);
    }
}

static uint64_t count_ecn_unreported_overlap(const quicly_ranges_t *retired, uint64_t lo, uint64_t hi_excl)
{
    uint64_t count = 0;
    if (lo >= hi_excl)
        return 0;
    for (size_t i = 0; i != retired->num_ranges; ++i) {
        if (retired->ranges[i].end <= lo)
            continue;
        if (retired->ranges[i].start >= hi_excl)
            break;
        uint64_t s = retired->ranges[i].start > lo ? retired->ranges[i].start : lo;
        uint64_t e = retired->ranges[i].end < hi_excl ? retired->ranges[i].end : hi_excl;
        count += e - s;
    }
    return count;
}

static void lim_ring_dispose(flexicast_lim_ring_t *ring)
{
    free(ring->ext_entries);
    *ring = (flexicast_lim_ring_t){0};
}

static void lim_ring_prune(flexicast_lim_ring_t *ring, int64_t floor_at)
{
    if (ring->count == 0 || ring->non_monotone || floor_at <= 0)
        return;
    size_t cap = ring->capacity != 0 ? ring->capacity : FLEXICAST_LIM_INLINE_CAPACITY;
    flexicast_lim_span_t *entries = ring->ext_entries != NULL ? ring->ext_entries : ring->inline_entries;
    size_t oldest = (ring->head + cap - ring->count) & (cap - 1);
    while (ring->count != 0 && entries[oldest].end < floor_at) {
        --ring->count;
        oldest = (oldest + 1) & (cap - 1);
    }
    if (ring->count == 0) {
        ring->head = 0;
        ring->max_end = 0;
    }
    if (ring->ext_entries != NULL && ring->count <= FLEXICAST_LIM_INLINE_CAPACITY) {
        for (size_t i = 0; i != ring->count; ++i)
            ring->inline_entries[i] = entries[(oldest + i) & (cap - 1)];
        free(ring->ext_entries);
        ring->ext_entries = NULL;
        ring->capacity = 0;
        ring->head = ring->count & (FLEXICAST_LIM_INLINE_CAPACITY - 1);
    }
}

static void lim_ring_record(flexicast_lim_ring_t *ring, uint64_t pn, int64_t now, uint32_t flags, int64_t floor_at)
{
    size_t cap = ring->capacity != 0 ? ring->capacity : FLEXICAST_LIM_INLINE_CAPACITY;
    flexicast_lim_span_t *entries = ring->ext_entries != NULL ? ring->ext_entries : ring->inline_entries;
    if (ring->count != 0) {
        size_t prev_idx = (ring->head + cap - 1) & (cap - 1);
        flexicast_lim_span_t *prev = entries + prev_idx;
        if (prev->end == now) {
            prev->flags |= flags;
            if (pn > prev->last_pn)
                prev->last_pn = pn;
            return;
        }
        if (now < prev->end) {
            ring->non_monotone = 1;
        } else if (!ring->non_monotone && pn == prev->last_pn + 1 && prev->flags == flags) {
            prev->end = now;
            prev->last_pn = pn;
            if (now > ring->max_end)
                ring->max_end = now;
            return;
        }
    }
    if (ring->count == cap) {
        lim_ring_prune(ring, floor_at);
        cap = ring->capacity != 0 ? ring->capacity : FLEXICAST_LIM_INLINE_CAPACITY;
        entries = ring->ext_entries != NULL ? ring->ext_entries : ring->inline_entries;
    }
    if (ring->count == cap && cap < FLEXICAST_LIM_MAX_CAPACITY) {
        size_t new_cap = cap * 2;
        if (new_cap > FLEXICAST_LIM_MAX_CAPACITY)
            new_cap = FLEXICAST_LIM_MAX_CAPACITY;
        flexicast_lim_span_t *grown = malloc(new_cap * sizeof(*grown));
        if (grown != NULL) {
            size_t oldest = (ring->head + cap - ring->count) & (cap - 1);
            for (size_t i = 0; i != ring->count; ++i)
                grown[i] = entries[(oldest + i) & (cap - 1)];
            free(ring->ext_entries);
            ring->ext_entries = grown;
            ring->capacity = (uint16_t)new_cap;
            ring->head = ring->count;
            cap = new_cap;
            entries = grown;
        }
    }
    entries[ring->head] = (flexicast_lim_span_t){.start = now, .end = now, .last_pn = pn, .flags = flags};
    ring->head = (uint16_t)((ring->head + 1) & (cap - 1));
    if (ring->count < cap)
        ++ring->count;
    if (now > ring->max_end)
        ring->max_end = now;
}

static uint32_t lim_ring_query(const flexicast_lim_ring_t *ring, int64_t start, int64_t end, uint32_t flags)
{
    const uint32_t both = QUICLY_FLEXICAST_SAMPLE_APP_LIMITED | QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
    if (ring->count == 0 || ring->max_end < start || (flags & both) == both)
        return flags;
    size_t cap = ring->capacity != 0 ? ring->capacity : FLEXICAST_LIM_INLINE_CAPACITY;
    const flexicast_lim_span_t *entries = ring->ext_entries != NULL ? ring->ext_entries : ring->inline_entries;
    for (size_t i = 0; i < ring->count && (flags & both) != both; ++i) {
        size_t slot = (ring->head + cap - 1 - i) & (cap - 1);
        const flexicast_lim_span_t *sp = entries + slot;
        if (sp->end < start) {
            if (!ring->non_monotone)
                break;
            continue;
        }
        if (sp->start <= end)
            flags |= sp->flags;
    }
    return flags;
}

static void set_member_active(quicly_flexicast_flow_t *flow, size_t member_index, int active)
{
    uint64_t *word = flow->active_member_words + member_index / 64;
    uint64_t bit = UINT64_C(1) << (member_index % 64);
    if (active)
        *word |= bit;
    else
        *word &= ~bit;
}

static void clear_sent_blocks(quicly_flexicast_flow_t *flow)
{
    for (size_t i = 0; i != FLEXICAST_SENT_BLOCK_COUNT; ++i) {
        free(flow->sent[i]);
        flow->sent[i] = NULL;
    }
}

static void free_sender_state(quicly_flexicast_flow_t *flow)
{
    if (flow->members != NULL) {
        for (size_t i = 0; i != flow->member_slot_watermark; ++i) {
            dispose_ecn_unreported(&flow->members[i].ecn_unreported_retired);
            lim_ring_dispose(&flow->members[i].limitations);
        }
    }
    lim_ring_dispose(&flow->limitations);
    flexicast_member_map_dispose(&flow->member_map);
    if (flow->sent != NULL) {
        clear_sent_blocks(flow);
        free(flow->sent);
        flow->sent = NULL;
    }
    free(flow->members);
    flow->members = NULL;
    free(flow->free_member_slots);
    flow->free_member_slots = NULL;
    free(flow->active_member_words);
    flow->active_member_words = NULL;
    free(flow->submissions);
    flow->submissions = NULL;
    flow->member_capacity = 0;
    flow->member_word_count = 0;
    flow->num_free_member_slots = 0;
    flow->member_slot_watermark = 0;
    flow->num_members = 0;
    flow->inactive_head = flow->inactive_tail = FLEXICAST_NO_SLOT;
    flow->submission_capacity = 0;
    flow->num_submissions = 0;
}

static int grow_sent_member_words(quicly_flexicast_flow_t *flow, size_t words)
{
    flexicast_sent_block_t *blocks[FLEXICAST_SENT_BLOCK_COUNT] = {0};
    for (size_t i = 0; i != FLEXICAST_SENT_BLOCK_COUNT; ++i) {
        flexicast_sent_block_t *old = flow->sent[i];
        if (old == NULL)
            continue;
        if ((blocks[i] = calloc(1, sent_block_size(words))) == NULL) {
            for (size_t j = 0; j != i; ++j)
                free(blocks[j]);
            return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
        }
        memcpy(blocks[i]->packets, old->packets, sizeof(old->packets));
        for (size_t p = 0; p != FLEXICAST_SENT_BLOCK_SIZE; ++p)
            memcpy(blocks[i]->pending + p * words, old->pending + p * flow->member_word_count,
                   flow->member_word_count * sizeof(*old->pending));
    }
    clear_sent_blocks(flow);
    memcpy(flow->sent, blocks, sizeof(blocks));
    return QUICLY_FLEXICAST_OK;
}

static int grow_flow_members(quicly_flexicast_flow_t *flow)
{
    size_t old_capacity = flow->member_capacity, capacity = old_capacity != 0 ? old_capacity * 2 : 8;
    if (capacity > flow->max_members)
        capacity = flow->max_members;
    size_t old_words = flow->member_word_count, words = (capacity + 63) / 64;
    quicly_flexicast_member_t *members = calloc(capacity, sizeof(*members));
    uint32_t *free_slots = malloc(capacity * sizeof(*free_slots));
    uint64_t *active = words != old_words ? calloc(words, sizeof(*active)) : flow->active_member_words;
    if (members == NULL || free_slots == NULL || active == NULL ||
        flexicast_member_map_reserve(&flow->member_map, capacity) != 0 ||
        (words != old_words && grow_sent_member_words(flow, words) != QUICLY_FLEXICAST_OK)) {
        free(members);
        free(free_slots);
        if (words != old_words)
            free(active);
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    }

    for (size_t i = 0; i != flow->member_slot_watermark; ++i) {
        members[i] = flow->members[i];
        if (members[i].ecn_unreported_retired.ranges == &flow->members[i].ecn_unreported_retired._initial)
            members[i].ecn_unreported_retired.ranges = &members[i].ecn_unreported_retired._initial;
    }
    /* Push newly allocated slots in reverse order. Repeat attachments still prefer previously freed slots. */
    size_t added = capacity - old_capacity;
    for (size_t i = 0; i != added; ++i)
        free_slots[i] = (uint32_t)(capacity - 1 - i);
    if (flow->num_free_member_slots != 0)
        memcpy(free_slots + added, flow->free_member_slots, flow->num_free_member_slots * sizeof(*free_slots));
    flow->num_free_member_slots += added;
    free(flow->members);
    free(flow->free_member_slots);
    flow->members = members;
    flow->free_member_slots = free_slots;
    flow->member_capacity = capacity;

    if (words != old_words) {
        if (old_words != 0)
            memcpy(active, flow->active_member_words, old_words * sizeof(*active));
        free(flow->active_member_words);
        flow->active_member_words = active;
        flow->member_word_count = words;
    }
    return QUICLY_FLEXICAST_OK;
}

static int ensure_sender_state(quicly_flexicast_flow_t *flow)
{
    if (flow->sent != NULL)
        return QUICLY_FLEXICAST_OK;
    flow->inactive_head = flow->inactive_tail = FLEXICAST_NO_SLOT;
    if ((flow->sent = calloc(FLEXICAST_SENT_BLOCK_COUNT, sizeof(*flow->sent))) == NULL)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    int ret = grow_flow_members(flow);
    if (ret != QUICLY_FLEXICAST_OK)
        free_sender_state(flow);
    return ret;
}

static void dispose_cipher(ptls_cipher_context_t **hp, ptls_aead_context_t **aead)
{
    if (*hp != NULL) {
        ptls_cipher_free(*hp);
        *hp = NULL;
    }
    if (*aead != NULL) {
        ptls_aead_free(*aead);
        *aead = NULL;
    }
}

static int get_aead_limits(const quicly_flexicast_config_t *config, uint64_t *packets, uint64_t *failures, uint64_t *attempts)
{
    if (config->cipher_suite->aead->tag_size != 16 || config->cipher_suite->aead->iv_size != 12 ||
        config->cipher_suite->aead->ctr_cipher == NULL)
        return 0;
    /* RFC 9001 section 6.6 limits */
    switch (config->cipher_suite->id) {
    case PTLS_CIPHER_SUITE_AES_128_GCM_SHA256:
    case PTLS_CIPHER_SUITE_AES_256_GCM_SHA384:
        *packets = UINT64_C(1) << 23;
        *failures = UINT64_C(1) << 52;
        break;
    case PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256:
        *packets = PTLS_QUICINT_MAX + UINT64_C(1);
        *failures = UINT64_C(1) << 36;
        break;
    case 0x1304: /* TLS_AES_128_CCM_SHA256 */
        *packets = *failures = UINT64_C(2965820);
        break;
    default:
        return 0;
    }
    if (config->cipher_suite->aead->confidentiality_limit == 0 || config->cipher_suite->aead->integrity_limit == 0)
        return 0;
    if (*packets > config->cipher_suite->aead->confidentiality_limit)
        *packets = config->cipher_suite->aead->confidentiality_limit;
    if (*failures > config->cipher_suite->aead->integrity_limit)
        *failures = config->cipher_suite->aead->integrity_limit;
    *attempts = *failures;
    if (config->max_decryption_attempts > *attempts)
        return 0;
    if (config->max_decryption_attempts != 0)
        *attempts = config->max_decryption_attempts;
    if (config->max_packets_per_key > *packets || config->max_authentication_failures > *failures)
        return 0;
    if (config->max_packets_per_key != 0)
        *packets = config->max_packets_per_key;
    if (config->max_authentication_failures != 0)
        *failures = config->max_authentication_failures;
    return 1;
}

int quicly_flexicast_flow_create(quicly_flexicast_flow_t **flow, const quicly_flexicast_config_t *config)
{
    quicly_flexicast_flow_t *new_flow;
    uint64_t max_packets_per_key, max_authentication_failures, max_decryption_attempts;
    size_t max_members;
    int ret;

    if (flow == NULL || config == NULL || !quicly_flexicast_flow_id_is_valid(&config->flow_id) ||
        config->first_packet_number > PTLS_QUICINT_MAX || config->packet_reordering_threshold >= QUICLY_FLEXICAST_SENT_WINDOW ||
        config->cipher_suite == NULL || config->cipher_suite->hash == NULL || config->cipher_suite->hash->create == NULL ||
        config->cipher_suite->hash->digest_size == 0 || config->cipher_suite->hash->digest_size > PTLS_MAX_DIGEST_SIZE ||
        config->cipher_suite->aead == NULL || config->crypto_engine == NULL || config->crypto_engine->setup_cipher == NULL ||
        config->crypto_engine->encrypt_packet == NULL || config->traffic_secret.base == NULL ||
        config->traffic_secret.len != config->cipher_suite->hash->digest_size ||
        config->max_packet_size > QUICLY_FLEXICAST_MAX_PACKET_SIZE ||
        (config->max_packet_size != 0 && config->max_packet_size < QUICLY_FLEXICAST_DEFAULT_MAX_PACKET_SIZE))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (config->cc != NULL && (config->cc->type == NULL || config->cc->bound_flow != NULL))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (!get_aead_limits(config, &max_packets_per_key, &max_authentication_failures, &max_decryption_attempts))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    max_members = config->max_members != 0 ? config->max_members : QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS;
    if (max_members > QUICLY_FLEXICAST_HARD_MAX_MEMBERS || (config->cc != NULL && config->cc->config.maximum_members < max_members))
        return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
    *flow = NULL;
    if ((new_flow = calloc(1, sizeof(*new_flow))) == NULL)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    new_flow->inactive_head = new_flow->inactive_tail = FLEXICAST_NO_SLOT;
    new_flow->flow_id = config->flow_id;
    new_flow->cipher_suite = config->cipher_suite;
    new_flow->crypto_engine = config->crypto_engine;
    new_flow->crypto_conn = config->crypto_conn;
    new_flow->crypto.max_packets_per_key = max_packets_per_key;
    new_flow->crypto.max_authentication_failures = max_authentication_failures;
    new_flow->crypto.max_decryption_attempts = max_decryption_attempts;
    new_flow->max_packet_size = config->max_packet_size != 0 ? config->max_packet_size : QUICLY_FLEXICAST_DEFAULT_MAX_PACKET_SIZE;
    new_flow->packet_reordering_threshold = config->packet_reordering_threshold != 0 ? config->packet_reordering_threshold : 3;
    new_flow->max_members = max_members;
    new_flow->received.ack_delay_msec = config->ack_delay_msec != 0 ? config->ack_delay_msec : 25;
    new_flow->received.ack_frequency = config->ack_frequency != 0 ? config->ack_frequency : QUICLY_FLEXICAST_DEFAULT_ACK_FREQUENCY;
    quicly_ranges_init(&new_flow->received.ack_ranges);

    new_flow->cc = config->cc;
    if (new_flow->cc != NULL)
        new_flow->cc->bound_flow = new_flow;
    if ((ret = quicly_flexicast_flow_rekey(new_flow, config->traffic_secret, config->first_packet_number, config->now)) != 0) {
        quicly_flexicast_flow_free(new_flow);
        return ret;
    }
    *flow = new_flow;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_flow_has_sender_state(const quicly_flexicast_flow_t *flow)
{
    return flow != NULL && flow->sent != NULL;
}

int quicly_flexicast_get_crypto_usage(const quicly_flexicast_flow_t *flow, quicly_flexicast_crypto_usage_t *usage)
{
    if (flow == NULL || usage == NULL || !flow->crypto.has_key)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    *usage = (quicly_flexicast_crypto_usage_t){.encrypted_packets = flow->crypto.encrypted_packets,
                                               .max_packets_per_key = flow->crypto.max_packets_per_key,
                                               .decryption_attempts = flow->crypto.decryption_attempts,
                                               .max_decryption_attempts = flow->crypto.max_decryption_attempts,
                                               .authentication_failures = flow->crypto.authentication_failures,
                                               .max_authentication_failures = flow->crypto.max_authentication_failures};
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_set_decryption_attempts(quicly_flexicast_flow_t *flow, uint64_t attempts)
{
    if (flow == NULL || !flow->crypto.has_key || attempts < flow->crypto.decryption_attempts ||
        attempts > flow->crypto.max_decryption_attempts)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    flow->crypto.decryption_attempts = attempts;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_check_receive_floor(const quicly_flexicast_flow_t *flow, uint64_t next_unallocated)
{
    return flow == NULL || next_unallocated > PTLS_QUICINT_MAX || next_unallocated < flow->first_packet_number ||
                   next_unallocated < flow->received.bootstrap_floor || flow->received.initialized
               ? QUICLY_FLEXICAST_ERROR_INVALID
               : QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_install_receive_floor(quicly_flexicast_flow_t *flow, uint64_t next_unallocated)
{
    int ret = quicly_flexicast_check_receive_floor(flow, next_unallocated);
    if (ret != QUICLY_FLEXICAST_OK)
        return ret;
    flow->received.bootstrap_floor = next_unallocated;
    flow->received.history_lower_bound = next_unallocated;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_flow_rekey(quicly_flexicast_flow_t *flow, ptls_iovec_t traffic_secret, uint64_t first_packet_number,
                                int64_t now)
{
    ptls_cipher_context_t *egress_hp = NULL, *ingress_hp = NULL;
    ptls_aead_context_t *egress_aead = NULL, *ingress_aead = NULL;
    uint8_t secret_hash[PTLS_MAX_DIGEST_SIZE];
    size_t digest_size;
    int same_secret = 0, ret;

    if (flow == NULL || traffic_secret.base == NULL || traffic_secret.len != flow->cipher_suite->hash->digest_size ||
        first_packet_number > PTLS_QUICINT_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    digest_size = flow->cipher_suite->hash->digest_size;
    if (flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures)
        return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
    /* keep packet numbers unique across rekeys to avoid AEAD nonce reuse */
    if (flow->crypto.has_key &&
        (first_packet_number < flow->next_packet_number || first_packet_number < flow->received.bootstrap_floor ||
         (flow->received.initialized && first_packet_number <= flow->received.largest)))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (ptls_calc_hash(flow->cipher_suite->hash, secret_hash, traffic_secret.base, traffic_secret.len) != 0)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    if (flow->crypto.has_key && ptls_mem_equal(flow->crypto.secret_hash, secret_hash, digest_size)) {
        same_secret = 1;
        if (flow->crypto.encrypted_packets >= flow->crypto.max_packets_per_key) {
            ptls_clear_memory(secret_hash, sizeof(secret_hash));
            return QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED;
        }
        if (flow->crypto.decryption_attempts >= flow->crypto.max_decryption_attempts) {
            ptls_clear_memory(secret_hash, sizeof(secret_hash));
            return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
        }
    } else if (flow->crypto.has_key) {
        flexicast_retired_key_t *saved = find_retired_key(flow, secret_hash, digest_size);
        if (saved != NULL) {
            if (saved->encrypted_packets >= flow->crypto.max_packets_per_key) {
                ptls_clear_memory(secret_hash, sizeof(secret_hash));
                return QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED;
            }
            if (saved->decryption_attempts >= flow->crypto.max_decryption_attempts) {
                ptls_clear_memory(secret_hash, sizeof(secret_hash));
                return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
            }
        }
        if ((ret = ensure_retired_key_slot(flow, flow->crypto.secret_hash, digest_size)) != QUICLY_FLEXICAST_OK) {
            ptls_clear_memory(secret_hash, sizeof(secret_hash));
            return ret;
        }
    }
    if (flow->crypto_engine->setup_cipher(flow->crypto_engine, flow->crypto_conn, QUICLY_EPOCH_1RTT, 1, &egress_hp, &egress_aead,
                                          flow->cipher_suite->aead, flow->cipher_suite->hash, traffic_secret.base) != 0)
        goto Error;
    if (flow->crypto_engine->setup_cipher(flow->crypto_engine, flow->crypto_conn, QUICLY_EPOCH_1RTT, 0, &ingress_hp, &ingress_aead,
                                          flow->cipher_suite->aead, flow->cipher_suite->hash, traffic_secret.base) != 0)
        goto Error;

    dispose_cipher(&flow->egress.header_protection, &flow->egress.aead);
    dispose_cipher(&flow->ingress.header_protection, &flow->ingress.aead);
    flow->egress.header_protection = egress_hp;
    flow->egress.aead = egress_aead;
    flow->ingress.header_protection = ingress_hp;
    flow->ingress.aead = ingress_aead;
    if (!same_secret) {
        uint64_t next_encrypted = 0, next_decryptions = 0;
        if (flow->crypto.has_key) {
            flexicast_retired_key_t *saved = find_retired_key(flow, secret_hash, digest_size);
            if (saved != NULL) {
                next_encrypted = saved->encrypted_packets;
                next_decryptions = saved->decryption_attempts;
            }
            save_retired_key(flow, flow->crypto.secret_hash, digest_size, flow->crypto.encrypted_packets,
                             flow->crypto.decryption_attempts);
        }
        memcpy(flow->crypto.secret_hash, secret_hash, digest_size);
        flow->crypto.encrypted_packets = next_encrypted;
        flow->crypto.decryption_attempts = next_decryptions;
    }
    ptls_clear_memory(secret_hash, sizeof(secret_hash));
    flow->crypto.has_key = 1;
    flow->first_packet_number = first_packet_number;
    flow->next_packet_number = first_packet_number;
    flow->suspend_epoch = 1;
    flow->received.history_lower_bound = first_packet_number;
    flow->received.bootstrap_floor = first_packet_number;
    flow->received.largest = 0;
    flow->received.mask = 0;
    flow->received.initialized = 0;
    flow->received.ack_ranges.num_ranges = 0;
    flow->received.ack_eliciting_since_ack = 0;
    flow->received.ack_ranges_since_ack = 0;
    flow->received.ack_frames_sent = 0;
    memset(flow->received.ecn_counts, 0, sizeof(flow->received.ecn_counts));
    flow->received.ack_pending_since = 0;
    flow->received.largest_received_at = 0;
    lim_ring_dispose(&flow->limitations);
    if (flow->sent != NULL) {
        clear_sent_blocks(flow);
        if (flow->submissions != NULL && flow->num_submissions != 0)
            memset(flow->submissions, 0, flow->submission_capacity * sizeof(*flow->submissions));
        flow->num_submissions = 0;
        memset(flow->active_member_words, 0, flow->member_word_count * sizeof(*flow->active_member_words));
        flow->num_members = 0;
        flow->inactive_head = flow->inactive_tail = FLEXICAST_NO_SLOT;
        for (size_t i = 0; i != flow->member_slot_watermark; ++i) {
            if (flow->members[i].stats.member_id == 0)
                continue;
            if (flow->members[i].active)
                quicly_flexicast_cc_on_member_suspended(flow->cc, flow->members[i].stats.member_id, now);
            flow->members[i].active = 0;
            flow->members[i].prev_inactive = flow->members[i].next_inactive = FLEXICAST_NO_SLOT;
            inactive_member_push_back(flow, (uint32_t)i);
            flow->members[i].loss_cursor = first_packet_number;
            flow->members[i].cc_pending_cursor = first_packet_number;
            flow->members[i].path_sample_floor = first_packet_number;
            flow->members[i].active_since_pn = first_packet_number;
            flow->members[i].suspended_at_pn = first_packet_number;
            flow->members[i].excluded_packets = 0;
            flow->members[i].retired_packets = 0;
            dispose_ecn_unreported(&flow->members[i].ecn_unreported_retired);
            lim_ring_dispose(&flow->members[i].limitations);
            flow->members[i].stats.largest_acknowledged = 0;
            flow->members[i].stats.last_feedback_at = 0;
            flow->members[i].rate_sample = (flexicast_delivery_sample_t){0};
            flow->members[i].published_rate_sample = (flexicast_delivery_sample_t){0};
            flow->members[i].rate_sample_epoch = 0;
            flow->members[i].rtt_sample_epoch = 0;
            flow->members[i].rtt_sample_at = 0;
            flow->members[i].rtt_sample_flags = 0;
            flow->members[i].has_rtt_sample = 0;
            flow->members[i].raw_rtt_msec = 0;
            flow->members[i].rtt_ack_delay_msec = 0;
            flow->members[i].applied_ack_delay_msec = 0;
            /* ECN counters are cumulative within this key epoch */
            flow->members[i].stats.ecn_ce_count = 0;
        }
    }
    /* preserve learned path rates and reset controller liveness on rekey */
    quicly_flexicast_cc_on_epoch_reset(flow->cc, now);
    return QUICLY_FLEXICAST_OK;

Error:
    ptls_clear_memory(secret_hash, sizeof(secret_hash));
    dispose_cipher(&egress_hp, &egress_aead);
    dispose_cipher(&ingress_hp, &ingress_aead);
    return QUICLY_FLEXICAST_ERROR_CRYPTO;
}

void quicly_flexicast_flow_free(quicly_flexicast_flow_t *flow)
{
    if (flow == NULL)
        return;
    if (flow->cc != NULL) {
        if (flow->members != NULL) {
            for (size_t i = 0; i != flow->member_slot_watermark; ++i) {
                if (flow->members[i].stats.member_id != 0)
                    quicly_flexicast_cc_on_member_removed(flow->cc, flow->members[i].stats.member_id, 0);
            }
        }
        quicly_flexicast_cc_on_epoch_reset(flow->cc, 0);
        if (flow->cc->bound_flow == flow)
            flow->cc->bound_flow = NULL;
    }
    quicly_ranges_clear(&flow->received.ack_ranges);
    dispose_cipher(&flow->egress.header_protection, &flow->egress.aead);
    dispose_cipher(&flow->ingress.header_protection, &flow->ingress.aead);
    free_sender_state(flow);
    if (flow->crypto.retired_keys != NULL) {
        ptls_clear_memory(flow->crypto.retired_keys, flow->crypto.retired_key_capacity * sizeof(*flow->crypto.retired_keys));
        free(flow->crypto.retired_keys);
    }
    ptls_clear_memory(flow->crypto.secret_hash, sizeof(flow->crypto.secret_hash));
    free(flow);
}

const quicly_flexicast_flow_id_t *quicly_flexicast_get_flow_id(const quicly_flexicast_flow_t *flow)
{
    return flow != NULL ? &flow->flow_id : NULL;
}

uint64_t quicly_flexicast_get_next_packet_number(const quicly_flexicast_flow_t *flow)
{
    return flow != NULL ? flow->next_packet_number : 0;
}

static int find_member(const quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    if (flow->members == NULL)
        return -1;
    int index = flexicast_member_map_find(&flow->member_map, member_id);
    return index >= 0 && flow->members[index].active ? index : -1;
}

static int find_known_member(const quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    if (flow->members == NULL)
        return -1;
    return flexicast_member_map_find(&flow->member_map, member_id);
}

static uint64_t sent_window_start(const quicly_flexicast_flow_t *flow)
{
    return flow->next_packet_number - flow->first_packet_number > QUICLY_FLEXICAST_SENT_WINDOW
               ? flow->next_packet_number - QUICLY_FLEXICAST_SENT_WINDOW
               : flow->first_packet_number;
}

static void clear_member_pending_slots(quicly_flexicast_flow_t *flow, size_t member_index, uint64_t from_pn)
{
    uint64_t window_start = sent_window_start(flow);
    if (from_pn < window_start)
        from_pn = window_start;
    for (uint64_t cursor = from_pn; cursor < flow->next_packet_number; ++cursor) {
        quicly_flexicast_sent_t *sent = get_sent(flow, cursor);
        if (sent != NULL && sent->pending_count != 0 && sent->packet_number == cursor)
            (void)sent_clear_member(flow, sent, member_index);
    }
}

static void compute_member_cc_pending(quicly_flexicast_flow_t *flow, size_t member_index, int *has_pending, uint64_t *oldest_pn,
                                      int64_t *oldest_sent_at)
{
    quicly_flexicast_member_t *member = flow->members + member_index;
    *has_pending = 0;
    *oldest_pn = 0;
    *oldest_sent_at = 0;
    if (member_pending_packets(flow, member) == 0) {
        member->cc_pending_cursor = flow->next_packet_number;
        return;
    }
    uint64_t cursor = member->cc_pending_cursor;
    uint64_t floor = sent_window_start(flow);
    if (floor < member->path_sample_floor)
        floor = member->path_sample_floor;
    if (cursor < floor)
        cursor = floor;
    while (cursor < flow->next_packet_number) {
        const quicly_flexicast_sent_t *sent = get_sent(flow, cursor);
        if (sent != NULL && sent->pending_count != 0 && sent->packet_number == cursor &&
            sent_has_member(flow, sent, member_index)) {
            member->cc_pending_cursor = cursor;
            flexicast_submission_t *sub = find_submission(flow, cursor, member_index);
            *has_pending = 1;
            *oldest_pn = cursor;
            *oldest_sent_at = sub != NULL ? sub->submitted_at : sent->rtt_untracked ? 0 : sent->sent_at;
            return;
        }
        ++cursor;
    }
    member->cc_pending_cursor = flow->next_packet_number;
}

static void sync_member_cc_pending(quicly_flexicast_flow_t *flow, size_t member_index, int64_t now)
{
    quicly_flexicast_member_t *member = flow->members + member_index;
    int has_pending;
    uint64_t oldest_pn;
    int64_t oldest_sent_at;
    if (!member->active || flow->cc == NULL)
        return;
    compute_member_cc_pending(flow, member_index, &has_pending, &oldest_pn, &oldest_sent_at);
    quicly_flexicast_cc_on_member_pending_updated(flow->cc, member->stats.member_id, has_pending, oldest_pn, oldest_sent_at, now);
}

int quicly_flexicast_attach(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int index, ret;
    if (flow == NULL || member_id == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((ret = ensure_sender_state(flow)) != QUICLY_FLEXICAST_OK)
        return ret;
    index = find_known_member(flow, member_id);
    if (index >= 0) {
        if (!flow->members[index].active) {
            if (quicly_flexicast_cc_on_member_added(flow->cc, member_id, now) != 0)
                return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
            inactive_member_unlink(flow, (uint32_t)index);
            flow->members[index].excluded_packets += flow->next_packet_number - flow->members[index].suspended_at_pn;
            flow->members[index].active_since_pn = flow->next_packet_number;
            flow->members[index].active = 1;
            set_member_active(flow, (size_t)index, 1);
            ++flow->num_members;
            sync_member_cc_pending(flow, (size_t)index, now);
        }
        return QUICLY_FLEXICAST_OK;
    }
    if (flow->num_members >= flow->max_members)
        return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
    if (flow->num_free_member_slots == 0 && flow->member_capacity < flow->max_members &&
        (ret = grow_flow_members(flow)) != QUICLY_FLEXICAST_OK)
        return ret;
    if (flow->num_free_member_slots != 0) {
        if (quicly_flexicast_cc_on_member_added(flow->cc, member_id, now) != 0)
            return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
        index = (int)flow->free_member_slots[--flow->num_free_member_slots];
    } else {
        /* reclaim the oldest inactive suspended slot in O(1) */
        if (flow->inactive_head == FLEXICAST_NO_SLOT)
            return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
        uint32_t reclaimed = flow->inactive_head;
        uint64_t old_id = flow->members[reclaimed].stats.member_id;
        uint64_t old_cursor = flow->members[reclaimed].loss_cursor;
        inactive_member_unlink(flow, reclaimed);
        quicly_flexicast_cc_on_member_removed(flow->cc, old_id, now);
        flexicast_member_map_remove(&flow->member_map, old_id);
        clear_member_pending_slots(flow, reclaimed, old_cursor);
        dispose_ecn_unreported(&flow->members[reclaimed].ecn_unreported_retired);
        lim_ring_dispose(&flow->members[reclaimed].limitations);
        memset(&flow->members[reclaimed], 0, sizeof(flow->members[reclaimed]));
        flow->members[reclaimed].prev_inactive = flow->members[reclaimed].next_inactive = FLEXICAST_NO_SLOT;
        if (quicly_flexicast_cc_on_member_added(flow->cc, member_id, now) != 0) {
            flow->free_member_slots[flow->num_free_member_slots++] = reclaimed;
            return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
        }
        index = (int)reclaimed;
    }
    if ((size_t)index + 1 > flow->member_slot_watermark)
        flow->member_slot_watermark = (size_t)index + 1;
    flow->members[index].prev_inactive = flow->members[index].next_inactive = FLEXICAST_NO_SLOT;
    flow->members[index].stats.member_id = member_id;
    flow->members[index].loss_cursor = flow->next_packet_number;
    flow->members[index].cc_pending_cursor = flow->next_packet_number;
    flow->members[index].path_sample_floor = flow->first_packet_number;
    flow->members[index].active_since_pn = flow->next_packet_number;
    flow->members[index].suspended_at_pn = flow->next_packet_number;
    flow->members[index].excluded_packets = flow->next_packet_number - flow->first_packet_number;
    flow->members[index].retired_packets = 0;
    flow->members[index].active = 1;
    flexicast_member_map_set(&flow->member_map, member_id, (size_t)index);
    set_member_active(flow, (size_t)index, 1);
    ++flow->num_members;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_detach(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int member_index;
    uint64_t old_cursor;
    if (flow == NULL || member_id == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((member_index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_cc_on_member_removed(flow->cc, member_id, now);
    if (flow->members[member_index].active) {
        set_member_active(flow, (size_t)member_index, 0);
        --flow->num_members;
    } else {
        inactive_member_unlink(flow, (uint32_t)member_index);
    }
    old_cursor = flow->members[member_index].loss_cursor;
    flexicast_member_map_remove(&flow->member_map, member_id);
    clear_member_pending_slots(flow, (size_t)member_index, old_cursor);
    dispose_ecn_unreported(&flow->members[member_index].ecn_unreported_retired);
    lim_ring_dispose(&flow->members[member_index].limitations);
    memset(&flow->members[member_index], 0, sizeof(flow->members[member_index]));
    flow->members[member_index].prev_inactive = flow->members[member_index].next_inactive = FLEXICAST_NO_SLOT;
    flow->free_member_slots[flow->num_free_member_slots++] = (uint32_t)member_index;
    return QUICLY_FLEXICAST_OK;
}

size_t quicly_flexicast_num_members(const quicly_flexicast_flow_t *flow)
{
    return flow != NULL ? flow->num_members : 0;
}

int quicly_flexicast_get_member_stats(const quicly_flexicast_flow_t *flow, uint64_t member_id,
                                      quicly_flexicast_member_stats_t *stats)
{
    int member_index;
    if (flow == NULL || stats == NULL || (member_index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    *stats = flow->members[member_index].stats;
    return QUICLY_FLEXICAST_OK;
}

size_t quicly_flexicast_datagram_size(const quicly_flexicast_flow_t *flow, size_t payload_size)
{
    size_t size;
    if (flow == NULL || payload_size > QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE)
        return 0;
    size = 1 + flow->flow_id.len + QUICLY_SEND_PN_SIZE + quicly_datagram_frame_capacity(ptls_iovec_init(NULL, payload_size)) +
           flow->cipher_suite->aead->tag_size;
    return size <= flow->max_packet_size ? size : 0;
}

static void retire_inactive_slot_obligations(quicly_flexicast_flow_t *flow, quicly_flexicast_sent_t *sent)
{
    size_t word_limit = (flow->member_slot_watermark + 63) / 64;
    uint64_t *words = sent_member_words(flow, sent);
    for (size_t wi = 0; wi < word_limit && sent->pending_count != 0; ++wi) {
        uint64_t w = words[wi];
        while (w != 0) {
#if defined(__GNUC__) || defined(__clang__)
            unsigned bit_idx = (unsigned)__builtin_ctzll(w);
#else
            unsigned bit_idx = 0;
            uint64_t low = w & (~w + 1);
            while ((low >> bit_idx) > 1)
                ++bit_idx;
#endif
            w &= w - 1;
            size_t slot = wi * 64 + bit_idx;
            if (slot >= flow->member_slot_watermark)
                continue;
            quicly_flexicast_member_t *m = flow->members + slot;
            if (m->stats.member_id == 0 || !m->active || sent->packet_number < m->active_since_pn) {
                if (sent_clear_member(flow, sent, slot) && m->stats.member_id != 0) {
                    ++m->stats.lost_packets;
                    m->stats.lost_bytes += sent->packet_size;
                    record_ecn_unreported_retirement(m, sent->packet_number, sent->packet_number + 1);
                    if (m->loss_cursor <= sent->packet_number)
                        m->loss_cursor = sent->packet_number + 1;
                }
            }
        }
    }
}

int quicly_flexicast_send_datagram(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                   size_t *packet_size, uint64_t *packet_number, int64_t now)
{
    uint64_t pn;
    size_t required, payload_from, active_words;
    uint8_t *dst;
    quicly_flexicast_sent_t *sent;

    if (flow == NULL || packet == NULL || packet_size == NULL || packet_number == NULL ||
        (payload.len != 0 && payload.base == NULL) || payload.len > QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE ||
        flow->next_packet_number > PTLS_QUICINT_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures)
        return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
    if (flow->num_members == 0 || flow->sent == NULL)
        return QUICLY_FLEXICAST_ERROR_NO_MEMBERS;
    if (flow->crypto.encrypted_packets >= flow->crypto.max_packets_per_key)
        return QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED;
    required = quicly_flexicast_datagram_size(flow, payload.len);
    if (required == 0 || required > packet_capacity)
        return QUICLY_FLEXICAST_ERROR_INVALID;

    pn = flow->next_packet_number;
    flexicast_sent_block_t **block = &flow->sent[sent_block_index(pn)];
    if (*block == NULL && (*block = calloc(1, sent_block_size(flow->member_word_count))) == NULL)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    sent = &(*block)->packets[pn % FLEXICAST_SENT_BLOCK_SIZE];
    if (sent->pending_count != 0 && sent->packet_number != pn) {
        if (sent->checked_suspend_epoch != flow->suspend_epoch) {
            retire_inactive_slot_obligations(flow, sent);
            sent->checked_suspend_epoch = flow->suspend_epoch;
        }
        if (sent->pending_count != 0)
            return QUICLY_FLEXICAST_ERROR_SEND_WINDOW;
    }

    dst = packet;
    *dst++ = QUICLY_QUIC_BIT | (QUICLY_SEND_PN_SIZE - 1);
    memcpy(dst, flow->flow_id.bytes, flow->flow_id.len);
    dst += flow->flow_id.len;
    quicly_encode16(dst, (uint16_t)pn);
    dst += QUICLY_SEND_PN_SIZE;
    payload_from = (size_t)(dst - packet);
    dst = quicly_encode_datagram_frame(dst, payload);
    dst += flow->egress.aead->algo->tag_size;

    flow->crypto_engine->encrypt_packet(flow->crypto_engine, flow->crypto_conn, flow->egress.header_protection, flow->egress.aead,
                                        ptls_iovec_init(packet, (size_t)(dst - packet)), 0, payload_from, pn, 0);
    ++flow->crypto.encrypted_packets;

    active_words = (flow->member_slot_watermark + 63) / 64;
    sent->packet_number = pn;
    sent->checked_suspend_epoch = flow->suspend_epoch;
    memcpy(sent_member_words(flow, sent), flow->active_member_words, active_words * sizeof(*flow->active_member_words));
    sent->pending_count = flow->num_members;
    sent->packet_size = (size_t)(dst - packet);
    sent->sent_at = now;
    sent->context = (quicly_flexicast_send_context_t){0};
    sent->has_submission = 0;
    sent->rtt_untracked = 0;
    ++flow->next_packet_number;
    quicly_flexicast_cc_on_packet_sent(flow->cc, pn, (size_t)(dst - packet), now);
    *packet_size = (size_t)(dst - packet);
    *packet_number = pn;
    return QUICLY_FLEXICAST_OK;
}

static int same_send_context(const quicly_flexicast_send_context_t *a, const quicly_flexicast_send_context_t *b)
{
    return a->pacing_rate_bytes_per_second == b->pacing_rate_bytes_per_second && a->physical_fanout == b->physical_fanout &&
           a->flags == b->flags;
}

static int64_t member_lim_retention_floor(quicly_flexicast_flow_t *flow, size_t member_index, int64_t now)
{
    quicly_flexicast_member_t *member = flow->members + member_index;
    int64_t floor_at = now;
    if (member->rate_sample.acked_at_end != 0 && member->rate_sample.sent_at_start > 0 &&
        member->rate_sample.sent_at_start < floor_at)
        floor_at = member->rate_sample.sent_at_start;
    if (member_pending_packets(flow, member) <= 1)
        return floor_at;
    uint64_t cursor = member->cc_pending_cursor;
    uint64_t win_start = sent_window_start(flow);
    if (win_start < member->path_sample_floor)
        win_start = member->path_sample_floor;
    if (cursor < win_start)
        cursor = win_start;
    while (cursor < flow->next_packet_number) {
        const quicly_flexicast_sent_t *s = get_sent(flow, cursor);
        if (s != NULL && s->pending_count != 0 && s->packet_number == cursor && sent_has_member(flow, s, member_index)) {
            member->cc_pending_cursor = cursor;
            flexicast_submission_t *sub = find_submission(flow, cursor, member_index);
            int64_t s_at = sub != NULL ? sub->submitted_at : s->rtt_untracked ? 0 : s->sent_at;
            if (s_at <= 0)
                return 0;
            return s_at < floor_at ? s_at : floor_at;
        }
        ++cursor;
    }
    return floor_at;
}

int quicly_flexicast_mark_submitted(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int64_t now,
                                    const quicly_flexicast_send_context_t *context)
{
    if (flow == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (flow->sent == NULL)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_sent_t *sent = get_sent(flow, packet_number);
    if (sent == NULL || sent->pending_count == 0 || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    int member_index = member_id != 0 ? find_member(flow, member_id) : -1;
    if (member_id != 0 && (member_index < 0 || !sent_has_member(flow, sent, (size_t)member_index)))
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_send_context_t normalized = context != NULL ? *context : (quicly_flexicast_send_context_t){0};
    uint32_t lim_flags = normalized.flags & (QUICLY_FLEXICAST_SAMPLE_APP_LIMITED | QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED);
    if (normalized.pacing_rate_bytes_per_second == 0 || normalized.physical_fanout == 0 || now <= 0)
        normalized.flags &= ~QUICLY_FLEXICAST_SAMPLE_VALID;
    if (member_id == 0 || !sent->has_submission) {
        /* store the first submission in place; only differing replicas use sparse storage */
        sent->sent_at = now;
        sent->context = normalized;
        sent->has_submission = 1;
        sent->rtt_untracked = now <= 0;
    } else {
        if ((now != sent->sent_at || !same_send_context(&normalized, &sent->context) ||
             find_submission(flow, packet_number, (size_t)member_index) != NULL) &&
            !save_submission(flow, packet_number, (size_t)member_index, now, &normalized))
            sent->rtt_untracked = 1;
    }
    /* record limitation spans and latch directly onto any overlapping open sample */
    if (lim_flags != 0 && now > 0) {
        if (member_index >= 0) {
            flexicast_delivery_sample_t *bucket = &flow->members[member_index].rate_sample;
            if (bucket->bytes != 0 && bucket->timestamps_valid && now >= bucket->sent_at_start && now <= bucket->sent_at_end)
                bucket->context.flags |= lim_flags;
            int64_t floor_at = member_lim_retention_floor(flow, (size_t)member_index, now);
            lim_ring_record(&flow->members[member_index].limitations, packet_number, now, lim_flags, floor_at);
        } else {
            lim_ring_record(&flow->limitations, packet_number, now, lim_flags, 0);
        }
    }
    if (member_id == 0) {
        quicly_flexicast_cc_on_member_pending_updated(flow->cc, 0, now > 0, packet_number, now > 0 ? now : 0, now);
    } else {
        uint64_t min_cur = flow->members[member_index].cc_pending_cursor;
        uint64_t win_start = sent_window_start(flow);
        if (min_cur < win_start)
            min_cur = win_start;
        if (min_cur < flow->members[member_index].path_sample_floor)
            min_cur = flow->members[member_index].path_sample_floor;
        if (packet_number == min_cur)
            sync_member_cc_pending(flow, (size_t)member_index, now);
    }
    return QUICLY_FLEXICAST_OK;
}

static int decode_header(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, uint64_t *packet_number,
                         size_t *payload_from)
{
    size_t pn_offset = 1 + flow->flow_id.len, pn_length, i, plaintext_size;
    uint8_t mask[5] = {0};
    uint32_t truncated = 0;
    uint64_t expected;

    if (flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures)
        return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
    if (packet_size > QUICLY_FLEXICAST_MAX_PACKET_SIZE ||
        packet_size < pn_offset + QUICLY_MAX_PN_SIZE + flow->ingress.header_protection->algo->iv_size ||
        (packet[0] & (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT)) != QUICLY_QUIC_BIT)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (memcmp(packet + 1, flow->flow_id.bytes, flow->flow_id.len) != 0)
        return QUICLY_FLEXICAST_ERROR_WRONG_FLOW;
    if (flow->crypto.decryption_attempts >= flow->crypto.max_decryption_attempts)
        return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;

    ptls_cipher_init(flow->ingress.header_protection, packet + pn_offset + QUICLY_MAX_PN_SIZE);
    ptls_cipher_encrypt(flow->ingress.header_protection, mask, mask, sizeof(mask));
    packet[0] ^= mask[0] & 0x1f;
    pn_length = (packet[0] & 0x3) + 1;
    for (i = 0; i != pn_length; ++i) {
        packet[pn_offset + i] ^= mask[i + 1];
        truncated = (truncated << 8) | packet[pn_offset + i];
    }
    expected = flow->received.initialized ? flow->received.largest + 1 : flow->first_packet_number;
    if (expected < flow->received.bootstrap_floor)
        expected = flow->received.bootstrap_floor;
    *packet_number = quicly_determine_packet_number(truncated, pn_length * 8, expected);
    if (*packet_number > PTLS_QUICINT_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    *payload_from = pn_offset + pn_length;
    ++flow->crypto.decryption_attempts;
    plaintext_size = ptls_aead_decrypt(flow->ingress.aead, packet + *payload_from, packet + *payload_from,
                                       packet_size - *payload_from, *packet_number, packet, *payload_from);
    if (plaintext_size == SIZE_MAX) {
        if (++flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures ||
            flow->crypto.decryption_attempts >= flow->crypto.max_decryption_attempts)
            return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
        return QUICLY_FLEXICAST_ERROR_CRYPTO;
    }
    /* check authenticated reserved header bits */
    if ((packet[0] & 0x18) != 0)
        return QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION;
    return (int)plaintext_size;
}

static int is_replayed_packet(const quicly_flexicast_flow_t *flow, uint64_t packet_number)
{
    if (!flow->received.initialized || packet_number > flow->received.largest)
        return 0;
    uint64_t distance = flow->received.largest - packet_number;
    return distance >= QUICLY_FLEXICAST_REPLAY_WINDOW || (flow->received.mask & (UINT64_C(1) << distance)) != 0;
}

static void update_replay_window(quicly_flexicast_flow_t *flow, uint64_t packet_number)
{
    uint64_t distance;
    if (!flow->received.initialized) {
        flow->received.initialized = 1;
        flow->received.largest = packet_number;
        flow->received.mask = 1;
        return;
    }
    if (packet_number > flow->received.largest) {
        distance = packet_number - flow->received.largest;
        flow->received.mask = distance >= QUICLY_FLEXICAST_REPLAY_WINDOW ? 1 : (flow->received.mask << distance) | 1;
        flow->received.largest = packet_number;
        return;
    }
    distance = flow->received.largest - packet_number;
    flow->received.mask |= (uint64_t)1 << distance;
}

static int decode_next_multicast_frame(const uint8_t **src, const uint8_t *end, ptls_iovec_t *payload, int *is_datagram,
                                       int *ack_eliciting)
{
    uint64_t frame_type;
    quicly_datagram_frame_t frame;

    *is_datagram = 0;
    if ((frame_type = quicly_decodev(src, end)) == UINT64_MAX)
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    switch (frame_type) {
    case QUICLY_FRAME_TYPE_PADDING:
        return QUICLY_FLEXICAST_OK;
    case QUICLY_FRAME_TYPE_PING:
        *ack_eliciting = 1;
        return QUICLY_FLEXICAST_OK;
    case QUICLY_FRAME_TYPE_DATAGRAM_NOLEN:
    case QUICLY_FRAME_TYPE_DATAGRAM_WITHLEN:
        if (quicly_decode_datagram_frame(frame_type, src, end, &frame) != 0)
            return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
        *payload = frame.payload;
        *is_datagram = 1;
        *ack_eliciting = 1;
        return QUICLY_FLEXICAST_OK;
    case QUICLY_FRAME_TYPE_FC_ANNOUNCE:
    case QUICLY_FRAME_TYPE_FC_STATE:
    case QUICLY_FRAME_TYPE_FC_KEY:
    case QUICLY_FRAME_TYPE_PATH_ACK:
    case QUICLY_FRAME_TYPE_PATH_ACK_ECN:
    case QUICLY_FRAME_TYPE_ACK:
    case QUICLY_FRAME_TYPE_ACK_ECN:
        return QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION;
    default:
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    }
}

/* validate packet frames before exposing payloads or committing receive state */
static int decode_datagrams(const uint8_t *src, const uint8_t *end, ptls_iovec_t *payloads, size_t capacity, size_t *count,
                            int *ack_eliciting)
{
    ptls_iovec_t payload;
    int ret, is_datagram;

    *count = 0;
    *ack_eliciting = 0;
    if (src == end)
        return QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION;
    while (src != end) {
        if ((ret = decode_next_multicast_frame(&src, end, &payload, &is_datagram, ack_eliciting)) != QUICLY_FLEXICAST_OK)
            return ret;
        if (is_datagram) {
            if (*count < capacity)
                payloads[*count] = payload;
            ++*count;
        }
    }
    return QUICLY_FLEXICAST_OK;
}

static int decrypt_and_check_replay(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, uint64_t *packet_number,
                                    const uint8_t **src, const uint8_t **end)
{
    size_t payload_from;
    int plaintext_size = decode_header(flow, packet, packet_size, packet_number, &payload_from);
    if (plaintext_size < 0)
        return plaintext_size;
    /* filter replays after authenticating packet numbers */
    if (*packet_number < flow->first_packet_number || *packet_number < flow->received.bootstrap_floor ||
        is_replayed_packet(flow, *packet_number))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    *src = packet + payload_from;
    *end = *src + plaintext_size;
    return QUICLY_FLEXICAST_OK;
}

static int commit_received_packet(quicly_flexicast_flow_t *flow, uint64_t packet_number, int ack_eliciting, uint8_t ecn,
                                  int64_t now)
{
    int is_pending_largest = flow->received.ack_ranges.num_ranges == 0 ||
                             packet_number >= flow->received.ack_ranges.ranges[flow->received.ack_ranges.num_ranges - 1].end;
    size_t previous_num_ranges = flow->received.ack_ranges.num_ranges;
    if (quicly_ranges_add(&flow->received.ack_ranges, packet_number, packet_number + 1) != 0)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    if (flow->received.ack_ranges.num_ranges > previous_num_ranges && flow->received.ack_ranges_since_ack < QUICLY_MAX_ACK_BLOCKS)
        ++flow->received.ack_ranges_since_ack;
    /* bound receive history to the newest ranges */
    if (flow->received.ack_ranges.num_ranges > QUICLY_FLEXICAST_SENT_WINDOW) {
        quicly_ranges_drop_by_range_indices(&flow->received.ack_ranges, 0,
                                            flow->received.ack_ranges.num_ranges - QUICLY_FLEXICAST_SENT_WINDOW);
        flow->received.history_lower_bound = flow->received.ack_ranges.ranges[0].start;
    }
    /* update replay window only after ACK range allocation succeeds */
    update_replay_window(flow, packet_number);
    if (is_pending_largest)
        flow->received.largest_received_at = now;
    if ((ecn &= 3) != 0) {
        size_t index = ecn == 2 ? 0 : ecn == 1 ? 1 : 2;
        if (flow->received.ecn_counts[index] < PTLS_QUICINT_MAX)
            ++flow->received.ecn_counts[index];
    }
    if (ack_eliciting && flow->received.ack_eliciting_since_ack++ == 0)
        flow->received.ack_pending_since = now;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_receive_packet(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size,
                                    quicly_flexicast_decrypted_t *decrypted, uint8_t ecn, int64_t now)
{
    const uint8_t *src, *end;
    uint64_t pn;
    size_t count;
    int ret, ack_eliciting;

    if (flow == NULL || packet == NULL || decrypted == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((ret = decrypt_and_check_replay(flow, packet, packet_size, &pn, &src, &end)) != 0)
        return ret;
    if ((ret = decode_datagrams(src, end, NULL, 0, &count, &ack_eliciting)) != 0)
        return ret;
    if ((ret = commit_received_packet(flow, pn, ack_eliciting, ecn, now)) != 0)
        return ret;
    *decrypted = (quicly_flexicast_decrypted_t){.src = src, .end = end, .packet_number = pn, .num_datagrams = count};
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_next_datagram(quicly_flexicast_decrypted_t *decrypted, ptls_iovec_t *payload)
{
    int ret, is_datagram, ack_eliciting = 0;

    if (decrypted == NULL || payload == NULL || (decrypted->src == NULL && decrypted->end != NULL) ||
        decrypted->src > decrypted->end)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    const uint8_t *src = decrypted->src, *end = decrypted->end;
    while (src != end) {
        if ((ret = decode_next_multicast_frame(&src, end, payload, &is_datagram, &ack_eliciting)) != QUICLY_FLEXICAST_OK)
            return ret;
        if (is_datagram) {
            decrypted->src = src;
            if (decrypted->num_datagrams != 0)
                --decrypted->num_datagrams;
            return 1;
        }
    }
    decrypted->src = src;
    *payload = ptls_iovec_init(NULL, 0);
    return 0;
}

int quicly_flexicast_receive_datagrams(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payloads,
                                       size_t *num_payloads, uint64_t *packet_number, uint8_t ecn, int64_t now)
{
    const uint8_t *src, *end;
    size_t count, capacity;
    int ret, ack_eliciting;
    ptls_iovec_t single_payload;

    if (flow == NULL || packet == NULL || num_payloads == NULL || packet_number == NULL || (payloads == NULL && *num_payloads != 0))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((ret = decrypt_and_check_replay(flow, packet, packet_size, packet_number, &src, &end)) != 0)
        return ret;

    capacity = *num_payloads;
    if (capacity <= 1) {
        if ((ret = decode_datagrams(src, end, &single_payload, capacity, &count, &ack_eliciting)) != 0)
            return ret;
        *num_payloads = count;
        if (count > capacity)
            return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
        if (count == 1)
            payloads[0] = single_payload;
    } else {
        ptls_iovec_t scratch_payloads[64];
        if ((ret = decode_datagrams(src, end, scratch_payloads, PTLS_ELEMENTSOF(scratch_payloads), &count, &ack_eliciting)) != 0)
            return ret;
        *num_payloads = count;
        if (count > capacity)
            return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
        if (count <= PTLS_ELEMENTSOF(scratch_payloads)) {
            if (count != 0)
                memcpy(payloads, scratch_payloads, count * sizeof(*payloads));
        } else {
            (void)decode_datagrams(src, end, payloads, capacity, &count, &ack_eliciting);
        }
    }
    return commit_received_packet(flow, *packet_number, ack_eliciting, ecn, now);
}

int quicly_flexicast_set_ack_delay(quicly_flexicast_flow_t *flow, uint64_t ack_delay_msec)
{
    if (flow == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    flow->received.ack_delay_msec = ack_delay_msec > UINT32_MAX ? UINT32_MAX : (uint32_t)ack_delay_msec;
    return QUICLY_FLEXICAST_OK;
}

int64_t quicly_flexicast_get_ack_deadline(const quicly_flexicast_flow_t *flow)
{
    if (flow == NULL || flow->received.ack_ranges.num_ranges == 0 || flow->received.ack_eliciting_since_ack == 0)
        return INT64_MAX;
    if (flow->received.ack_frames_sent == 0 || flow->received.ack_eliciting_since_ack >= flow->received.ack_frequency ||
        flow->received.ack_ranges_since_ack >= QUICLY_MAX_ACK_BLOCKS)
        return flow->received.ack_pending_since;
    if (flow->received.ack_pending_since > INT64_MAX - (int64_t)flow->received.ack_delay_msec)
        return INT64_MAX;
    return flow->received.ack_pending_since + (int64_t)flow->received.ack_delay_msec;
}

int quicly_flexicast_ack_is_due(const quicly_flexicast_flow_t *flow, int64_t now)
{
    int64_t deadline = quicly_flexicast_get_ack_deadline(flow);
    if (deadline == INT64_MAX)
        return 0;
    if (flow->received.ack_frames_sent == 0 || flow->received.ack_eliciting_since_ack >= flow->received.ack_frequency ||
        flow->received.ack_ranges_since_ack >= QUICLY_MAX_ACK_BLOCKS)
        return 1;
    return now >= deadline;
}

int quicly_flexicast_encode_pending_ack(quicly_flexicast_flow_t *flow, uint64_t ack_path_id, uint8_t *dst, size_t capacity,
                                        int64_t now, size_t *encoded_size)
{
    uint8_t *end;
    uint64_t ack_delay = 0;
    quicly_ranges_t ranges;
    if (flow == NULL || ack_path_id == 0 || ack_path_id > PTLS_QUICINT_MAX || dst == NULL || encoded_size == NULL ||
        flow->received.ack_ranges.num_ranges == 0 || capacity < 2)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    ranges = flow->received.ack_ranges;
    /* prioritize recent packets when ranges exceed the block limit */
    if (ranges.num_ranges > QUICLY_MAX_ACK_BLOCKS) {
        ranges.ranges += ranges.num_ranges - QUICLY_MAX_ACK_BLOCKS;
        ranges.num_ranges = QUICLY_MAX_ACK_BLOCKS;
    }
    if (now > flow->received.largest_received_at)
        ack_delay = (uint64_t)now - (uint64_t)flow->received.largest_received_at;
    /* scale ACK delay using the local ACK delay exponent */
    const uint64_t units_per_msec = 1000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT;
    ack_delay = ack_delay > PTLS_QUICINT_MAX / units_per_msec ? PTLS_QUICINT_MAX : ack_delay * units_per_msec;
    if ((end = quicly_encode_path_ack_frame(dst, dst + capacity - 1, ack_path_id, &ranges, flow->received.ecn_counts, ack_delay)) ==
        NULL)
        return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
    *end++ = QUICLY_FRAME_TYPE_PING;
    *encoded_size = (size_t)(end - dst);
    return QUICLY_FLEXICAST_OK;
}

void quicly_flexicast_ack_sent(quicly_flexicast_flow_t *flow)
{
    if (flow == NULL)
        return;
    ++flow->received.ack_frames_sent;
    /* retain only the newest ACK blocks */
    if (flow->received.ack_ranges.num_ranges > QUICLY_MAX_ACK_BLOCKS) {
        quicly_ranges_drop_by_range_indices(&flow->received.ack_ranges, 0,
                                            flow->received.ack_ranges.num_ranges - QUICLY_MAX_ACK_BLOCKS);
        flow->received.history_lower_bound = flow->received.ack_ranges.ranges[0].start;
    }
    flow->received.ack_eliciting_since_ack = 0;
    flow->received.ack_ranges_since_ack = 0;
    flow->received.ack_pending_since = 0;
}

int quicly_flexicast_send_pending_ack(quicly_flexicast_flow_t *flow, quicly_conn_t *conn, int64_t now, int force)
{
    uint64_t ack_delay_msec = 0;
    quicly_error_t err;

    if (flow == NULL || conn == NULL)
        return QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION;
    if (quicly_flexicast_get_ack_deadline(flow) == INT64_MAX || (!force && !quicly_flexicast_ack_is_due(flow, now)))
        return QUICLY_FLEXICAST_OK;
    if (now > flow->received.largest_received_at)
        ack_delay_msec = (uint64_t)now - (uint64_t)flow->received.largest_received_at;
    err = quicly_flexicast_send_path_ack(conn, &flow->flow_id, &flow->received.ack_ranges, flow->received.ecn_counts,
                                         ack_delay_msec, now);
    if (err != 0) {
        if (err == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION)
            return QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION;
        if (err == QUICLY_ERROR_STATE_EXHAUSTION)
            return QUICLY_FLEXICAST_ERROR_SEND_WINDOW;
        if (err == PTLS_ERROR_NO_MEMORY)
            return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
        return QUICLY_FLEXICAST_ERROR_INVALID;
    }
    quicly_flexicast_ack_sent(flow);
    return QUICLY_FLEXICAST_OK;
}

static uint32_t clamp_msec(uint64_t value)
{
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
}

static void update_rtt(quicly_flexicast_member_t *member, int64_t submitted_at, int64_t now, uint32_t ack_delay_msec)
{
    quicly_flexicast_member_stats_t *stats = &member->stats;
    uint32_t sample;
    if (now <= 0 || submitted_at <= 0 || now < submitted_at)
        return;
    sample = clamp_msec((uint64_t)(now - submitted_at));
    ++member->rtt_sample_epoch;
    member->rtt_sample_at = now;
    member->raw_rtt_msec = sample;
    member->rtt_ack_delay_msec = ack_delay_msec;
    member->applied_ack_delay_msec = 0;
    member->rtt_sample_flags = QUICLY_FLEXICAST_RTT_VALID;
    member->has_rtt_sample = 1;
    if (stats->minimum_rtt_msec == 0 || sample < stats->minimum_rtt_msec)
        stats->minimum_rtt_msec = sample;
    if ((uint64_t)sample >= (uint64_t)stats->minimum_rtt_msec + ack_delay_msec) {
        sample -= ack_delay_msec;
        member->applied_ack_delay_msec = ack_delay_msec;
    } else if (ack_delay_msec != 0) {
        member->rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
    }
    stats->latest_rtt_msec = sample;
    if (stats->smoothed_rtt_msec == 0)
        stats->smoothed_rtt_msec = sample;
    else
        stats->smoothed_rtt_msec = (uint32_t)(((uint64_t)stats->smoothed_rtt_msec * 7 + sample) / 8);
}

static void merge_send_context(quicly_flexicast_send_context_t *dst, const quicly_flexicast_send_context_t *src, int first)
{
    if (first) {
        *dst = *src;
        return;
    }
    uint32_t flags = dst->flags | src->flags;
    if (!(dst->flags & QUICLY_FLEXICAST_SAMPLE_VALID) || !(src->flags & QUICLY_FLEXICAST_SAMPLE_VALID))
        flags &= ~QUICLY_FLEXICAST_SAMPLE_VALID;
    if (dst->pacing_rate_bytes_per_second != src->pacing_rate_bytes_per_second || dst->physical_fanout != src->physical_fanout)
        flags = (flags | QUICLY_FLEXICAST_SAMPLE_MIXED) & ~QUICLY_FLEXICAST_SAMPLE_VALID;
    dst->flags = flags;
}

static int acknowledge_packet(quicly_flexicast_flow_t *flow, int member_index, uint64_t packet_number, int64_t now,
                              quicly_flexicast_feedback_t *feedback, flexicast_delivery_sample_t *observation,
                              size_t *num_completed, unsigned flags, size_t *total_acked)
{
    quicly_flexicast_sent_t *sent = get_sent(flow, packet_number);
    quicly_flexicast_member_t *member = flow->members + member_index;
    quicly_flexicast_member_stats_t *stats = &member->stats;

    if (sent == NULL || sent->pending_count == 0 || sent->packet_number != packet_number ||
        !sent_has_member(flow, sent, (size_t)member_index))
        return 0;
    if (packet_number >= member->path_sample_floor) {
        flexicast_submission_t *submission = find_submission(flow, packet_number, (size_t)member_index);
        int64_t submitted_at = submission != NULL ? submission->submitted_at : sent->rtt_untracked ? 0 : sent->sent_at;
        quicly_flexicast_send_context_t context = submission != NULL ? submission->context : sent->context;
        int timestamp_valid = submitted_at > 0 && now >= submitted_at;
        if (!timestamp_valid)
            context.flags &= ~QUICLY_FLEXICAST_SAMPLE_VALID;
        merge_send_context(&observation->context, &context, observation->bytes == 0);
        observation->timestamps_valid =
            observation->bytes == 0 ? timestamp_valid : observation->timestamps_valid && timestamp_valid;
        if (observation->bytes == 0 || submitted_at < observation->sent_at_start)
            observation->sent_at_start = submitted_at;
        if (submitted_at > observation->sent_at_end)
            observation->sent_at_end = submitted_at;
        observation->bytes += sent->packet_size;
        /* exclude pre-reset packets from current-route CC ACK counts */
        ++feedback->acked_packets;
        feedback->acked_bytes += sent->packet_size;
        /* update RTT only for the frame's largest PN */
        if (packet_number == feedback->largest_acknowledged && !(flags & QUICLY_FLEXICAST_ACK_OMIT_RTT))
            update_rtt(member, submitted_at, now, feedback->ack_delay_msec);
    }
    (void)sent_clear_member(flow, sent, (size_t)member_index);
    ++*total_acked;
    ++stats->delivered_packets;
    stats->delivered_bytes += sent->packet_size;
    if (sent->pending_count == 0)
        ++*num_completed;
    return 1;
}

static void latch_bucket_limitations(const quicly_flexicast_flow_t *flow, const quicly_flexicast_member_t *member,
                                     flexicast_delivery_sample_t *bucket)
{
    if (bucket->bytes != 0 && bucket->timestamps_valid && bucket->sent_at_start > 0 &&
        bucket->sent_at_end >= bucket->sent_at_start) {
        bucket->context.flags =
            lim_ring_query(&flow->limitations, bucket->sent_at_start, bucket->sent_at_end, bucket->context.flags);
        bucket->context.flags =
            lim_ring_query(&member->limitations, bucket->sent_at_start, bucket->sent_at_end, bucket->context.flags);
    }
}

static void sample_delivery_rate(quicly_flexicast_flow_t *flow, quicly_flexicast_member_t *member,
                                 const flexicast_delivery_sample_t *observation, int64_t now)
{
    flexicast_delivery_sample_t *bucket = &member->rate_sample;
    if (observation->bytes == 0 || now <= 0)
        return;
    if (bucket->acked_at_end == 0 || now < bucket->acked_at_end) {
        /* use the first ACK to establish the clock without counting its bytes */
        int64_t sent_at = observation->timestamps_valid ? observation->sent_at_end : 0;
        *bucket = (flexicast_delivery_sample_t){.acked_at_start = now,
                                                .acked_at_end = now,
                                                .sent_at_start = sent_at,
                                                .sent_at_end = sent_at,
                                                .timestamps_valid = observation->timestamps_valid,
                                                .end_timestamp_valid = observation->timestamps_valid};
        return;
    }
    if (now > bucket->acked_at_end) {
        /* publish only completed receive-time buckets */
        uint64_t elapsed = (uint64_t)(bucket->acked_at_end - bucket->acked_at_start);
        if (elapsed != 0 && bucket->bytes != 0) {
            if (!bucket->timestamps_valid || bucket->sent_at_start <= 0 || bucket->sent_at_end < bucket->sent_at_start) {
                bucket->context.flags &= ~QUICLY_FLEXICAST_SAMPLE_VALID;
            } else if ((uint64_t)(bucket->sent_at_end - bucket->sent_at_start) > elapsed) {
                /* clamp elapsed interval to actual send interval against ACK compression */
                elapsed = (uint64_t)(bucket->sent_at_end - bucket->sent_at_start);
            }
            uint64_t bytes = bucket->bytes;
            uint64_t sample = bytes > UINT64_MAX / 1000 ? UINT64_MAX : bytes * 1000 / elapsed;
            bucket->rate = sample;
            latch_bucket_limitations(flow, member, bucket);
            member->published_rate_sample = *bucket;
            quicly_flexicast_member_stats_t *stats = &member->stats;
            if (stats->delivery_rate_bytes_per_second == 0)
                stats->delivery_rate_bytes_per_second = sample;
            else
                stats->delivery_rate_bytes_per_second =
                    stats->delivery_rate_bytes_per_second - stats->delivery_rate_bytes_per_second / 8 + sample / 8;
            ++member->rate_sample_epoch;
        }
        /* advance to the next interval boundary */
        int64_t sent_at = bucket->end_timestamp_valid ? bucket->sent_at_end : 0;
        *bucket = (flexicast_delivery_sample_t){.acked_at_start = bucket->acked_at_end,
                                                .acked_at_end = now,
                                                .sent_at_start = sent_at,
                                                .timestamps_valid = sent_at > 0,
                                                .end_timestamp_valid = 1};
        if (member->limitations.ext_entries != NULL && sent_at > 0 && member_pending_packets(flow, member) == 0)
            lim_ring_prune(&member->limitations, sent_at);
    }
    merge_send_context(&bucket->context, &observation->context, bucket->bytes == 0);
    bucket->timestamps_valid = bucket->timestamps_valid && observation->timestamps_valid;
    bucket->end_timestamp_valid = bucket->end_timestamp_valid && observation->timestamps_valid;
    /* include send time of reordered older packets */
    if (observation->sent_at_start > 0 && observation->sent_at_start < bucket->sent_at_start)
        bucket->sent_at_start = observation->sent_at_start;
    if (observation->sent_at_end > bucket->sent_at_end)
        bucket->sent_at_end = observation->sent_at_end;
    bucket->bytes = UINT64_MAX - bucket->bytes < observation->bytes ? UINT64_MAX : bucket->bytes + observation->bytes;
    latch_bucket_limitations(flow, member, bucket);
}

static void finish_feedback(quicly_flexicast_flow_t *flow, int member_index, quicly_flexicast_feedback_t *feedback,
                            const flexicast_delivery_sample_t *observation, unsigned flags, int has_member_event)
{
    quicly_flexicast_member_t *member = flow->members + member_index;
    quicly_flexicast_member_stats_t *stats = &member->stats;
    int has_route_event = feedback->acked_packets != 0 || feedback->lost_packets != 0 || feedback->ecn_ce_count != 0;
    if (!has_member_event && !has_route_event)
        return;
    if (flags & QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE) {
        if (observation->bytes != 0)
            member->rate_sample = (flexicast_delivery_sample_t){0};
    } else {
        sample_delivery_rate(flow, member, observation, feedback->now);
    }
    if (feedback->now > 0)
        stats->last_feedback_at = feedback->now;
    feedback->epoch = ++stats->feedback_epoch;
    if (!has_route_event) {
        sync_member_cc_pending(flow, (size_t)member_index, feedback->now);
        return;
    }
    feedback->delivered_bytes = stats->delivered_bytes;
    /* publish sample epoch only for completed buckets on the current path */
    int has_rate_sample = !(flags & QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE) && member->published_rate_sample.acked_at_end != 0;
    const flexicast_delivery_sample_t no_sample = {0};
    const flexicast_delivery_sample_t *sample = has_rate_sample ? &member->published_rate_sample : &no_sample;
    feedback->delivery_rate_sample_epoch = has_rate_sample ? member->rate_sample_epoch : 0;
    feedback->delivery_rate_bytes_per_second = sample->rate;
    feedback->delivery_sample_flags = sample->context.flags;
    feedback->delivery_sample_fanout = sample->context.physical_fanout;
    feedback->delivery_sample_pacing_rate_bytes_per_second = sample->context.pacing_rate_bytes_per_second;
    feedback->delivery_sample_bytes = sample->bytes;
    feedback->delivery_sample_sent_at_start = sample->sent_at_start;
    feedback->delivery_sample_sent_at_end = sample->sent_at_end;
    feedback->delivery_sample_acked_at_start = sample->acked_at_start;
    feedback->delivery_sample_acked_at_end = sample->acked_at_end;
    if ((flags & QUICLY_FLEXICAST_ACK_OMIT_RTT) || !member->has_rtt_sample) {
        feedback->latest_rtt_msec = feedback->minimum_rtt_msec = feedback->smoothed_rtt_msec = 0;
        feedback->rtt_sample_epoch = feedback->rtt_sample_at = 0;
        feedback->raw_rtt_msec = feedback->rtt_ack_delay_msec = feedback->applied_ack_delay_msec = 0;
        feedback->rtt_sample_flags = 0;
    } else {
        feedback->latest_rtt_msec = stats->latest_rtt_msec;
        feedback->minimum_rtt_msec = stats->minimum_rtt_msec;
        feedback->smoothed_rtt_msec = stats->smoothed_rtt_msec;
        feedback->rtt_sample_epoch = member->rtt_sample_epoch;
        feedback->rtt_sample_at = member->rtt_sample_at;
        feedback->raw_rtt_msec = member->raw_rtt_msec;
        feedback->rtt_ack_delay_msec = member->rtt_ack_delay_msec;
        feedback->applied_ack_delay_msec = member->applied_ack_delay_msec;
        feedback->rtt_sample_flags = member->rtt_sample_flags;
    }
    if (member->active && flow->cc != NULL) {
        int has_pending;
        uint64_t oldest_pn;
        int64_t oldest_sent_at;
        compute_member_cc_pending(flow, (size_t)member_index, &has_pending, &oldest_pn, &oldest_sent_at);
        feedback->pending_valid = 1;
        feedback->has_pending = (uint8_t)has_pending;
        feedback->oldest_pending_pn = oldest_pn;
        feedback->oldest_pending_sent_at = oldest_sent_at;
        quicly_flexicast_cc_on_feedback(flow->cc, feedback);
    }
}

static size_t retire_loss_range(quicly_flexicast_flow_t *flow, int member_index, uint64_t start_pn, uint64_t end_pn,
                                quicly_flexicast_feedback_t *feedback, size_t *num_completed)
{
    size_t retired = 0;
    for (uint64_t packet_number = start_pn;; ++packet_number) {
        quicly_flexicast_sent_t *sent = get_sent(flow, packet_number);
        if (sent != NULL && sent->pending_count != 0 && sent->packet_number == packet_number &&
            sent_clear_member(flow, sent, (size_t)member_index)) {
            ++retired;
            ++flow->members[member_index].stats.lost_packets;
            flow->members[member_index].stats.lost_bytes += sent->packet_size;
            record_ecn_unreported_retirement(&flow->members[member_index], packet_number, packet_number + 1);
            if (packet_number >= flow->members[member_index].path_sample_floor) {
                ++feedback->lost_packets;
                feedback->lost_bytes += sent->packet_size;
            }
            if (sent->pending_count == 0)
                ++*num_completed;
        }
        if (packet_number == end_pn)
            break;
    }
    return retired;
}

static size_t retire_lost_packets(quicly_flexicast_flow_t *flow, int member_index, uint64_t largest_acknowledged,
                                  quicly_flexicast_feedback_t *feedback, size_t *num_completed)
{
    uint64_t threshold = flow->packet_reordering_threshold;
    uint64_t last_lost, cursor, window_start;
    size_t retired;

    if (largest_acknowledged < threshold)
        return 0;
    last_lost = largest_acknowledged - threshold;
    cursor = flow->members[member_index].loss_cursor;
    window_start = sent_window_start(flow);
    if (cursor < window_start)
        cursor = window_start;
    if (cursor > last_lost)
        return 0;
    retired = retire_loss_range(flow, member_index, cursor, last_lost, feedback, num_completed);
    flow->members[member_index].loss_cursor = last_lost + 1;
    return retired;
}

int quicly_flexicast_ack_packet(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete,
                                int64_t now)
{
    quicly_flexicast_feedback_t feedback = {.member_id = member_id, .largest_acknowledged = packet_number, .now = now};
    flexicast_delivery_sample_t observation = {0};
    int member_index;
    size_t num_completed = 0, total_acked = 0, retired_lost;
    quicly_flexicast_sent_t *sent;

    if (flow == NULL || complete == NULL || flow->sent == NULL || (member_index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    sent = get_sent(flow, packet_number);
    if (sent == NULL || sent->pending_count == 0 || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!sent_has_member(flow, sent, (size_t)member_index))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    unsigned flags = packet_number < flow->members[member_index].path_sample_floor
                         ? QUICLY_FLEXICAST_ACK_OMIT_RTT | QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE
                         : 0;
    (void)acknowledge_packet(flow, member_index, packet_number, now, &feedback, &observation, &num_completed, flags, &total_acked);
    if (total_acked != 0)
        record_ecn_unreported_retirement(&flow->members[member_index], packet_number, packet_number + 1);
    *complete = num_completed != 0;
    retired_lost = retire_lost_packets(flow, member_index, packet_number, &feedback, &num_completed);
    if (packet_number > flow->members[member_index].stats.largest_acknowledged)
        flow->members[member_index].stats.largest_acknowledged = packet_number;
    finish_feedback(flow, member_index, &feedback, &observation, flags, total_acked != 0 || retired_lost != 0);
    return QUICLY_FLEXICAST_OK;
}

static int validate_ack_frame(const quicly_ack_frame_t *frame)
{
    uint64_t largest;
    if (frame == NULL || frame->num_gaps > QUICLY_ACK_MAX_GAPS)
        return 0;
    largest = frame->largest_acknowledged;
    for (uint64_t i = 0; i <= frame->num_gaps; ++i) {
        uint64_t length = frame->ack_block_lengths[i];
        uint64_t smallest;
        if (length == 0 || length - 1 > largest)
            return 0;
        smallest = largest - (length - 1);
        if (i == frame->num_gaps)
            return smallest == frame->smallest_acknowledged;
        if (frame->gaps[i] >= smallest)
            return 0;
        largest = smallest - frame->gaps[i] - 1;
    }
    return 0;
}

static void acknowledge_range(quicly_flexicast_flow_t *flow, int member_index, uint64_t smallest, uint64_t largest, int64_t now,
                              quicly_flexicast_feedback_t *feedback, flexicast_delivery_sample_t *observation,
                              size_t *num_completed, unsigned flags, size_t *total_acked)
{
    uint64_t window_start;
    if (flow->next_packet_number == flow->first_packet_number)
        return;
    window_start = sent_window_start(flow);
    if (window_start < flow->members[member_index].loss_cursor)
        window_start = flow->members[member_index].loss_cursor;
    if (largest >= flow->next_packet_number)
        largest = flow->next_packet_number - 1;
    if (smallest < window_start)
        smallest = window_start;
    if (smallest > largest)
        return;
    for (uint64_t packet_number = largest;; --packet_number) {
        (void)acknowledge_packet(flow, member_index, packet_number, now, feedback, observation, num_completed, flags, total_acked);
        if (packet_number == smallest)
            break;
    }
}

int quicly_flexicast_ack_frame(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame, unsigned flags,
                               size_t *num_acked, size_t *num_lost, size_t *num_completed, int64_t now)
{
    quicly_flexicast_feedback_t feedback = {
        .member_id = member_id, .largest_acknowledged = frame != NULL ? frame->largest_acknowledged : 0, .now = now};
    flexicast_delivery_sample_t observation = {0};
    int member_index;
    uint64_t largest, sent_in_epoch;
    size_t total_acked = 0, retired_lost = 0, completed = 0;

    if (num_acked != NULL)
        *num_acked = 0;
    if (num_lost != NULL)
        *num_lost = 0;
    if (num_completed != NULL)
        *num_completed = 0;
    if (flow == NULL || flow->sent == NULL)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (flags & ~(QUICLY_FLEXICAST_ACK_OMIT_RTT | QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE | QUICLY_FLEXICAST_ACK_DEFER_LOSS))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    /* permit known suspended members to retire pre-suspension packets */
    if ((member_index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!validate_ack_frame(frame) || frame->largest_acknowledged >= flow->next_packet_number)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    /* ignore stale feedback from previous key epochs */
    if (frame->largest_acknowledged < flow->first_packet_number)
        return QUICLY_FLEXICAST_OK;
    /* reject implausible ECN totals exceeding packets sent in this epoch */
    sent_in_epoch = flow->next_packet_number - flow->first_packet_number;
    if (frame->ecn_counts[0] > sent_in_epoch || frame->ecn_counts[1] > sent_in_epoch - frame->ecn_counts[0] ||
        frame->ecn_counts[2] > sent_in_epoch - frame->ecn_counts[0] - frame->ecn_counts[1])
        return QUICLY_FLEXICAST_ERROR_INVALID;
    /* receipt credit survives a route reset while samples from the old route do not */
    if (frame->largest_acknowledged < flow->members[member_index].path_sample_floor)
        flags |= QUICLY_FLEXICAST_ACK_OMIT_RTT | QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE;
    feedback.ack_delay_msec = clamp_msec(frame->ack_delay);
    uint64_t spurious_old = 0;
    int has_unreported_retired = flow->members[member_index].ecn_unreported_retired.num_ranges != 0;
    uint64_t old_floor_excl = flow->members[member_index].path_sample_floor;
    largest = frame->largest_acknowledged;
    for (uint64_t i = 0; i <= frame->num_gaps; ++i) {
        uint64_t smallest = largest - (frame->ack_block_lengths[i] - 1);
        if (has_unreported_retired && largest >= flow->first_packet_number) {
            uint64_t lo = smallest < flow->first_packet_number ? flow->first_packet_number : smallest;
            uint64_t hi_excl = largest + 1;
            if (lo < old_floor_excl) {
                uint64_t old_hi = hi_excl < old_floor_excl ? hi_excl : old_floor_excl;
                spurious_old += count_ecn_unreported_overlap(&flow->members[member_index].ecn_unreported_retired, lo, old_hi);
            }
            (void)quicly_ranges_subtract(&flow->members[member_index].ecn_unreported_retired, lo, hi_excl);
            has_unreported_retired = flow->members[member_index].ecn_unreported_retired.num_ranges != 0;
        }
        acknowledge_range(flow, member_index, smallest, largest, now, &feedback, &observation, &completed, flags, &total_acked);
        if (i != frame->num_gaps)
            largest = smallest - frame->gaps[i] - 1;
    }
    if (!(flags & QUICLY_FLEXICAST_ACK_DEFER_LOSS))
        retired_lost = retire_lost_packets(flow, member_index, frame->largest_acknowledged, &feedback, &completed);
    if (frame->largest_acknowledged > flow->members[member_index].stats.largest_acknowledged)
        flow->members[member_index].stats.largest_acknowledged = frame->largest_acknowledged;
    if (frame->ecn_counts[2] > flow->members[member_index].stats.ecn_ce_count) {
        uint64_t ce_delta = frame->ecn_counts[2] - flow->members[member_index].stats.ecn_ce_count;
        flow->members[member_index].stats.ecn_ce_count = frame->ecn_counts[2];
        /* absorb old-route CE marks on old-only and route-straddling ACKs */
        if (frame->largest_acknowledged >= flow->members[member_index].path_sample_floor) {
            uint64_t old_acked = total_acked - feedback.acked_packets + spurious_old;
            feedback.ecn_ce_count = ce_delta > old_acked ? ce_delta - old_acked : 0;
        }
    }
    if (total_acked != 0 && observation.bytes == 0 && feedback.lost_packets == 0 && feedback.ecn_ce_count == 0)
        flags |= QUICLY_FLEXICAST_ACK_OMIT_RTT | QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE;
    if (num_acked != NULL)
        *num_acked = total_acked;
    if (num_lost != NULL)
        *num_lost = retired_lost;
    if (num_completed != NULL)
        *num_completed = completed;
    finish_feedback(flow, member_index, &feedback, &observation, flags,
                    total_acked != 0 || retired_lost != 0 || feedback.ecn_ce_count != 0);
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_get_pending_members(const quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t *pending)
{
    const quicly_flexicast_sent_t *sent;
    if (flow == NULL || pending == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (flow->sent == NULL)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    sent = get_sent(flow, packet_number);
    if (sent == NULL || sent->pending_count == 0 || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    *pending = sent->pending_count;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_abandon_datagram(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete)
{
    int member_index;
    quicly_flexicast_sent_t *sent;
    if (flow == NULL || complete == NULL || flow->sent == NULL || (member_index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    sent = get_sent(flow, packet_number);
    if (sent == NULL || sent->pending_count == 0 || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!sent_has_member(flow, sent, (size_t)member_index))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    (void)sent_clear_member(flow, sent, (size_t)member_index);
    record_ecn_unreported_retirement(&flow->members[member_index], packet_number, packet_number + 1);
    *complete = sent->pending_count == 0;
    if (flow->members[member_index].active)
        sync_member_cc_pending(flow, (size_t)member_index, INT64_MIN);
    return QUICLY_FLEXICAST_OK;
}

void quicly_flexicast_cc_on_flow_timeout(quicly_flexicast_flow_t *flow, int64_t now)
{
    if (flow != NULL)
        quicly_flexicast_cc_on_timeout(flow->cc, now);
}

void quicly_flexicast_cc_get_flow_output(const quicly_flexicast_flow_t *flow, quicly_flexicast_cc_output_t *output)
{
    quicly_flexicast_cc_get_output(flow != NULL ? flow->cc : NULL, output);
}

int quicly_flexicast_suspend(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int index;
    if (flow == NULL || (index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (flow->members[index].active) {
        flow->members[index].active = 0;
        flow->members[index].suspended_at_pn = flow->next_packet_number;
        set_member_active(flow, (size_t)index, 0);
        --flow->num_members;
        ++flow->suspend_epoch;
        inactive_member_push_back(flow, (uint32_t)index);
        quicly_flexicast_cc_on_member_suspended(flow->cc, member_id, now);
    }
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_note_member_feedback(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int index;
    if (flow == NULL || now < 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((index = find_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_member_stats_t *stats = &flow->members[index].stats;
    if (now <= stats->last_feedback_at)
        return QUICLY_FLEXICAST_OK;
    if (stats->feedback_epoch == UINT64_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    stats->last_feedback_at = now;
    quicly_flexicast_feedback_t feedback = {.member_id = member_id,
                                            .epoch = ++stats->feedback_epoch,
                                            .largest_acknowledged = stats->largest_acknowledged,
                                            .delivered_bytes = stats->delivered_bytes,
                                            .now = now};
    quicly_flexicast_cc_on_feedback(flow->cc, &feedback);
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_reset_member_path(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int index;
    if (flow == NULL || (index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_member_t *member = flow->members + index;
    member->path_sample_floor = flow->next_packet_number;
    member->cc_pending_cursor = flow->next_packet_number;
    member->stats.latest_rtt_msec = member->stats.minimum_rtt_msec = member->stats.smoothed_rtt_msec = 0;
    member->stats.delivery_rate_bytes_per_second = 0;
    member->rate_sample = member->published_rate_sample = (flexicast_delivery_sample_t){0};
    member->rtt_sample_at = 0;
    member->has_rtt_sample = 0;
    member->raw_rtt_msec = member->rtt_ack_delay_msec = member->applied_ack_delay_msec = member->rtt_sample_flags = 0;
    /* recreate controller member to drop cached RTT/rate baselines without touching sent bits */
    quicly_flexicast_cc_on_member_removed(flow->cc, member_id, now);
    if (member->active && quicly_flexicast_cc_on_member_added(flow->cc, member_id, now) != 0) {
        member->active = 0;
        member->suspended_at_pn = flow->next_packet_number;
        set_member_active(flow, (size_t)index, 0);
        --flow->num_members;
        ++flow->suspend_epoch;
        inactive_member_push_back(flow, (uint32_t)index);
        return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
    }
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_resume(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int index;
    if (flow == NULL || (index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!flow->members[index].active) {
        inactive_member_unlink(flow, (uint32_t)index);
        flow->members[index].excluded_packets += flow->next_packet_number - flow->members[index].suspended_at_pn;
        flow->members[index].active_since_pn = flow->next_packet_number;
        flow->members[index].active = 1;
        set_member_active(flow, (size_t)index, 1);
        ++flow->num_members;
        return quicly_flexicast_reset_member_path(flow, member_id, now);
    }
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_get_receive_state(const quicly_flexicast_flow_t *flow, const quicly_range_t **ranges, size_t *num_ranges,
                                       uint64_t *history_lower_bound, int64_t *largest_received_at, uint64_t ecn_counts[3])
{
    if (flow == NULL || ranges == NULL || num_ranges == NULL || history_lower_bound == NULL || largest_received_at == NULL ||
        ecn_counts == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    *ranges = flow->received.ack_ranges.ranges;
    *num_ranges = flow->received.ack_ranges.num_ranges;
    *history_lower_bound = flow->received.history_lower_bound;
    *largest_received_at = flow->received.largest_received_at;
    memcpy(ecn_counts, flow->received.ecn_counts, sizeof(flow->received.ecn_counts));
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_commit_ack_loss(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t coverage_lower_bound,
                                     uint64_t largest_received, size_t *num_lost, size_t *num_completed, int64_t now)
{
    int index;
    size_t completed = 0, retired;

    if (num_lost != NULL)
        *num_lost = 0;
    if (num_completed != NULL)
        *num_completed = 0;
    if (flow == NULL || flow->sent == NULL || (index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (coverage_lower_bound > largest_received || coverage_lower_bound < flow->first_packet_number ||
        largest_received >= flow->next_packet_number)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    uint64_t threshold = flow->packet_reordering_threshold;
    if (largest_received < threshold)
        return QUICLY_FLEXICAST_OK;
    uint64_t end = largest_received - threshold, start = sent_window_start(flow);
    if (start < flow->members[index].loss_cursor)
        start = flow->members[index].loss_cursor;
    if (start < coverage_lower_bound)
        start = coverage_lower_bound;
    if (start > end)
        return QUICLY_FLEXICAST_OK;
    quicly_flexicast_feedback_t feedback = {.member_id = member_id, .largest_acknowledged = largest_received, .now = now};
    retired = retire_loss_range(flow, index, start, end, &feedback, &completed);
    /* keep loss_cursor conservative when unresolved holes remain below coverage */
    if (coverage_lower_bound <= flow->members[index].loss_cursor && end >= flow->members[index].loss_cursor)
        flow->members[index].loss_cursor = end + 1;
    if (num_lost != NULL)
        *num_lost = retired;
    if (num_completed != NULL)
        *num_completed = completed;
    const flexicast_delivery_sample_t observation = {0};
    finish_feedback(flow, index, &feedback, &observation, QUICLY_FLEXICAST_ACK_OMIT_RTT | QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE,
                    retired != 0);
    return QUICLY_FLEXICAST_OK;
}
