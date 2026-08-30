/*
 * Copyright (c) 2026 Joseph Calderon
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "quicly/flexicast.h"

#include "quicly/frame.h"

#include <stdlib.h>

static int valid_flow_id(const quicly_flexicast_flow_id_t *flow_id)
{
    return flow_id != NULL && flow_id->len >= 1 && flow_id->len <= QUICLY_FLEXICAST_MAX_FLOW_ID_SIZE;
}

static int valid_varint(uint64_t value)
{
    return value <= PTLS_QUICINT_MAX;
}

static size_t frame_prefix_capacity(uint64_t frame_type, const quicly_flexicast_flow_id_t *flow_id, uint64_t sequence)
{
    if (!valid_flow_id(flow_id) || !valid_varint(sequence))
        return 0;
    return quicly_encodev_capacity(frame_type) + 1 + flow_id->len + quicly_encodev_capacity(sequence);
}

static uint8_t *encode_frame_prefix(uint8_t *dst, uint64_t frame_type, const quicly_flexicast_flow_id_t *flow_id, uint64_t sequence)
{
    dst = quicly_encodev(dst, frame_type);
    *dst++ = flow_id->len;
    memcpy(dst, flow_id->bytes, flow_id->len);
    dst += flow_id->len;
    return quicly_encodev(dst, sequence);
}

static int decode_frame_prefix(const uint8_t **src, const uint8_t *end, uint64_t expected_type, quicly_flexicast_flow_id_t *flow_id,
                               uint64_t *sequence)
{
    uint64_t frame_type;

    if ((frame_type = quicly_decodev(src, end)) == UINT64_MAX || frame_type != expected_type || *src == end)
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    flow_id->len = *(*src)++;
    if (!valid_flow_id(flow_id) || (size_t)(end - *src) < flow_id->len)
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    memcpy(flow_id->bytes, *src, flow_id->len);
    *src += flow_id->len;
    if ((*sequence = quicly_decodev(src, end)) == UINT64_MAX)
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    return QUICLY_FLEXICAST_OK;
}

size_t quicly_flexicast_announce_frame_capacity(const quicly_flexicast_announce_frame_t *frame)
{
    size_t prefix, address_size;

    if (frame == NULL || (frame->ip_version != 4 && frame->ip_version != 6) ||
        (prefix = frame_prefix_capacity(QUICLY_FRAME_TYPE_FC_ANNOUNCE, &frame->flow_id, frame->sequence)) == 0)
        return 0;
    address_size = frame->ip_version == 4 ? 4 : 16;
    return prefix + 1 + 2 * address_size + 2 + 8;
}

int quicly_flexicast_encode_announce_frame(uint8_t *dst, size_t capacity, const quicly_flexicast_announce_frame_t *frame,
                                           size_t *encoded_size)
{
    size_t required, address_size;
    uint8_t *start = dst;

    if (dst == NULL || encoded_size == NULL || (required = quicly_flexicast_announce_frame_capacity(frame)) == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (capacity < required)
        return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
    address_size = frame->ip_version == 4 ? 4 : 16;
    dst = encode_frame_prefix(dst, QUICLY_FRAME_TYPE_FC_ANNOUNCE, &frame->flow_id, frame->sequence);
    *dst++ = frame->ip_version;
    memcpy(dst, frame->source_ip, address_size);
    dst += address_size;
    memcpy(dst, frame->group_ip, address_size);
    dst += address_size;
    dst = quicly_encode16(dst, frame->udp_port);
    dst = quicly_encode64(dst, frame->ack_delay_msec);
    *encoded_size = dst - start;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_decode_announce_frame(const uint8_t *src, size_t len, quicly_flexicast_announce_frame_t *frame,
                                           size_t *consumed)
{
    const uint8_t *start = src, *end;
    size_t address_size;
    int ret;

    if (src == NULL || frame == NULL || consumed == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    end = src + len;
    memset(frame, 0, sizeof(*frame));
    if ((ret = decode_frame_prefix(&src, end, QUICLY_FRAME_TYPE_FC_ANNOUNCE, &frame->flow_id, &frame->sequence)) != 0)
        return ret;
    if (src == end || (*src != 4 && *src != 6))
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    frame->ip_version = *src++;
    address_size = frame->ip_version == 4 ? 4 : 16;
    if ((size_t)(end - src) < 2 * address_size + 2 + 8)
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    memcpy(frame->source_ip, src, address_size);
    src += address_size;
    memcpy(frame->group_ip, src, address_size);
    src += address_size;
    frame->udp_port = quicly_decode16(&src);
    frame->ack_delay_msec = quicly_decode64(&src);
    *consumed = src - start;
    return QUICLY_FLEXICAST_OK;
}

static int valid_state_action(uint64_t action)
{
    return action == QUICLY_FLEXICAST_STATE_JOIN || action == QUICLY_FLEXICAST_STATE_LEAVE ||
           action == QUICLY_FLEXICAST_STATE_READY;
}

size_t quicly_flexicast_state_frame_capacity(const quicly_flexicast_state_frame_t *frame)
{
    size_t prefix;

    if (frame == NULL || !valid_state_action(frame->action) ||
        (prefix = frame_prefix_capacity(QUICLY_FRAME_TYPE_FC_STATE, &frame->flow_id, frame->sequence)) == 0)
        return 0;
    return prefix + 8;
}

int quicly_flexicast_encode_state_frame(uint8_t *dst, size_t capacity, const quicly_flexicast_state_frame_t *frame,
                                        size_t *encoded_size)
{
    size_t required;
    uint8_t *start = dst;

    if (dst == NULL || encoded_size == NULL || (required = quicly_flexicast_state_frame_capacity(frame)) == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (capacity < required)
        return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
    dst = encode_frame_prefix(dst, QUICLY_FRAME_TYPE_FC_STATE, &frame->flow_id, frame->sequence);
    dst = quicly_encode64(dst, frame->action);
    *encoded_size = dst - start;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_decode_state_frame(const uint8_t *src, size_t len, quicly_flexicast_state_frame_t *frame, size_t *consumed)
{
    const uint8_t *start = src, *end;
    int ret;

    if (src == NULL || frame == NULL || consumed == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    end = src + len;
    memset(frame, 0, sizeof(*frame));
    if ((ret = decode_frame_prefix(&src, end, QUICLY_FRAME_TYPE_FC_STATE, &frame->flow_id, &frame->sequence)) != 0)
        return ret;
    if ((size_t)(end - src) < 8)
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    frame->action = quicly_decode64(&src);
    if (!valid_state_action(frame->action))
        return QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION;
    *consumed = src - start;
    return QUICLY_FLEXICAST_OK;
}

size_t quicly_flexicast_key_frame_capacity(const quicly_flexicast_key_frame_t *frame)
{
    size_t prefix, key_len_capacity;

    if (frame == NULL || !valid_varint(frame->first_packet_number) || frame->key.len > PTLS_QUICINT_MAX ||
        (frame->key.len != 0 && frame->key.base == NULL) ||
        (prefix = frame_prefix_capacity(QUICLY_FRAME_TYPE_FC_KEY, &frame->flow_id, frame->sequence)) == 0)
        return 0;
    key_len_capacity = quicly_encodev_capacity(frame->key.len);
    if (frame->key.len > SIZE_MAX - prefix - quicly_encodev_capacity(frame->first_packet_number) - key_len_capacity - 8)
        return 0;
    return prefix + quicly_encodev_capacity(frame->first_packet_number) + key_len_capacity + frame->key.len + 8;
}

int quicly_flexicast_encode_key_frame(uint8_t *dst, size_t capacity, const quicly_flexicast_key_frame_t *frame,
                                      size_t *encoded_size)
{
    size_t required;
    uint8_t *start = dst;

    if (dst == NULL || encoded_size == NULL || (required = quicly_flexicast_key_frame_capacity(frame)) == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (capacity < required)
        return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
    dst = encode_frame_prefix(dst, QUICLY_FRAME_TYPE_FC_KEY, &frame->flow_id, frame->sequence);
    dst = quicly_encodev(dst, frame->first_packet_number);
    dst = quicly_encodev(dst, frame->key.len);
    if (frame->key.len != 0)
        memcpy(dst, frame->key.base, frame->key.len);
    dst += frame->key.len;
    dst = quicly_encode64(dst, frame->algorithm);
    *encoded_size = dst - start;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_decode_key_frame(const uint8_t *src, size_t len, quicly_flexicast_key_frame_t *frame, size_t *consumed)
{
    const uint8_t *start = src, *end;
    uint64_t key_len;
    int ret;

    if (src == NULL || frame == NULL || consumed == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    end = src + len;
    memset(frame, 0, sizeof(*frame));
    if ((ret = decode_frame_prefix(&src, end, QUICLY_FRAME_TYPE_FC_KEY, &frame->flow_id, &frame->sequence)) != 0)
        return ret;
    if ((frame->first_packet_number = quicly_decodev(&src, end)) == UINT64_MAX ||
        (key_len = quicly_decodev(&src, end)) == UINT64_MAX || (size_t)(end - src) < 8 || key_len > (uint64_t)((end - src) - 8))
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    frame->key = ptls_iovec_init(src, (size_t)key_len);
    src += key_len;
    if ((size_t)(end - src) < 8)
        return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
    frame->algorithm = quicly_decode64(&src);
    *consumed = src - start;
    return QUICLY_FLEXICAST_OK;
}

typedef struct st_quicly_flexicast_sent_t {
    uint64_t packet_number;
    size_t pending_count;
    size_t packet_size;
    int64_t sent_at;
    int occupied;
} quicly_flexicast_sent_t;

typedef struct st_quicly_flexicast_member_t {
    uint64_t id;
    uint64_t loss_cursor;
    quicly_flexicast_member_stats_t stats;
    int known;
    int active;
} quicly_flexicast_member_t;

typedef struct st_quicly_flexicast_member_map_entry_t {
    uint64_t id;
    uint32_t slot;
    uint8_t state;
} quicly_flexicast_member_map_entry_t;

#define MEMBER_MAP_EMPTY 0
#define MEMBER_MAP_OCCUPIED 1
#define MEMBER_MAP_TOMBSTONE 2

struct st_quicly_flexicast_flow_t {
    uint64_t flow_id;
    ptls_cipher_suite_t *cipher_suite;
    quicly_crypto_engine_t *crypto_engine;
    quicly_conn_t *crypto_conn;
    struct {
        ptls_cipher_context_t *header_protection;
        ptls_aead_context_t *aead;
    } egress, ingress;
    uint64_t next_packet_number;
    uint64_t first_packet_number;
    struct {
        uint64_t largest;
        uint64_t mask;
        quicly_ranges_t ack_ranges;
        size_t ack_eliciting_since_ack;
        uint64_t ack_frames_sent;
        int64_t ack_pending_since;
        int64_t largest_received_at;
        uint32_t ack_delay_msec;
        uint16_t ack_frequency;
        int initialized;
    } received;
    quicly_flexicast_member_t *members;
    uint32_t *free_member_slots;
    size_t num_free_member_slots;
    size_t max_members;
    size_t num_members;
    quicly_flexicast_member_map_entry_t *member_map;
    size_t member_map_capacity;
    uint64_t *active_member_words;
    uint64_t *pending_member_words;
    size_t member_word_count;
    quicly_flexicast_cc_config_t cc_config;
    quicly_flexicast_cc_t *cc;
    quicly_flexicast_sent_t sent[QUICLY_FLEXICAST_SENT_WINDOW];
};

static uint64_t member_hash(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static int member_map_lookup(const quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    size_t index = (size_t)member_hash(member_id) & (flow->member_map_capacity - 1);
    for (size_t probe = 0; probe != flow->member_map_capacity; ++probe) {
        const quicly_flexicast_member_map_entry_t *entry = flow->member_map + index;
        if (entry->state == MEMBER_MAP_EMPTY)
            return -1;
        if (entry->state == MEMBER_MAP_OCCUPIED && entry->id == member_id)
            return (int)entry->slot;
        index = (index + 1) & (flow->member_map_capacity - 1);
    }
    return -1;
}

static int member_map_insert(quicly_flexicast_flow_t *flow, uint64_t member_id, uint32_t slot)
{
    size_t index = (size_t)member_hash(member_id) & (flow->member_map_capacity - 1), tombstone = SIZE_MAX;
    for (size_t probe = 0; probe != flow->member_map_capacity; ++probe) {
        quicly_flexicast_member_map_entry_t *entry = flow->member_map + index;
        if (entry->state == MEMBER_MAP_OCCUPIED) {
            if (entry->id == member_id)
                return -1;
        } else if (entry->state == MEMBER_MAP_TOMBSTONE) {
            if (tombstone == SIZE_MAX)
                tombstone = index;
        } else {
            if (tombstone != SIZE_MAX)
                entry = flow->member_map + tombstone;
            entry->id = member_id;
            entry->slot = slot;
            entry->state = MEMBER_MAP_OCCUPIED;
            return 0;
        }
        index = (index + 1) & (flow->member_map_capacity - 1);
    }
    if (tombstone != SIZE_MAX) {
        quicly_flexicast_member_map_entry_t *entry = flow->member_map + tombstone;
        entry->id = member_id;
        entry->slot = slot;
        entry->state = MEMBER_MAP_OCCUPIED;
        return 0;
    }
    return -1;
}

static void member_map_remove(quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    size_t index = (size_t)member_hash(member_id) & (flow->member_map_capacity - 1);
    for (size_t probe = 0; probe != flow->member_map_capacity; ++probe) {
        quicly_flexicast_member_map_entry_t *entry = flow->member_map + index;
        if (entry->state == MEMBER_MAP_EMPTY)
            return;
        if (entry->state == MEMBER_MAP_OCCUPIED && entry->id == member_id) {
            entry->id = 0;
            entry->slot = 0;
            entry->state = MEMBER_MAP_TOMBSTONE;
            return;
        }
        index = (index + 1) & (flow->member_map_capacity - 1);
    }
}

static uint64_t *sent_member_words(quicly_flexicast_flow_t *flow, const quicly_flexicast_sent_t *sent)
{
    size_t sent_index = (size_t)(sent - flow->sent);
    return flow->pending_member_words + sent_index * flow->member_word_count;
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
    --sent->pending_count;
    return 1;
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

int quicly_flexicast_flow_create(quicly_flexicast_flow_t **flow, const quicly_flexicast_config_t *config)
{
    quicly_flexicast_flow_t *new_flow;
    quicly_flexicast_cc_config_t cc_config;
    size_t max_members, member_map_capacity;
    int ret;

    if (flow == NULL || config == NULL || config->flow_id == 0 || config->flow_id > PTLS_QUICINT_MAX ||
        config->first_packet_number > PTLS_QUICINT_MAX || config->cipher_suite == NULL || config->crypto_engine == NULL ||
        config->crypto_engine->setup_cipher == NULL || config->crypto_engine->encrypt_packet == NULL ||
        config->traffic_secret.base == NULL || config->traffic_secret.len != config->cipher_suite->hash->digest_size)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    max_members = config->max_members != 0 ? config->max_members : QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS;
    if (max_members > QUICLY_FLEXICAST_HARD_MAX_MEMBERS)
        return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
    *flow = NULL;
    if ((new_flow = calloc(1, sizeof(*new_flow))) == NULL)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    new_flow->flow_id = config->flow_id;
    new_flow->first_packet_number = config->first_packet_number;
    new_flow->next_packet_number = config->first_packet_number;
    new_flow->cipher_suite = config->cipher_suite;
    new_flow->crypto_engine = config->crypto_engine;
    new_flow->crypto_conn = config->crypto_conn;
    quicly_ranges_init(&new_flow->received.ack_ranges);
    new_flow->max_members = max_members;
    new_flow->member_word_count = (max_members + 63) / 64;
    for (member_map_capacity = 2; member_map_capacity < max_members * 2; member_map_capacity *= 2)
        ;
    new_flow->member_map_capacity = member_map_capacity;
    if ((new_flow->members = calloc(max_members, sizeof(*new_flow->members))) == NULL ||
        (new_flow->free_member_slots = malloc(max_members * sizeof(*new_flow->free_member_slots))) == NULL ||
        (new_flow->member_map = calloc(member_map_capacity, sizeof(*new_flow->member_map))) == NULL ||
        (new_flow->active_member_words = calloc(new_flow->member_word_count, sizeof(*new_flow->active_member_words))) == NULL ||
        (new_flow->pending_member_words =
             calloc(QUICLY_FLEXICAST_SENT_WINDOW * new_flow->member_word_count, sizeof(*new_flow->pending_member_words))) == NULL)
        goto NoMemory;
    for (size_t i = 0; i != max_members; ++i)
        new_flow->free_member_slots[new_flow->num_free_member_slots++] = (uint32_t)(max_members - i - 1);
    new_flow->received.ack_delay_msec = config->ack_delay_msec != 0 ? config->ack_delay_msec : 25;
    new_flow->received.ack_frequency = config->ack_frequency != 0 ? config->ack_frequency : QUICLY_FLEXICAST_DEFAULT_ACK_FREQUENCY;

    cc_config = config->cc_config;
    if (cc_config.maximum_datagram_size == 0)
        cc_config.maximum_datagram_size = 1200;
    if (cc_config.startup_rate_bytes_per_second == 0)
        cc_config.startup_rate_bytes_per_second = 64 * 1024;
    if (cc_config.minimum_rate_bytes_per_second == 0)
        cc_config.minimum_rate_bytes_per_second = 2 * 1024;
    if (cc_config.feedback_timeout_msec == 0)
        cc_config.feedback_timeout_msec = 1000;
    if (cc_config.packet_reordering_threshold == 0)
        cc_config.packet_reordering_threshold = 3;
    if (cc_config.maximum_members == 0)
        cc_config.maximum_members = max_members;
    if (cc_config.maximum_members < max_members)
        cc_config.maximum_members = max_members;
    new_flow->cc_config = cc_config;
    if (config->cc_type != NULL && quicly_flexicast_cc_create(&new_flow->cc, config->cc_type, &cc_config, config->now) != 0)
        goto NoMemory;

    if ((ret = new_flow->crypto_engine->setup_cipher(
             new_flow->crypto_engine, new_flow->crypto_conn, QUICLY_EPOCH_1RTT, 1, &new_flow->egress.header_protection,
             &new_flow->egress.aead, config->cipher_suite->aead, config->cipher_suite->hash, config->traffic_secret.base)) != 0)
        goto CryptoError;
    if ((ret = new_flow->crypto_engine->setup_cipher(
             new_flow->crypto_engine, new_flow->crypto_conn, QUICLY_EPOCH_1RTT, 0, &new_flow->ingress.header_protection,
             &new_flow->ingress.aead, config->cipher_suite->aead, config->cipher_suite->hash, config->traffic_secret.base)) != 0)
        goto CryptoError;

    *flow = new_flow;
    return QUICLY_FLEXICAST_OK;

CryptoError:
    (void)ret;
    quicly_flexicast_flow_free(new_flow);
    return QUICLY_FLEXICAST_ERROR_CRYPTO;

NoMemory:
    quicly_flexicast_flow_free(new_flow);
    return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
}

int quicly_flexicast_flow_rekey(quicly_flexicast_flow_t *flow, ptls_iovec_t traffic_secret, uint64_t first_packet_number,
                                int64_t now)
{
    ptls_cipher_context_t *egress_hp = NULL, *ingress_hp = NULL;
    ptls_aead_context_t *egress_aead = NULL, *ingress_aead = NULL;
    int ret;
    if (flow == NULL || traffic_secret.base == NULL || traffic_secret.len != flow->cipher_suite->hash->digest_size ||
        first_packet_number > PTLS_QUICINT_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((ret = flow->crypto_engine->setup_cipher(flow->crypto_engine, flow->crypto_conn, QUICLY_EPOCH_1RTT, 1, &egress_hp,
                                                 &egress_aead, flow->cipher_suite->aead, flow->cipher_suite->hash,
                                                 traffic_secret.base)) != 0)
        goto Error;
    if ((ret = flow->crypto_engine->setup_cipher(flow->crypto_engine, flow->crypto_conn, QUICLY_EPOCH_1RTT, 0, &ingress_hp,
                                                 &ingress_aead, flow->cipher_suite->aead, flow->cipher_suite->hash,
                                                 traffic_secret.base)) != 0)
        goto Error;

    dispose_cipher(&flow->egress.header_protection, &flow->egress.aead);
    dispose_cipher(&flow->ingress.header_protection, &flow->ingress.aead);
    flow->egress.header_protection = egress_hp;
    flow->egress.aead = egress_aead;
    flow->ingress.header_protection = ingress_hp;
    flow->ingress.aead = ingress_aead;
    flow->first_packet_number = first_packet_number;
    flow->next_packet_number = first_packet_number;
    flow->received.largest = 0;
    flow->received.mask = 0;
    flow->received.initialized = 0;
    flow->received.ack_ranges.num_ranges = 0;
    flow->received.ack_eliciting_since_ack = 0;
    flow->received.ack_frames_sent = 0;
    flow->received.ack_pending_since = 0;
    flow->received.largest_received_at = 0;
    memset(flow->sent, 0, sizeof(flow->sent));
    memset(flow->pending_member_words, 0,
           QUICLY_FLEXICAST_SENT_WINDOW * flow->member_word_count * sizeof(*flow->pending_member_words));
    memset(flow->active_member_words, 0, flow->member_word_count * sizeof(*flow->active_member_words));
    flow->num_members = 0;
    for (size_t i = 0; i != flow->max_members; ++i) {
        if (!flow->members[i].known)
            continue;
        flow->members[i].active = 0;
        flow->members[i].loss_cursor = first_packet_number;
    }
    /* Feedback for the old packet-number epoch cannot satisfy a deadline in
     * the new one. Preserve learned path rates, but restart controller-local
     * liveness and congestion episodes at the rekey boundary. */
    quicly_flexicast_cc_on_epoch_reset(flow->cc, now);
    return QUICLY_FLEXICAST_OK;

Error:
    (void)ret;
    dispose_cipher(&egress_hp, &egress_aead);
    dispose_cipher(&ingress_hp, &ingress_aead);
    return QUICLY_FLEXICAST_ERROR_CRYPTO;
}

void quicly_flexicast_flow_free(quicly_flexicast_flow_t *flow)
{
    if (flow == NULL)
        return;
    quicly_flexicast_cc_free(flow->cc);
    flow->cc = NULL;
    quicly_ranges_clear(&flow->received.ack_ranges);
    dispose_cipher(&flow->egress.header_protection, &flow->egress.aead);
    dispose_cipher(&flow->ingress.header_protection, &flow->ingress.aead);
    if (flow->members != NULL) {
        ptls_clear_memory(flow->members, flow->max_members * sizeof(*flow->members));
        free(flow->members);
    }
    free(flow->free_member_slots);
    free(flow->member_map);
    free(flow->active_member_words);
    if (flow->pending_member_words != NULL) {
        ptls_clear_memory(flow->pending_member_words,
                          QUICLY_FLEXICAST_SENT_WINDOW * flow->member_word_count * sizeof(*flow->pending_member_words));
        free(flow->pending_member_words);
    }
    ptls_clear_memory(flow, sizeof(*flow));
    free(flow);
}

uint64_t quicly_flexicast_get_flow_id(const quicly_flexicast_flow_t *flow)
{
    return flow != NULL ? flow->flow_id : 0;
}

uint64_t quicly_flexicast_get_next_packet_number(const quicly_flexicast_flow_t *flow)
{
    return flow != NULL ? flow->next_packet_number : 0;
}

static int find_member(const quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    int index = member_map_lookup(flow, member_id);
    return index >= 0 && flow->members[index].active ? index : -1;
}

static int find_known_member(const quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    int index = member_map_lookup(flow, member_id);
    return index >= 0 && flow->members[index].known ? index : -1;
}

int quicly_flexicast_attach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    size_t i;
    int known_index;
    if (flow == NULL || member_id == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (find_member(flow, member_id) >= 0)
        return QUICLY_FLEXICAST_OK;
    if ((known_index = find_known_member(flow, member_id)) >= 0) {
        i = (size_t)known_index;
        flow->members[i].active = 1;
        flow->members[i].loss_cursor = flow->next_packet_number;
        set_member_active(flow, i, 1);
        ++flow->num_members;
        return QUICLY_FLEXICAST_OK;
    }
    if (flow->num_free_member_slots == 0)
        return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
    i = flow->free_member_slots[--flow->num_free_member_slots];
    flow->members[i].id = member_id;
    flow->members[i].loss_cursor = flow->next_packet_number;
    flow->members[i].stats.member_id = member_id;
    flow->members[i].known = 1;
    flow->members[i].active = 1;
    if (member_map_insert(flow, member_id, (uint32_t)i) != 0) {
        memset(flow->members + i, 0, sizeof(flow->members[i]));
        flow->free_member_slots[flow->num_free_member_slots++] = (uint32_t)i;
        return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
    }
    set_member_active(flow, i, 1);
    ++flow->num_members;
    quicly_flexicast_cc_on_member_added(flow->cc, member_id, now);
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_attach(quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    return quicly_flexicast_attach_at(flow, member_id, 0);
}

int quicly_flexicast_detach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int member_index;
    size_t i;
    if (flow == NULL || member_id == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((member_index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_cc_on_member_removed(flow->cc, member_id, now);
    if (flow->members[member_index].active) {
        set_member_active(flow, (size_t)member_index, 0);
        --flow->num_members;
    }
    member_map_remove(flow, member_id);
    memset(&flow->members[member_index], 0, sizeof(flow->members[member_index]));
    flow->free_member_slots[flow->num_free_member_slots++] = (uint32_t)member_index;
    for (i = 0; i != QUICLY_FLEXICAST_SENT_WINDOW; ++i) {
        if (flow->sent[i].occupied)
            (void)sent_clear_member(flow, flow->sent + i, (size_t)member_index);
        if (flow->sent[i].occupied && flow->sent[i].pending_count == 0)
            flow->sent[i].occupied = 0;
    }
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_detach(quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    return quicly_flexicast_detach_at(flow, member_id, 0);
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

int quicly_flexicast_send_datagram_at(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                      size_t *packet_size, uint64_t *packet_number, int64_t now)
{
    uint64_t pn;
    size_t required, payload_from;
    uint8_t *dst;
    quicly_flexicast_sent_t *sent;

    if (flow == NULL || packet == NULL || packet_size == NULL || packet_number == NULL ||
        (payload.len != 0 && payload.base == NULL) || payload.len > QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE ||
        flow->next_packet_number == UINT64_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (flow->num_members == 0)
        return QUICLY_FLEXICAST_ERROR_NO_MEMBERS;
    required = 1 + QUICLY_FLEXICAST_FLOW_ID_SIZE + QUICLY_SEND_PN_SIZE + quicly_datagram_frame_capacity(payload) +
               flow->egress.aead->algo->tag_size;
    if (required > packet_capacity)
        return QUICLY_FLEXICAST_ERROR_INVALID;

    pn = flow->next_packet_number;
    sent = flow->sent + pn % QUICLY_FLEXICAST_SENT_WINDOW;
    if (sent->occupied && sent->packet_number != pn)
        return QUICLY_FLEXICAST_ERROR_SEND_WINDOW;

    dst = packet;
    *dst++ = QUICLY_QUIC_BIT | (QUICLY_SEND_PN_SIZE - 1);
    dst = quicly_encode64(dst, flow->flow_id);
    quicly_encode16(dst, (uint16_t)pn);
    dst += QUICLY_SEND_PN_SIZE;
    payload_from = dst - packet;
    dst = quicly_encode_datagram_frame(dst, payload);
    dst += flow->egress.aead->algo->tag_size;

    flow->crypto_engine->encrypt_packet(flow->crypto_engine, flow->crypto_conn, flow->egress.header_protection, flow->egress.aead,
                                        ptls_iovec_init(packet, dst - packet), 0, payload_from, pn, 0);

    sent->packet_number = pn;
    memcpy(sent_member_words(flow, sent), flow->active_member_words, flow->member_word_count * sizeof(*flow->active_member_words));
    sent->pending_count = flow->num_members;
    sent->packet_size = dst - packet;
    sent->sent_at = now;
    sent->occupied = 1;
    ++flow->next_packet_number;
    *packet_size = dst - packet;
    *packet_number = pn;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_send_datagram(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                   size_t *packet_size, uint64_t *packet_number)
{
    return quicly_flexicast_send_datagram_at(flow, payload, packet, packet_capacity, packet_size, packet_number, 0);
}

static int decode_header(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, uint64_t *packet_number,
                         size_t *payload_from)
{
    size_t pn_offset = 1 + QUICLY_FLEXICAST_FLOW_ID_SIZE, pn_length, i, plaintext_size;
    const uint8_t *flow_id_at;
    uint8_t mask[5] = {0};
    uint32_t truncated = 0;
    uint64_t expected, wire_flow_id;

    if (packet_size < pn_offset + QUICLY_MAX_PN_SIZE + flow->ingress.header_protection->algo->iv_size ||
        (packet[0] & (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT)) != QUICLY_QUIC_BIT)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    flow_id_at = packet + 1;
    wire_flow_id = quicly_decode64(&flow_id_at);
    if (wire_flow_id != flow->flow_id)
        return QUICLY_FLEXICAST_ERROR_WRONG_FLOW;

    ptls_cipher_init(flow->ingress.header_protection, packet + pn_offset + QUICLY_MAX_PN_SIZE);
    ptls_cipher_encrypt(flow->ingress.header_protection, mask, mask, sizeof(mask));
    packet[0] ^= mask[0] & 0x1f;
    pn_length = (packet[0] & 0x3) + 1;
    if (pn_length != QUICLY_SEND_PN_SIZE || (packet[0] & 0x18) != 0)
        return QUICLY_FLEXICAST_ERROR_CRYPTO;
    for (i = 0; i != pn_length; ++i) {
        packet[pn_offset + i] ^= mask[i + 1];
        truncated = (truncated << 8) | packet[pn_offset + i];
    }
    expected = flow->received.initialized ? flow->received.largest + 1 : flow->first_packet_number;
    *packet_number = quicly_determine_packet_number(truncated, pn_length * 8, expected);
    *payload_from = pn_offset + pn_length;
    plaintext_size = ptls_aead_decrypt(flow->ingress.aead, packet + *payload_from, packet + *payload_from,
                                       packet_size - *payload_from, *packet_number, packet, *payload_from);
    if (plaintext_size == SIZE_MAX)
        return QUICLY_FLEXICAST_ERROR_CRYPTO;
    return (int)plaintext_size;
}

static int update_replay_window(quicly_flexicast_flow_t *flow, uint64_t packet_number)
{
    uint64_t distance;
    if (!flow->received.initialized) {
        flow->received.initialized = 1;
        flow->received.largest = packet_number;
        flow->received.mask = 1;
        return QUICLY_FLEXICAST_OK;
    }
    if (packet_number > flow->received.largest) {
        distance = packet_number - flow->received.largest;
        flow->received.mask = distance >= QUICLY_FLEXICAST_REPLAY_WINDOW ? 1 : (flow->received.mask << distance) | 1;
        flow->received.largest = packet_number;
        return QUICLY_FLEXICAST_OK;
    }
    distance = flow->received.largest - packet_number;
    if (distance >= QUICLY_FLEXICAST_REPLAY_WINDOW || (flow->received.mask & ((uint64_t)1 << distance)) != 0)
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    flow->received.mask |= (uint64_t)1 << distance;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_receive_datagram_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                         uint64_t *packet_number, int64_t now)
{
    const uint8_t *src, *end;
    uint64_t frame_type;
    size_t payload_from;
    int plaintext_size, ret;
    quicly_datagram_frame_t frame;

    if (flow == NULL || packet == NULL || payload == NULL || packet_number == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((plaintext_size = decode_header(flow, packet, packet_size, packet_number, &payload_from)) < 0)
        return plaintext_size;
    src = packet + payload_from;
    end = src + plaintext_size;
    if ((frame_type = quicly_decodev(&src, end)) == UINT64_MAX || frame_type != QUICLY_FRAME_TYPE_DATAGRAM_WITHLEN ||
        quicly_decode_datagram_frame(frame_type, &src, end, &frame) != 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    while (src != end && *src == QUICLY_FRAME_TYPE_PADDING)
        ++src;
    if (src != end)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    int is_new_largest = !flow->received.initialized || *packet_number > flow->received.largest;
    if ((ret = update_replay_window(flow, *packet_number)) != QUICLY_FLEXICAST_OK)
        return ret;
    if (is_new_largest)
        flow->received.largest_received_at = now;
    if (quicly_ranges_add(&flow->received.ack_ranges, *packet_number, *packet_number + 1) != 0)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    if (flow->received.ack_eliciting_since_ack++ == 0)
        flow->received.ack_pending_since = now;
    *payload = frame.payload;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_receive_datagram(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                      uint64_t *packet_number)
{
    return quicly_flexicast_receive_datagram_at(flow, packet, packet_size, payload, packet_number, 0);
}

int64_t quicly_flexicast_get_ack_deadline(const quicly_flexicast_flow_t *flow)
{
    if (flow == NULL || flow->received.ack_ranges.num_ranges == 0)
        return INT64_MAX;
    if (flow->received.ack_pending_since > INT64_MAX - flow->received.ack_delay_msec)
        return INT64_MAX;
    return flow->received.ack_pending_since + flow->received.ack_delay_msec;
}

int quicly_flexicast_ack_is_due(const quicly_flexicast_flow_t *flow, int64_t now)
{
    int64_t deadline;
    if (flow == NULL || flow->received.ack_ranges.num_ranges == 0)
        return 0;
    if (flow->received.ack_frames_sent == 0 || flow->received.ack_eliciting_since_ack >= flow->received.ack_frequency ||
        flow->received.ack_ranges.num_ranges >= QUICLY_MAX_ACK_BLOCKS)
        return 1;
    deadline = quicly_flexicast_get_ack_deadline(flow);
    return deadline != INT64_MAX && now >= deadline;
}

int quicly_flexicast_encode_pending_ack(quicly_flexicast_flow_t *flow, uint8_t *dst, size_t capacity, int64_t now,
                                        size_t *encoded_size)
{
    uint8_t *end;
    uint64_t ecn_counts[3] = {0};
    uint64_t ack_delay = 0;
    if (flow == NULL || dst == NULL || encoded_size == NULL || flow->received.ack_ranges.num_ranges == 0 ||
        flow->received.ack_ranges.num_ranges > QUICLY_MAX_ACK_BLOCKS || capacity < 2)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (now > flow->received.largest_received_at && flow->received.largest_received_at > 0) {
        ack_delay = (uint64_t)(now - flow->received.largest_received_at);
        if (ack_delay > flow->received.ack_delay_msec)
            ack_delay = flow->received.ack_delay_msec;
    }
    /* Flexicast PATH_ACK encodes this extension-owned value directly in
     * milliseconds; it does not use the connection ACK-delay exponent. */
    if ((end = quicly_encode_path_ack_frame(dst, dst + capacity - 1, flow->flow_id, &flow->received.ack_ranges, ecn_counts,
                                            ack_delay)) == NULL)
        return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
    *end++ = QUICLY_FRAME_TYPE_PING;
    *encoded_size = end - dst;
    return QUICLY_FLEXICAST_OK;
}

void quicly_flexicast_ack_sent(quicly_flexicast_flow_t *flow)
{
    if (flow == NULL)
        return;
    ++flow->received.ack_frames_sent;
    flow->received.ack_ranges.num_ranges = 0;
    flow->received.ack_eliciting_since_ack = 0;
    flow->received.ack_pending_since = 0;
}

static uint32_t clamp_msec(uint64_t value)
{
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
}

static void update_rtt(quicly_flexicast_member_stats_t *stats, const quicly_flexicast_sent_t *sent, int64_t now,
                       uint32_t ack_delay_msec)
{
    uint32_t sample;
    if (now <= 0 || sent->sent_at <= 0 || now < sent->sent_at)
        return;
    sample = clamp_msec((uint64_t)(now - sent->sent_at));
    if (stats->minimum_rtt_msec == 0 || sample < stats->minimum_rtt_msec)
        stats->minimum_rtt_msec = sample;
    if ((uint64_t)sample > (uint64_t)stats->minimum_rtt_msec + ack_delay_msec)
        sample -= ack_delay_msec;
    stats->latest_rtt_msec = sample;
    if (stats->smoothed_rtt_msec == 0)
        stats->smoothed_rtt_msec = sample;
    else
        stats->smoothed_rtt_msec = (uint32_t)(((uint64_t)stats->smoothed_rtt_msec * 7 + sample) / 8);
}

static int acknowledge_packet(quicly_flexicast_flow_t *flow, int member_index, uint64_t packet_number, int64_t now,
                              quicly_flexicast_feedback_t *feedback, size_t *num_completed)
{
    quicly_flexicast_sent_t *sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
    quicly_flexicast_member_stats_t *stats = &flow->members[member_index].stats;

    if (!sent->occupied || sent->packet_number != packet_number || !sent_has_member(flow, sent, (size_t)member_index))
        return 0;
    if (feedback->acked_packets == 0)
        update_rtt(stats, sent, now, feedback->ack_delay_msec);
    (void)sent_clear_member(flow, sent, (size_t)member_index);
    ++feedback->acked_packets;
    feedback->acked_bytes += sent->packet_size;
    ++stats->delivered_packets;
    stats->delivered_bytes += sent->packet_size;
    if (sent->pending_count == 0) {
        sent->occupied = 0;
        ++*num_completed;
    }
    return 1;
}

static void finish_feedback(quicly_flexicast_flow_t *flow, int member_index, quicly_flexicast_feedback_t *feedback,
                            int64_t previous_feedback_at)
{
    quicly_flexicast_member_stats_t *stats = &flow->members[member_index].stats;
    if (feedback->acked_bytes != 0 && previous_feedback_at > 0 && feedback->now > previous_feedback_at) {
        uint64_t elapsed = (uint64_t)(feedback->now - previous_feedback_at);
        uint64_t sample = feedback->acked_bytes > UINT64_MAX / 1000 ? UINT64_MAX : feedback->acked_bytes * 1000 / elapsed;
        if (stats->delivery_rate_bytes_per_second == 0)
            stats->delivery_rate_bytes_per_second = sample;
        else
            stats->delivery_rate_bytes_per_second =
                stats->delivery_rate_bytes_per_second - stats->delivery_rate_bytes_per_second / 8 + sample / 8;
    }
    if (feedback->now > 0)
        stats->last_feedback_at = feedback->now;
    if (feedback->acked_packets == 0 && feedback->lost_packets == 0 && feedback->ecn_ce_count == 0)
        return;
    feedback->epoch = ++stats->feedback_epoch;
    feedback->delivered_bytes = stats->delivered_bytes;
    feedback->delivery_rate_bytes_per_second = stats->delivery_rate_bytes_per_second;
    feedback->latest_rtt_msec = stats->latest_rtt_msec;
    feedback->minimum_rtt_msec = stats->minimum_rtt_msec;
    feedback->smoothed_rtt_msec = stats->smoothed_rtt_msec;
    quicly_flexicast_cc_on_feedback(flow->cc, feedback);
}

int quicly_flexicast_ack_at(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete, int64_t now)
{
    quicly_flexicast_feedback_t feedback = {.member_id = member_id, .largest_acknowledged = packet_number, .now = now};
    int member_index;
    size_t num_completed = 0;
    int64_t previous_feedback_at;
    quicly_flexicast_sent_t *sent;

    if (flow == NULL || complete == NULL || (member_index = find_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
    if (!sent->occupied || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!sent_has_member(flow, sent, (size_t)member_index))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    previous_feedback_at = flow->members[member_index].stats.last_feedback_at;
    (void)acknowledge_packet(flow, member_index, packet_number, now, &feedback, &num_completed);
    *complete = num_completed != 0;
    if (packet_number > flow->members[member_index].stats.largest_acknowledged)
        flow->members[member_index].stats.largest_acknowledged = packet_number;
    finish_feedback(flow, member_index, &feedback, previous_feedback_at);
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_ack(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete)
{
    return quicly_flexicast_ack_at(flow, member_id, packet_number, complete, 0);
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
                              quicly_flexicast_feedback_t *feedback, size_t *num_completed)
{
    uint64_t window_start;
    if (flow->next_packet_number == flow->first_packet_number)
        return;
    window_start = flow->next_packet_number - flow->first_packet_number > QUICLY_FLEXICAST_SENT_WINDOW
                       ? flow->next_packet_number - QUICLY_FLEXICAST_SENT_WINDOW
                       : flow->first_packet_number;
    if (largest >= flow->next_packet_number)
        largest = flow->next_packet_number - 1;
    if (smallest < window_start)
        smallest = window_start;
    if (smallest > largest)
        return;
    for (uint64_t packet_number = largest;; --packet_number) {
        (void)acknowledge_packet(flow, member_index, packet_number, now, feedback, num_completed);
        if (packet_number == smallest)
            break;
    }
}

static void retire_lost_packets(quicly_flexicast_flow_t *flow, int member_index, uint64_t largest_acknowledged,
                                quicly_flexicast_feedback_t *feedback, size_t *num_completed)
{
    uint64_t threshold = flow->cc_config.packet_reordering_threshold;
    uint64_t last_lost, cursor, window_start;

    if (largest_acknowledged < threshold)
        return;
    last_lost = largest_acknowledged - threshold;
    cursor = flow->members[member_index].loss_cursor;
    window_start = flow->next_packet_number - flow->first_packet_number > QUICLY_FLEXICAST_SENT_WINDOW
                       ? flow->next_packet_number - QUICLY_FLEXICAST_SENT_WINDOW
                       : flow->first_packet_number;
    if (cursor < window_start)
        cursor = window_start;
    if (cursor > last_lost)
        return;
    for (uint64_t packet_number = cursor;; ++packet_number) {
        quicly_flexicast_sent_t *sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
        if (sent->occupied && sent->packet_number == packet_number && sent_clear_member(flow, sent, (size_t)member_index)) {
            ++feedback->lost_packets;
            feedback->lost_bytes += sent->packet_size;
            ++flow->members[member_index].stats.lost_packets;
            flow->members[member_index].stats.lost_bytes += sent->packet_size;
            if (sent->pending_count == 0) {
                sent->occupied = 0;
                ++*num_completed;
            }
        }
        if (packet_number == last_lost)
            break;
    }
    flow->members[member_index].loss_cursor = last_lost + 1;
}

int quicly_flexicast_ack_frame_at(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame,
                                  size_t *num_acked, size_t *num_lost, size_t *num_completed, int64_t now)
{
    quicly_flexicast_feedback_t feedback = {
        .member_id = member_id, .largest_acknowledged = frame != NULL ? frame->largest_acknowledged : 0, .now = now};
    int member_index;
    uint64_t largest;
    int64_t previous_feedback_at;

    if (flow == NULL || frame == NULL || num_acked == NULL || num_lost == NULL || num_completed == NULL ||
        (member_index = find_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!validate_ack_frame(frame) || frame->largest_acknowledged >= flow->next_packet_number)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    feedback.ack_delay_msec =
        frame->ack_delay > flow->received.ack_delay_msec ? flow->received.ack_delay_msec : (uint32_t)frame->ack_delay;
    *num_acked = 0;
    *num_lost = 0;
    *num_completed = 0;
    previous_feedback_at = flow->members[member_index].stats.last_feedback_at;
    largest = frame->largest_acknowledged;
    for (uint64_t i = 0; i <= frame->num_gaps; ++i) {
        uint64_t smallest = largest - (frame->ack_block_lengths[i] - 1);
        acknowledge_range(flow, member_index, smallest, largest, now, &feedback, num_completed);
        if (i != frame->num_gaps)
            largest = smallest - frame->gaps[i] - 1;
    }
    retire_lost_packets(flow, member_index, frame->largest_acknowledged, &feedback, num_completed);
    if (frame->largest_acknowledged > flow->members[member_index].stats.largest_acknowledged)
        flow->members[member_index].stats.largest_acknowledged = frame->largest_acknowledged;
    if (frame->ecn_counts[2] > flow->members[member_index].stats.ecn_ce_count) {
        feedback.ecn_ce_count = frame->ecn_counts[2] - flow->members[member_index].stats.ecn_ce_count;
        flow->members[member_index].stats.ecn_ce_count = frame->ecn_counts[2];
    }
    *num_acked = (size_t)feedback.acked_packets;
    *num_lost = (size_t)feedback.lost_packets;
    finish_feedback(flow, member_index, &feedback, previous_feedback_at);
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_ack_frame(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame,
                               size_t *num_acked, size_t *num_completed)
{
    size_t num_lost;
    return quicly_flexicast_ack_frame_at(flow, member_id, frame, num_acked, &num_lost, num_completed, 0);
}

int quicly_flexicast_get_pending_members(const quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t *pending)
{
    const quicly_flexicast_sent_t *sent;
    if (flow == NULL || pending == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
    if (!sent->occupied || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    *pending = sent->pending_count;
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_abandon_datagram(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete)
{
    int member_index;
    quicly_flexicast_sent_t *sent;
    if (flow == NULL || complete == NULL || (member_index = find_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
    if (!sent->occupied || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!sent_has_member(flow, sent, (size_t)member_index))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    (void)sent_clear_member(flow, sent, (size_t)member_index);
    *complete = sent->pending_count == 0;
    if (*complete)
        sent->occupied = 0;
    return QUICLY_FLEXICAST_OK;
}

void quicly_flexicast_cc_set_flow_hints(quicly_flexicast_flow_t *flow, const quicly_flexicast_cc_hints_t *hints, int64_t now)
{
    if (flow != NULL)
        quicly_flexicast_cc_set_hints(flow->cc, hints, now);
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
