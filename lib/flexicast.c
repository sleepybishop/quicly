#include "quicly/flexicast.h"

#include "quicly/frame.h"

#include "flexicast_member_map.h"
#include "flexicast_cc_internal.h"

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
           action == QUICLY_FLEXICAST_STATE_LISTEN;
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
    frame->algorithm = quicly_decode64(&src);
    *consumed = src - start;
    return QUICLY_FLEXICAST_OK;
}

typedef struct st_quicly_flexicast_sent_t {
    uint64_t packet_number;
    size_t pending_count;
    size_t packet_size;
    int64_t sent_at;
    quicly_flexicast_send_context_t context;
    int has_submission;
    int rtt_untracked;
} quicly_flexicast_sent_t;

/* store only paced replica timestamp exceptions with a bounded per-flow table */
#define MAX_SUBMISSION_TIMESTAMPS 4096

typedef struct st_flexicast_submission_t {
    uint64_t packet_number;
    int64_t submitted_at;
    quicly_flexicast_send_context_t context;
    uint32_t member_slot_plus_one;
} flexicast_submission_t;

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
    flexicast_delivery_sample_t rate_sample;
    flexicast_delivery_sample_t published_rate_sample;
    uint64_t rate_sample_epoch;
    uint64_t rtt_sample_epoch;
    int64_t rtt_sample_at;
    uint32_t raw_rtt_msec, rtt_ack_delay_msec, applied_ack_delay_msec, rtt_sample_flags;
    quicly_flexicast_member_stats_t stats;
    int active;
} quicly_flexicast_member_t;

typedef struct st_quicly_flexicast_key_usage_t {
    struct st_quicly_flexicast_key_usage_t *next;
    uint8_t secret_hash[PTLS_MAX_DIGEST_SIZE];
    uint64_t encrypted_packets;
} quicly_flexicast_key_usage_t;

struct st_quicly_flexicast_flow_t {
    uint64_t flow_id;
    ptls_cipher_suite_t *cipher_suite;
    quicly_crypto_engine_t *crypto_engine;
    quicly_conn_t *crypto_conn;
    struct {
        ptls_cipher_context_t *header_protection;
        ptls_aead_context_t *aead;
    } egress, ingress;
    struct {
        uint64_t max_packets_per_key;
        uint64_t max_authentication_failures;
        uint64_t authentication_failures;
        quicly_flexicast_key_usage_t *keys;
        quicly_flexicast_key_usage_t *current_key;
    } crypto;
    uint64_t next_packet_number;
    uint64_t first_packet_number;
    size_t max_packet_size;
    int64_t app_limited_at, host_limited_at;
    struct {
        uint64_t largest;
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
    quicly_flexicast_member_t *members;
    uint32_t *free_member_slots;
    size_t num_free_member_slots;
    size_t member_slot_watermark;
    size_t max_members;
    size_t num_members;
    flexicast_member_map_t member_map;
    uint64_t *active_member_words;
    uint64_t *pending_member_words;
    size_t member_word_count;
    quicly_flexicast_cc_config_t cc_config;
    quicly_flexicast_cc_t *cc;
    flexicast_submission_t *submissions;
    size_t submission_capacity;
    size_t num_submissions;
    quicly_flexicast_sent_t sent[QUICLY_FLEXICAST_SENT_WINDOW];
};

static size_t submission_hash(uint64_t packet_number, uint32_t member_slot_plus_one)
{
    return flexicast_member_hash(packet_number ^ (UINT64_C(0x9e3779b97f4a7c15) * member_slot_plus_one));
}

static flexicast_submission_t *find_submission(quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t member_slot)
{
    if (flow->submission_capacity == 0)
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
    remove_submission(flow, sent->packet_number, member_index);
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

static int get_aead_limits(const quicly_flexicast_config_t *config, uint64_t *packets, uint64_t *failures)
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
    case 0x1304:                                  /* TLS_AES_128_CCM_SHA256 (RFC 8446 appendix B.4) */
        *packets = *failures = UINT64_C(2965820); /* floor(2^21.5) */
        break;
    default:
        /* reject suites without documented QUIC limits */
        return 0;
    }
    if (config->cipher_suite->aead->confidentiality_limit == 0 || config->cipher_suite->aead->integrity_limit == 0)
        return 0;
    if (*packets > config->cipher_suite->aead->confidentiality_limit)
        *packets = config->cipher_suite->aead->confidentiality_limit;
    if (*failures > config->cipher_suite->aead->integrity_limit)
        *failures = config->cipher_suite->aead->integrity_limit;
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
    quicly_flexicast_cc_config_t cc_config;
    uint64_t max_packets_per_key, max_authentication_failures;
    size_t max_members;
    int ret;

    if (flow == NULL || config == NULL || config->flow_id == 0 || config->flow_id > PTLS_QUICINT_MAX ||
        config->first_packet_number > PTLS_QUICINT_MAX || config->cipher_suite == NULL || config->cipher_suite->hash == NULL ||
        config->cipher_suite->hash->create == NULL || config->cipher_suite->hash->digest_size == 0 ||
        config->cipher_suite->hash->digest_size > PTLS_MAX_DIGEST_SIZE || config->cipher_suite->aead == NULL ||
        config->crypto_engine == NULL || config->crypto_engine->setup_cipher == NULL ||
        config->crypto_engine->encrypt_packet == NULL || config->traffic_secret.base == NULL ||
        config->traffic_secret.len != config->cipher_suite->hash->digest_size ||
        config->max_packet_size > QUICLY_FLEXICAST_MAX_PACKET_SIZE ||
        (config->max_packet_size != 0 && config->max_packet_size < QUICLY_FLEXICAST_DEFAULT_MAX_PACKET_SIZE))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (!get_aead_limits(config, &max_packets_per_key, &max_authentication_failures))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    max_members = config->max_members != 0 ? config->max_members : QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS;
    if (max_members > QUICLY_FLEXICAST_HARD_MAX_MEMBERS)
        return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
    *flow = NULL;
    if ((new_flow = calloc(1, sizeof(*new_flow))) == NULL)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    new_flow->flow_id = config->flow_id;
    new_flow->cipher_suite = config->cipher_suite;
    new_flow->crypto_engine = config->crypto_engine;
    new_flow->crypto_conn = config->crypto_conn;
    new_flow->crypto.max_packets_per_key = max_packets_per_key;
    new_flow->crypto.max_authentication_failures = max_authentication_failures;
    new_flow->max_packet_size = config->max_packet_size != 0 ? config->max_packet_size : QUICLY_FLEXICAST_DEFAULT_MAX_PACKET_SIZE;
    quicly_ranges_init(&new_flow->received.ack_ranges);
    new_flow->max_members = max_members;
    new_flow->member_word_count = (max_members + 63) / 64;
    if ((new_flow->members = calloc(max_members, sizeof(*new_flow->members))) == NULL ||
        (new_flow->free_member_slots = malloc(max_members * sizeof(*new_flow->free_member_slots))) == NULL ||
        flexicast_member_map_init(&new_flow->member_map, max_members) != 0 ||
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
    if (cc_config.maximum_members < max_members)
        cc_config.maximum_members = max_members;
    if (config->cc_type != NULL && !valid_cc_config(&cc_config)) {
        quicly_flexicast_flow_free(new_flow);
        return QUICLY_FLEXICAST_ERROR_INVALID;
    }
    new_flow->cc_config = cc_config;
    if ((ret = quicly_flexicast_flow_rekey(new_flow, config->traffic_secret, config->first_packet_number, config->now)) != 0) {
        quicly_flexicast_flow_free(new_flow);
        return ret;
    }
    if (config->cc_type != NULL && quicly_flexicast_cc_create(&new_flow->cc, config->cc_type, &cc_config, config->now) != 0)
        goto NoMemory;

    *flow = new_flow;
    return QUICLY_FLEXICAST_OK;

NoMemory:
    quicly_flexicast_flow_free(new_flow);
    return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
}

int quicly_flexicast_flow_rekey(quicly_flexicast_flow_t *flow, ptls_iovec_t traffic_secret, uint64_t first_packet_number,
                                int64_t now)
{
    ptls_cipher_context_t *egress_hp = NULL, *ingress_hp = NULL;
    ptls_aead_context_t *egress_aead = NULL, *ingress_aead = NULL;
    quicly_flexicast_key_usage_t *key, *new_key = NULL;
    uint8_t secret_hash[PTLS_MAX_DIGEST_SIZE];
    if (flow == NULL || traffic_secret.base == NULL || traffic_secret.len != flow->cipher_suite->hash->digest_size ||
        first_packet_number > PTLS_QUICINT_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures)
        return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
    /* keep packet numbers unique across rekeys to avoid AEAD nonce reuse */
    if (flow->egress.aead != NULL && (first_packet_number < flow->next_packet_number ||
                                      (flow->received.initialized && first_packet_number <= flow->received.largest)))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (ptls_calc_hash(flow->cipher_suite->hash, secret_hash, traffic_secret.base, traffic_secret.len) != 0)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    for (key = flow->crypto.keys; key != NULL; key = key->next)
        if (ptls_mem_equal(key->secret_hash, secret_hash, flow->cipher_suite->hash->digest_size))
            break;
    if (key == NULL) {
        if ((new_key = calloc(1, sizeof(*new_key))) == NULL) {
            ptls_clear_memory(secret_hash, sizeof(secret_hash));
            return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
        }
        key = new_key;
        memcpy(key->secret_hash, secret_hash, flow->cipher_suite->hash->digest_size);
    }
    ptls_clear_memory(secret_hash, sizeof(secret_hash));
    if (key->encrypted_packets >= flow->crypto.max_packets_per_key)
        return QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED;
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
    if (new_key != NULL) {
        new_key->next = flow->crypto.keys;
        flow->crypto.keys = new_key;
    }
    flow->crypto.current_key = key;
    flow->first_packet_number = first_packet_number;
    flow->next_packet_number = first_packet_number;
    flow->app_limited_at = flow->host_limited_at = 0;
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
    memset(flow->sent, 0, sizeof(flow->sent));
    if (flow->submissions != NULL)
        memset(flow->submissions, 0, flow->submission_capacity * sizeof(*flow->submissions));
    flow->num_submissions = 0;
    memset(flow->pending_member_words, 0,
           QUICLY_FLEXICAST_SENT_WINDOW * flow->member_word_count * sizeof(*flow->pending_member_words));
    memset(flow->active_member_words, 0, flow->member_word_count * sizeof(*flow->active_member_words));
    flow->num_members = 0;
    for (size_t i = 0; i != flow->member_slot_watermark; ++i) {
        if (flow->members[i].stats.member_id == 0)
            continue;
        if (flow->members[i].active)
            quicly_flexicast_cc_on_member_suspended(flow->cc, flow->members[i].stats.member_id, now);
        flow->members[i].active = 0;
        flow->members[i].loss_cursor = first_packet_number;
        flow->members[i].stats.largest_acknowledged = 0;
        flow->members[i].stats.last_feedback_at = 0;
        flow->members[i].rate_sample = (flexicast_delivery_sample_t){0};
        flow->members[i].published_rate_sample = (flexicast_delivery_sample_t){0};
        flow->members[i].rate_sample_epoch = 0;
        flow->members[i].rtt_sample_epoch = 0;
        flow->members[i].rtt_sample_at = 0;
        flow->members[i].rtt_sample_flags = 0;
        flow->members[i].raw_rtt_msec = 0;
        flow->members[i].rtt_ack_delay_msec = 0;
        flow->members[i].applied_ack_delay_msec = 0;
        /* ECN counters are cumulative within this key epoch */
        flow->members[i].stats.ecn_ce_count = 0;
    }
    /* preserve learned path rates and reset controller liveness on rekey */
    quicly_flexicast_cc_on_epoch_reset(flow->cc, now);
    return QUICLY_FLEXICAST_OK;

Error:
    if (new_key != NULL) {
        ptls_clear_memory(new_key, sizeof(*new_key));
        free(new_key);
    }
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
    while (flow->crypto.keys != NULL) {
        quicly_flexicast_key_usage_t *key = flow->crypto.keys;
        flow->crypto.keys = key->next;
        ptls_clear_memory(key, sizeof(*key));
        free(key);
    }
    if (flow->members != NULL) {
        ptls_clear_memory(flow->members, flow->max_members * sizeof(*flow->members));
        free(flow->members);
    }
    free(flow->submissions);
    free(flow->free_member_slots);
    flexicast_member_map_dispose(&flow->member_map);
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
    int index = flexicast_member_map_find(&flow->member_map, member_id);
    return index >= 0 && flow->members[index].active ? index : -1;
}

static int find_known_member(const quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    return flexicast_member_map_find(&flow->member_map, member_id);
}

static uint64_t sent_window_start(const quicly_flexicast_flow_t *flow)
{
    return flow->next_packet_number - flow->first_packet_number > QUICLY_FLEXICAST_SENT_WINDOW
               ? flow->next_packet_number - QUICLY_FLEXICAST_SENT_WINDOW
               : flow->first_packet_number;
}

int quicly_flexicast_attach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int index;
    if (flow == NULL || member_id == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    index = find_known_member(flow, member_id);
    if (index < 0) {
        if (flow->num_free_member_slots == 0)
            return QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT;
        index = flow->free_member_slots[--flow->num_free_member_slots];
        if ((size_t)index + 1 > flow->member_slot_watermark)
            flow->member_slot_watermark = (size_t)index + 1;
        flow->members[index].stats.member_id = member_id;
        flexicast_member_map_set(&flow->member_map, member_id, (size_t)index);
    }
    if (!flow->members[index].active) {
        quicly_flexicast_cc_on_member_added(flow->cc, member_id, now);
        flow->members[index].active = 1;
        flow->members[index].loss_cursor = flow->next_packet_number;
        set_member_active(flow, (size_t)index, 1);
        ++flow->num_members;
    }
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_attach(quicly_flexicast_flow_t *flow, uint64_t member_id)
{
    return quicly_flexicast_attach_at(flow, member_id, 0);
}

int quicly_flexicast_detach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now)
{
    int member_index;
    uint64_t cursor, window_start;
    if (flow == NULL || member_id == 0)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((member_index = find_known_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_cc_on_member_removed(flow->cc, member_id, now);
    if (flow->members[member_index].active) {
        set_member_active(flow, (size_t)member_index, 0);
        --flow->num_members;
    }
    cursor = flow->members[member_index].loss_cursor;
    flexicast_member_map_remove(&flow->member_map, member_id);
    memset(&flow->members[member_index], 0, sizeof(flow->members[member_index]));
    flow->free_member_slots[flow->num_free_member_slots++] = (uint32_t)member_index;
    window_start = sent_window_start(flow);
    if (cursor < window_start)
        cursor = window_start;
    for (; cursor < flow->next_packet_number; ++cursor) {
        quicly_flexicast_sent_t *sent = flow->sent + cursor % QUICLY_FLEXICAST_SENT_WINDOW;
        if (sent->pending_count != 0 && sent->packet_number == cursor)
            (void)sent_clear_member(flow, sent, (size_t)member_index);
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

size_t quicly_flexicast_datagram_size(const quicly_flexicast_flow_t *flow, size_t payload_size)
{
    size_t size;
    if (flow == NULL || payload_size > QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE)
        return 0;
    size = 1 + QUICLY_FLEXICAST_FLOW_ID_SIZE + QUICLY_SEND_PN_SIZE +
           quicly_datagram_frame_capacity(ptls_iovec_init(NULL, payload_size)) + flow->egress.aead->algo->tag_size;
    return size <= flow->max_packet_size ? size : 0;
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
        flow->next_packet_number > PTLS_QUICINT_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if (flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures)
        return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
    if (flow->num_members == 0)
        return QUICLY_FLEXICAST_ERROR_NO_MEMBERS;
    if (flow->crypto.current_key->encrypted_packets >= flow->crypto.max_packets_per_key)
        return QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED;
    required = quicly_flexicast_datagram_size(flow, payload.len);
    if (required == 0 || required > packet_capacity)
        return QUICLY_FLEXICAST_ERROR_INVALID;

    pn = flow->next_packet_number;
    sent = flow->sent + pn % QUICLY_FLEXICAST_SENT_WINDOW;
    if (sent->pending_count != 0 && sent->packet_number != pn)
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
    ++flow->crypto.current_key->encrypted_packets;

    sent->packet_number = pn;
    memcpy(sent_member_words(flow, sent), flow->active_member_words, flow->member_word_count * sizeof(*flow->active_member_words));
    sent->pending_count = flow->num_members;
    sent->packet_size = dst - packet;
    sent->sent_at = now;
    sent->context = (quicly_flexicast_send_context_t){.flags = QUICLY_FLEXICAST_SAMPLE_PRESENT};
    sent->has_submission = 0;
    sent->rtt_untracked = 0;
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

int quicly_flexicast_mark_submitted(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int64_t now)
{
    return quicly_flexicast_mark_submitted_with_context(flow, member_id, packet_number, now, NULL);
}

static int same_send_context(const quicly_flexicast_send_context_t *a, const quicly_flexicast_send_context_t *b)
{
    return a->pacing_rate_bytes_per_second == b->pacing_rate_bytes_per_second && a->physical_fanout == b->physical_fanout &&
           a->flags == b->flags;
}

int quicly_flexicast_mark_submitted_with_context(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number,
                                                 int64_t now, const quicly_flexicast_send_context_t *context)
{
    if (flow == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    quicly_flexicast_sent_t *sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
    if (sent->pending_count == 0 || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    int member_index = member_id != 0 ? find_member(flow, member_id) : -1;
    if (member_id != 0 && (member_index < 0 || !sent_has_member(flow, sent, (size_t)member_index)))
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    quicly_flexicast_send_context_t normalized = context != NULL ? *context : (quicly_flexicast_send_context_t){0};
    normalized.flags |= QUICLY_FLEXICAST_SAMPLE_PRESENT;
    /* preserve limitation watermarks even if the flagged packet is lost */
    if ((normalized.flags & QUICLY_FLEXICAST_SAMPLE_APP_LIMITED) && now > flow->app_limited_at)
        flow->app_limited_at = now;
    if ((normalized.flags & QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED) && now > flow->host_limited_at)
        flow->host_limited_at = now;
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
    return QUICLY_FLEXICAST_OK;
}

static int decode_header(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, uint64_t *packet_number,
                         size_t *payload_from)
{
    size_t pn_offset = 1 + QUICLY_FLEXICAST_FLOW_ID_SIZE, pn_length, i, plaintext_size;
    const uint8_t *flow_id_at;
    uint8_t mask[5] = {0};
    uint32_t truncated = 0;
    uint64_t expected, wire_flow_id;

    if (flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures)
        return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
    if (packet_size > QUICLY_FLEXICAST_MAX_PACKET_SIZE ||
        packet_size < pn_offset + QUICLY_MAX_PN_SIZE + flow->ingress.header_protection->algo->iv_size ||
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
    for (i = 0; i != pn_length; ++i) {
        packet[pn_offset + i] ^= mask[i + 1];
        truncated = (truncated << 8) | packet[pn_offset + i];
    }
    expected = flow->received.initialized ? flow->received.largest + 1 : flow->first_packet_number;
    *packet_number = quicly_determine_packet_number(truncated, pn_length * 8, expected);
    *payload_from = pn_offset + pn_length;
    plaintext_size = ptls_aead_decrypt(flow->ingress.aead, packet + *payload_from, packet + *payload_from,
                                       packet_size - *payload_from, *packet_number, packet, *payload_from);
    if (plaintext_size == SIZE_MAX) {
        if (++flow->crypto.authentication_failures >= flow->crypto.max_authentication_failures)
            return QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED;
        return QUICLY_FLEXICAST_ERROR_CRYPTO;
    }
    if (*packet_number > PTLS_QUICINT_MAX)
        return QUICLY_FLEXICAST_ERROR_INVALID;
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

/* validate packet frames before exposing payloads or committing receive state */
static int decode_datagrams(const uint8_t *src, const uint8_t *end, ptls_iovec_t *payloads, size_t capacity, size_t *count,
                            int *ack_eliciting)
{
    uint64_t frame_type;
    quicly_datagram_frame_t frame;
    *count = 0;
    *ack_eliciting = 0;
    if (src == end)
        return QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION;
    while (src != end) {
        if ((frame_type = quicly_decodev(&src, end)) == UINT64_MAX)
            return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
        switch (frame_type) {
        case QUICLY_FRAME_TYPE_PADDING:
            break;
        case QUICLY_FRAME_TYPE_PING:
            *ack_eliciting = 1;
            break;
        case QUICLY_FRAME_TYPE_DATAGRAM_NOLEN:
        case QUICLY_FRAME_TYPE_DATAGRAM_WITHLEN:
            if (quicly_decode_datagram_frame(frame_type, &src, end, &frame) != 0)
                return QUICLY_FLEXICAST_ERROR_FRAME_ENCODING;
            if (*count < capacity)
                payloads[*count] = frame.payload;
            ++*count;
            *ack_eliciting = 1;
            break;
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
    return QUICLY_FLEXICAST_OK;
}

static int do_receive_datagrams(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payloads,
                                size_t *num_payloads, uint64_t *packet_number, int64_t now, uint8_t ecn)
{
    size_t payload_from, count;
    int plaintext_size, ret, ack_eliciting;
    ptls_iovec_t scratch_payloads[64];

    if (flow == NULL || packet == NULL || num_payloads == NULL || packet_number == NULL || (payloads == NULL && *num_payloads != 0))
        return QUICLY_FLEXICAST_ERROR_INVALID;
    if ((plaintext_size = decode_header(flow, packet, packet_size, packet_number, &payload_from)) < 0)
        return plaintext_size;
    /* filter replays after authenticating packet numbers */
    if (*packet_number < flow->first_packet_number || is_replayed_packet(flow, *packet_number))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    const uint8_t *src = packet + payload_from, *end = src + plaintext_size;
    if ((ret = decode_datagrams(src, end, scratch_payloads, PTLS_ELEMENTSOF(scratch_payloads), &count, &ack_eliciting)) != 0)
        return ret;
    size_t capacity = *num_payloads;
    *num_payloads = count;
    if (count > capacity)
        return QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL;
    int is_pending_largest = flow->received.ack_ranges.num_ranges == 0 ||
                             *packet_number >= flow->received.ack_ranges.ranges[flow->received.ack_ranges.num_ranges - 1].end;
    size_t previous_num_ranges = flow->received.ack_ranges.num_ranges;
    if (quicly_ranges_add(&flow->received.ack_ranges, *packet_number, *packet_number + 1) != 0)
        return QUICLY_FLEXICAST_ERROR_NO_MEMORY;
    if (flow->received.ack_ranges.num_ranges > previous_num_ranges &&
        flow->received.ack_ranges_since_ack < QUICLY_MAX_ACK_BLOCKS)
        ++flow->received.ack_ranges_since_ack;
    /* bound receive history to the newest ranges */
    if (flow->received.ack_ranges.num_ranges > QUICLY_FLEXICAST_SENT_WINDOW)
        quicly_ranges_drop_by_range_indices(&flow->received.ack_ranges, 0,
                                            flow->received.ack_ranges.num_ranges - QUICLY_FLEXICAST_SENT_WINDOW);
    /* update replay window only after ACK range allocation succeeds */
    update_replay_window(flow, *packet_number);
    if (is_pending_largest)
        flow->received.largest_received_at = now;
    if ((ecn &= 3) != 0) {
        size_t index = ecn == 2 ? 0 : ecn == 1 ? 1 : 2;
        if (flow->received.ecn_counts[index] < PTLS_QUICINT_MAX)
            ++flow->received.ecn_counts[index];
    }
    if (ack_eliciting && flow->received.ack_eliciting_since_ack++ == 0)
        flow->received.ack_pending_since = now;
    if (count <= PTLS_ELEMENTSOF(scratch_payloads)) {
        if (count != 0)
            memcpy(payloads, scratch_payloads, count * sizeof(*payloads));
    } else {
        (void)decode_datagrams(src, end, payloads, capacity, &count, &ack_eliciting);
    }
    return QUICLY_FLEXICAST_OK;
}

int quicly_flexicast_receive_datagrams_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size,
                                          ptls_iovec_t *payloads, size_t *num_payloads, uint64_t *packet_number, int64_t now)
{
    return do_receive_datagrams(flow, packet, packet_size, payloads, num_payloads, packet_number, now, 0);
}

int quicly_flexicast_receive_datagram_ecn_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size,
                                             ptls_iovec_t *payload, uint64_t *packet_number, int64_t now, uint8_t ecn)
{
    if (payload == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    size_t count = 1;
    int ret = do_receive_datagrams(flow, packet, packet_size, payload, &count, packet_number, now, ecn);
    if (ret == 0 && count == 0)
        *payload = ptls_iovec_init(NULL, 0);
    return ret;
}

int quicly_flexicast_receive_datagram_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                         uint64_t *packet_number, int64_t now)
{
    return quicly_flexicast_receive_datagram_ecn_at(flow, packet, packet_size, payload, packet_number, now, 0);
}

int quicly_flexicast_receive_datagram(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                      uint64_t *packet_number)
{
    return quicly_flexicast_receive_datagram_at(flow, packet, packet_size, payload, packet_number, 0);
}

int64_t quicly_flexicast_get_ack_deadline(const quicly_flexicast_flow_t *flow)
{
    if (flow == NULL || flow->received.ack_ranges.num_ranges == 0 || flow->received.ack_eliciting_since_ack == 0)
        return INT64_MAX;
    if (flow->received.ack_pending_since > INT64_MAX - flow->received.ack_delay_msec)
        return INT64_MAX;
    return flow->received.ack_pending_since + flow->received.ack_delay_msec;
}

int quicly_flexicast_ack_is_due(const quicly_flexicast_flow_t *flow, int64_t now)
{
    int64_t deadline;
    if (flow == NULL || flow->received.ack_ranges.num_ranges == 0 || flow->received.ack_eliciting_since_ack == 0)
        return 0;
    if (flow->received.ack_frames_sent == 0 || flow->received.ack_eliciting_since_ack >= flow->received.ack_frequency ||
        flow->received.ack_ranges_since_ack >= QUICLY_MAX_ACK_BLOCKS)
        return 1;
    deadline = quicly_flexicast_get_ack_deadline(flow);
    return deadline != INT64_MAX && now >= deadline;
}

int quicly_flexicast_encode_pending_ack(quicly_flexicast_flow_t *flow, uint8_t *dst, size_t capacity, int64_t now,
                                        size_t *encoded_size)
{
    uint8_t *end;
    uint64_t ack_delay = 0;
    quicly_ranges_t ranges;
    if (flow == NULL || dst == NULL || encoded_size == NULL || flow->received.ack_ranges.num_ranges == 0 || capacity < 2)
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
    if ((end = quicly_encode_path_ack_frame(dst, dst + capacity - 1, flow->flow_id, &ranges, flow->received.ecn_counts,
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
    /* retain only the newest ACK blocks */
    if (flow->received.ack_ranges.num_ranges > QUICLY_MAX_ACK_BLOCKS)
        quicly_ranges_drop_by_range_indices(&flow->received.ack_ranges, 0,
                                            flow->received.ack_ranges.num_ranges - QUICLY_MAX_ACK_BLOCKS);
    flow->received.ack_eliciting_since_ack = 0;
    flow->received.ack_ranges_since_ack = 0;
    flow->received.ack_pending_since = 0;
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
    member->rtt_sample_flags = QUICLY_FLEXICAST_RTT_PRESENT | QUICLY_FLEXICAST_RTT_VALID;
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
                              size_t *num_completed)
{
    quicly_flexicast_sent_t *sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
    quicly_flexicast_member_stats_t *stats = &flow->members[member_index].stats;

    if (sent->pending_count == 0 || sent->packet_number != packet_number || !sent_has_member(flow, sent, (size_t)member_index))
        return 0;
    flexicast_submission_t *submission = find_submission(flow, packet_number, (size_t)member_index);
    int64_t submitted_at = submission != NULL ? submission->submitted_at : sent->rtt_untracked ? 0 : sent->sent_at;
    quicly_flexicast_send_context_t context = submission != NULL ? submission->context : sent->context;
    int timestamp_valid = submitted_at > 0 && now >= submitted_at;
    if (!timestamp_valid)
        context.flags &= ~QUICLY_FLEXICAST_SAMPLE_VALID;
    merge_send_context(&observation->context, &context, observation->bytes == 0);
    observation->timestamps_valid = observation->bytes == 0 ? timestamp_valid : observation->timestamps_valid && timestamp_valid;
    if (observation->bytes == 0 || submitted_at < observation->sent_at_start)
        observation->sent_at_start = submitted_at;
    if (submitted_at > observation->sent_at_end)
        observation->sent_at_end = submitted_at;
    observation->bytes += sent->packet_size;
    /* update RTT only for the frame's largest PN */
    if (packet_number == feedback->largest_acknowledged)
        update_rtt(flow->members + member_index, submitted_at, now, feedback->ack_delay_msec);
    (void)sent_clear_member(flow, sent, (size_t)member_index);
    ++feedback->acked_packets;
    feedback->acked_bytes += sent->packet_size;
    ++stats->delivered_packets;
    stats->delivered_bytes += sent->packet_size;
    if (sent->pending_count == 0)
        ++*num_completed;
    return 1;
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
            /* mark intervals whose send start precedes limitation watermarks */
            if (flow->app_limited_at > 0 && bucket->sent_at_start <= flow->app_limited_at)
                bucket->context.flags |= QUICLY_FLEXICAST_SAMPLE_APP_LIMITED;
            if (flow->host_limited_at > 0 && bucket->sent_at_start <= flow->host_limited_at)
                bucket->context.flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
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
}

static void finish_feedback(quicly_flexicast_flow_t *flow, int member_index, quicly_flexicast_feedback_t *feedback,
                            const flexicast_delivery_sample_t *observation)
{
    quicly_flexicast_member_t *member = flow->members + member_index;
    quicly_flexicast_member_stats_t *stats = &member->stats;
    if (feedback->acked_packets == 0 && feedback->lost_packets == 0 && feedback->ecn_ce_count == 0)
        return;
    sample_delivery_rate(flow, member, observation, feedback->now);
    if (feedback->now > 0)
        stats->last_feedback_at = feedback->now;
    feedback->epoch = ++stats->feedback_epoch;
    feedback->delivered_bytes = stats->delivered_bytes;
    /* publish sample epoch only for completed buckets in this key epoch */
    feedback->delivery_rate_sample_epoch = member->rate_sample_epoch;
    const flexicast_delivery_sample_t *sample = &member->published_rate_sample;
    feedback->delivery_rate_bytes_per_second = sample->rate;
    feedback->delivery_sample_flags = sample->context.flags | QUICLY_FLEXICAST_SAMPLE_PRESENT;
    feedback->delivery_sample_fanout = sample->context.physical_fanout;
    feedback->delivery_sample_pacing_rate_bytes_per_second = sample->context.pacing_rate_bytes_per_second;
    feedback->delivery_sample_bytes = sample->bytes;
    feedback->delivery_sample_sent_at_start = sample->sent_at_start;
    feedback->delivery_sample_sent_at_end = sample->sent_at_end;
    feedback->delivery_sample_acked_at_start = sample->acked_at_start;
    feedback->delivery_sample_acked_at_end = sample->acked_at_end;
    feedback->latest_rtt_msec = stats->latest_rtt_msec;
    feedback->minimum_rtt_msec = stats->minimum_rtt_msec;
    feedback->smoothed_rtt_msec = stats->smoothed_rtt_msec;
    feedback->rtt_sample_epoch = member->rtt_sample_epoch;
    feedback->rtt_sample_at = member->rtt_sample_at;
    feedback->raw_rtt_msec = member->raw_rtt_msec;
    feedback->rtt_ack_delay_msec = member->rtt_ack_delay_msec;
    feedback->applied_ack_delay_msec = member->applied_ack_delay_msec;
    feedback->rtt_sample_flags = member->rtt_sample_flags | QUICLY_FLEXICAST_RTT_PRESENT;
    quicly_flexicast_cc_on_feedback(flow->cc, feedback);
}

static void retire_lost_packets(quicly_flexicast_flow_t *flow, int member_index, uint64_t largest_acknowledged,
                                quicly_flexicast_feedback_t *feedback, size_t *num_completed);

int quicly_flexicast_ack_at(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete, int64_t now)
{
    quicly_flexicast_feedback_t feedback = {.member_id = member_id, .largest_acknowledged = packet_number, .now = now};
    flexicast_delivery_sample_t observation = {0};
    int member_index;
    size_t num_completed = 0;
    quicly_flexicast_sent_t *sent;

    if (flow == NULL || complete == NULL || (member_index = find_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
    if (sent->pending_count == 0 || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!sent_has_member(flow, sent, (size_t)member_index))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    (void)acknowledge_packet(flow, member_index, packet_number, now, &feedback, &observation, &num_completed);
    *complete = num_completed != 0;
    retire_lost_packets(flow, member_index, packet_number, &feedback, &num_completed);
    if (packet_number > flow->members[member_index].stats.largest_acknowledged)
        flow->members[member_index].stats.largest_acknowledged = packet_number;
    finish_feedback(flow, member_index, &feedback, &observation);
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
                              quicly_flexicast_feedback_t *feedback, flexicast_delivery_sample_t *observation,
                              size_t *num_completed)
{
    uint64_t window_start;
    if (flow->next_packet_number == flow->first_packet_number)
        return;
    window_start = sent_window_start(flow);
    if (largest >= flow->next_packet_number)
        largest = flow->next_packet_number - 1;
    if (smallest < window_start)
        smallest = window_start;
    if (smallest > largest)
        return;
    for (uint64_t packet_number = largest;; --packet_number) {
        (void)acknowledge_packet(flow, member_index, packet_number, now, feedback, observation, num_completed);
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
    window_start = sent_window_start(flow);
    if (cursor < window_start)
        cursor = window_start;
    if (cursor > last_lost)
        return;
    for (uint64_t packet_number = cursor;; ++packet_number) {
        quicly_flexicast_sent_t *sent = flow->sent + packet_number % QUICLY_FLEXICAST_SENT_WINDOW;
        if (sent->pending_count != 0 && sent->packet_number == packet_number &&
            sent_clear_member(flow, sent, (size_t)member_index)) {
            ++feedback->lost_packets;
            feedback->lost_bytes += sent->packet_size;
            ++flow->members[member_index].stats.lost_packets;
            flow->members[member_index].stats.lost_bytes += sent->packet_size;
            if (sent->pending_count == 0)
                ++*num_completed;
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
    flexicast_delivery_sample_t observation = {0};
    int member_index;
    uint64_t largest;

    if (flow == NULL || frame == NULL || num_acked == NULL || num_lost == NULL || num_completed == NULL ||
        (member_index = find_member(flow, member_id)) < 0)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!validate_ack_frame(frame) || frame->largest_acknowledged >= flow->next_packet_number)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    *num_acked = 0;
    *num_lost = 0;
    *num_completed = 0;
    /* ignore stale feedback from previous key epochs */
    if (frame->largest_acknowledged < flow->first_packet_number)
        return QUICLY_FLEXICAST_OK;
    /* clamp ACK delay in milliseconds */
    feedback.ack_delay_msec = clamp_msec(frame->ack_delay);
    largest = frame->largest_acknowledged;
    for (uint64_t i = 0; i <= frame->num_gaps; ++i) {
        uint64_t smallest = largest - (frame->ack_block_lengths[i] - 1);
        acknowledge_range(flow, member_index, smallest, largest, now, &feedback, &observation, num_completed);
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
    finish_feedback(flow, member_index, &feedback, &observation);
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
    if (sent->pending_count == 0 || sent->packet_number != packet_number)
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
    if (sent->pending_count == 0 || sent->packet_number != packet_number)
        return QUICLY_FLEXICAST_ERROR_NOT_FOUND;
    if (!sent_has_member(flow, sent, (size_t)member_index))
        return QUICLY_FLEXICAST_ERROR_REPLAY;
    (void)sent_clear_member(flow, sent, (size_t)member_index);
    *complete = sent->pending_count == 0;
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

int quicly_flexicast_cc_enable_flow_trace(quicly_flexicast_flow_t *flow, size_t capacity)
{
    return quicly_flexicast_cc_enable_trace(flow != NULL ? flow->cc : NULL, capacity);
}

void quicly_flexicast_cc_disable_flow_trace(quicly_flexicast_flow_t *flow)
{
    quicly_flexicast_cc_disable_trace(flow != NULL ? flow->cc : NULL);
}

size_t quicly_flexicast_cc_read_flow_trace(quicly_flexicast_flow_t *flow, quicly_flexicast_cc_trace_event_t *events,
                                           size_t capacity, uint64_t *overwritten)
{
    return quicly_flexicast_cc_read_trace(flow != NULL ? flow->cc : NULL, events, capacity, overwritten);
}
