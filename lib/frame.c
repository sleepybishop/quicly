/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <assert.h>
#include <string.h>
#include "quicly/frame.h"

uint8_t *quicly_encode_path_challenge_frame(uint8_t *dst, int is_response, const uint8_t *data)
{
    *dst++ = is_response ? QUICLY_FRAME_TYPE_PATH_RESPONSE : QUICLY_FRAME_TYPE_PATH_CHALLENGE;
    memcpy(dst, data, QUICLY_PATH_CHALLENGE_DATA_LEN);
    dst += QUICLY_PATH_CHALLENGE_DATA_LEN;
    return dst;
}

static uint8_t *encode_ack_frame_core(uint8_t *dst, uint8_t *dst_end, uint8_t frame_type, quicly_ranges_t *ranges,
                                      uint64_t *ecn_counts, uint64_t ack_delay)
{
#define WRITE_BLOCK(start, end)                                                                                                    \
    do {                                                                                                                           \
        uint64_t _start = (start), _end = (end);                                                                                   \
        assert(_start < _end);                                                                                                     \
        if (dst_end - dst < quicly_encodev_capacity(_end - _start - 1))                                                            \
            return NULL;                                                                                                           \
        dst = quicly_encodev(dst, _end - _start - 1);                                                                              \
    } while (0)

    size_t range_index = ranges->num_ranges - 1;

    assert(ranges->num_ranges != 0);
    if (ranges->num_ranges > QUICLY_MAX_ACK_BLOCKS ||
        (size_t)(dst_end - dst) <
            quicly_encodev_capacity(ranges->ranges[range_index].end - 1) + quicly_encodev_capacity(ack_delay) + 1)
        return NULL;
    dst = quicly_encodev(dst, ranges->ranges[range_index].end - 1); /* largest acknowledged */
    dst = quicly_encodev(dst, ack_delay);                           /* ack delay */
    PTLS_BUILD_ASSERT(QUICLY_MAX_ACK_BLOCKS - 1 <= 63);
    *dst++ = (uint8_t)(ranges->num_ranges - 1); /* ack blocks */

    while (1) {
        WRITE_BLOCK(ranges->ranges[range_index].start, ranges->ranges[range_index].end); /* ACK block count */
        if (range_index-- == 0)
            break;
        WRITE_BLOCK(ranges->ranges[range_index].end, ranges->ranges[range_index + 1].start);
    }

    if (frame_type == QUICLY_FRAME_TYPE_ACK_ECN || frame_type == QUICLY_FRAME_TYPE_PATH_ACK_ECN) {
        uint8_t buf[24], *p = buf;
        for (size_t i = 0; i < 3; ++i)
            p = quicly_encodev(p, ecn_counts[i]);
        size_t len = p - buf;
        if (dst_end - dst < len)
            return NULL;
        memcpy(dst, buf, len);
        dst += len;
    }

    return dst;

#undef WRITE_BLOCK
}

uint8_t *quicly_encode_ack_frame(uint8_t *dst, uint8_t *dst_end, quicly_ranges_t *ranges, uint64_t *ecn_counts, uint64_t ack_delay)
{
    /* emit ACK_ECN frame if any of the three ECN counts are non-zero */
    uint8_t frame_type = (ecn_counts[0] | ecn_counts[1] | ecn_counts[2]) != 0 ? QUICLY_FRAME_TYPE_ACK_ECN : QUICLY_FRAME_TYPE_ACK;
    if (dst_end - dst < 1)
        return NULL;
    *dst++ = frame_type;
    return encode_ack_frame_core(dst, dst_end, frame_type, ranges, ecn_counts, ack_delay);
}

uint8_t *quicly_encode_path_ack_frame(uint8_t *dst, uint8_t *dst_end, uint64_t path_id, quicly_ranges_t *ranges,
                                      uint64_t *ecn_counts, uint64_t ack_delay)
{
    /* emit PATH_ACK_ECN frame if any of the three ECN counts are non-zero */
    uint8_t frame_type =
        (ecn_counts[0] | ecn_counts[1] | ecn_counts[2]) != 0 ? QUICLY_FRAME_TYPE_PATH_ACK_ECN : QUICLY_FRAME_TYPE_PATH_ACK;
    size_t path_id_len = quicly_encodev_capacity(path_id);
    if ((size_t)(dst_end - dst) < 1 + path_id_len)
        return NULL;
    *dst++ = frame_type;
    dst = quicly_encodev(dst, path_id);
    return encode_ack_frame_core(dst, dst_end, frame_type, ranges, ecn_counts, ack_delay);
}

quicly_error_t quicly_decode_ack_frame(const uint8_t **src, const uint8_t *end, quicly_ack_frame_t *frame, int is_ack_ecn)
{
    uint64_t i, num_gaps, gap, ack_range, smallest;

    if ((frame->largest_acknowledged = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((frame->ack_delay = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((num_gaps = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;

    if ((ack_range = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if (frame->largest_acknowledged < ack_range)
        goto Error;
    frame->smallest_acknowledged = frame->largest_acknowledged - ack_range;
    smallest = frame->smallest_acknowledged;
    frame->ack_block_lengths[0] = ack_range + 1;
    frame->num_gaps = 0;

    for (i = 0; i != num_gaps; ++i) {
        if ((gap = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
        if ((ack_range = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
        /* even ranges that do not fit in output must be well formed */
        if (smallest < gap + ack_range + 2)
            goto Error;
        smallest -= gap + ack_range + 2;
        if (i < QUICLY_ACK_MAX_GAPS) {
            frame->gaps[i] = gap + 1;
            frame->ack_block_lengths[i + 1] = ack_range + 1;
            frame->smallest_acknowledged = smallest;
            ++frame->num_gaps;
        }
    }

    if (is_ack_ecn) {
        for (i = 0; i < PTLS_ELEMENTSOF(frame->ecn_counts); ++i)
            if ((frame->ecn_counts[i] = quicly_decodev(src, end)) == UINT64_MAX)
                goto Error;
    } else {
        for (i = 0; i < PTLS_ELEMENTSOF(frame->ecn_counts); ++i)
            frame->ecn_counts[i] = 0;
    }

    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

static size_t encode_close_frame(uint8_t *const base, uint64_t error_code, uint64_t offending_frame_type, const char *reason_phrase)
{
    size_t offset = 0, reason_phrase_len = strlen(reason_phrase);

#define PUSHV(v)                                                                                                                   \
    do {                                                                                                                           \
        if (base != NULL) {                                                                                                        \
            offset = quicly_encodev(base + offset, (v)) - base;                                                                    \
        } else {                                                                                                                   \
            offset += quicly_encodev_capacity(v);                                                                                  \
        }                                                                                                                          \
    } while (0)

    PUSHV(offending_frame_type == UINT64_MAX ? QUICLY_FRAME_TYPE_APPLICATION_CLOSE : QUICLY_FRAME_TYPE_TRANSPORT_CLOSE);
    PUSHV(error_code);
    if (offending_frame_type != UINT64_MAX)
        PUSHV(offending_frame_type);
    PUSHV(reason_phrase_len);
    if (base != NULL)
        memcpy(base + offset, reason_phrase, reason_phrase_len);
    offset += reason_phrase_len;

#undef PUSHV

    return offset;
}

size_t quicly_close_frame_capacity(uint64_t error_code, uint64_t offending_frame_type, const char *reason_phrase)
{
    return encode_close_frame(NULL, error_code, offending_frame_type, reason_phrase);
}

uint8_t *quicly_encode_close_frame(uint8_t *const base, uint64_t error_code, uint64_t offending_frame_type,
                                   const char *reason_phrase)
{
    return base + encode_close_frame(base, error_code, offending_frame_type, reason_phrase);
}

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
