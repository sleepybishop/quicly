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
#include "quicly/frame.h"
#include "test.h"

static void test_ack_decode_underflow(void)
{
    quicly_ack_frame_t decoded;

    { /* ack pn=0 */
        const uint8_t pat[] = {0, 0, 0, 0}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0);
        ok(decoded.num_gaps == 0);
        ok(decoded.ack_block_lengths[0] == 1);
        ok(decoded.smallest_acknowledged == 0);
    }
    { /* underflow in first block length */
        const uint8_t pat[] = {0, 0, 0, 1}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) != 0);
    }

    { /* frame with gap going down to pn=0 */
        const uint8_t pat[] = {2, 0, 1, 0, 0, 0}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 2);
        ok(decoded.num_gaps == 1);
        ok(decoded.ack_block_lengths[0] == 1);
        ok(decoded.ack_block_lengths[1] == 1);
        ok(decoded.smallest_acknowledged == 0);
    }

    { /* additional block length going negative */
        const uint8_t pat[] = {2, 0, 1, 0, 0, 1}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) != 0);
    }
    { /* gap going negative */
        const uint8_t pat[] = {2, 0, 1, 0, 3, 0}, *src = pat;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) != 0);
    }
    { /* ranges beyond the retained limit must still be checked for underflow */
        uint8_t pat[2 * QUICLY_ACK_MAX_GAPS + 32], *end = pat;
        const uint8_t *src = pat;
        end = quicly_encodev(end, 2 * QUICLY_ACK_MAX_GAPS);
        end = quicly_encodev(end, 0);
        end = quicly_encodev(end, QUICLY_ACK_MAX_GAPS + 1);
        end = quicly_encodev(end, 0);
        for (size_t i = 0; i != QUICLY_ACK_MAX_GAPS + 1; ++i) {
            end = quicly_encodev(end, 0);
            end = quicly_encodev(end, 0);
        }
        ok(quicly_decode_ack_frame(&src, end, &decoded, 0) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }
}

static void test_ack_decode(void)
{
    {
        const uint8_t pat[] = {0x34, 0x00, 0x00, 0x11}, *src = pat;
        quicly_ack_frame_t decoded;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0x34);
        ok(decoded.num_gaps == 0);
        ok(decoded.ack_block_lengths[0] == 0x12);
        ok(decoded.smallest_acknowledged == 0x34 - 0x12 + 1);
    }

    {
        const uint8_t pat[] = {0x34, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04}, *src = pat;
        quicly_ack_frame_t decoded;
        ok(quicly_decode_ack_frame(&src, pat + sizeof(pat), &decoded, 0) == 0);
        ok(src == pat + sizeof(pat));
        ok(decoded.largest_acknowledged == 0x34);
        ok(decoded.num_gaps == 2);
        ok(decoded.ack_block_lengths[0] == 1);
        ok(decoded.gaps[0] == 2);
        ok(decoded.ack_block_lengths[1] == 3);
        ok(decoded.gaps[1] == 4);
        ok(decoded.ack_block_lengths[2] == 5);
        ok(decoded.smallest_acknowledged == 0x34 - 1 - 2 - 3 - 4 - 5 + 1);
    }

    { /* Bogus ACK Frame larger than the internal buffer */
        uint8_t pat[1024], *end = pat;
        const uint8_t *src = pat;
        uint64_t i, range_sum;
        quicly_ack_frame_t decoded;
        end = quicly_encodev(end, 0xFA00);
        end = quicly_encodev(end, 0);
        end = quicly_encodev(end, QUICLY_ACK_MAX_GAPS + 30); // with excess ranges
        end = quicly_encodev(end, 8);
        for (i = 0; i < QUICLY_ACK_MAX_GAPS + 30; ++i) {
            end = quicly_encodev(end, i);      // gap
            end = quicly_encodev(end, i % 10); // ack-range
        }

        ok(quicly_decode_ack_frame(&src, end, &decoded, 0) == 0);
        ok(decoded.largest_acknowledged == 0xFA00);
        ok(decoded.ack_delay == 0);
        ok(decoded.num_gaps == QUICLY_ACK_MAX_GAPS);
        ok(decoded.ack_block_lengths[0] == 8 + 1); // first ack-range
        range_sum = decoded.ack_block_lengths[0];
        for (i = 0; i < decoded.num_gaps; ++i) {
            ok(decoded.gaps[i] == i + 1);
            ok(decoded.ack_block_lengths[i + 1] == (i % 10) + 1);
            range_sum += decoded.gaps[i] + decoded.ack_block_lengths[i + 1];
        }
        ok(src == end); // decoded the entire frame
        ok(decoded.smallest_acknowledged == 0xFA00 - range_sum + 1);
    }

    subtest("underflow", test_ack_decode_underflow);
}

static void test_ack_encode(void)
{
    quicly_ranges_t ranges;
    uint8_t buf[256], *end;
    const uint8_t *src;
    quicly_ack_frame_t decoded;
    uint64_t ecn_counts[3] = {};

    quicly_ranges_init(&ranges);
    quicly_ranges_add(&ranges, 0x12, 0x14);

    { /* PATH_ACK must reserve the entire path ID before writing anything */
        uint8_t short_buf[3] = {0xaa, 0xbb, 0xcc};
        ok(quicly_encode_path_ack_frame(short_buf, short_buf + 2, 64, &ranges, ecn_counts, 0) == NULL);
        ok(short_buf[0] == 0xaa && short_buf[1] == 0xbb && short_buf[2] == 0xcc);
    }

    /* encode */
    end = quicly_encode_ack_frame(buf, buf + sizeof(buf), &ranges, ecn_counts, 63);
    ok(end - buf == 5);
    /* decode */
    src = buf + 1;
    ok(quicly_decode_ack_frame(&src, end, &decoded, 0) == 0);
    ok(src == end);
    ok(decoded.ack_delay == 63);
    ok(decoded.num_gaps == 0);
    ok(decoded.largest_acknowledged == 0x13);
    ok(decoded.ack_block_lengths[0] == 2);
    ok(decoded.ecn_counts[0] == 0);
    ok(decoded.ecn_counts[1] == 0);
    ok(decoded.ecn_counts[2] == 0);

    quicly_ranges_add(&ranges, 0x10, 0x11);
    ecn_counts[0] = 12;
    ecn_counts[1] = 34;
    ecn_counts[2] = 56;

    /* encode */
    end = quicly_encode_ack_frame(buf, buf + sizeof(buf), &ranges, ecn_counts, 63);
    ok(end - buf == 10);
    /* decode */
    src = buf + 1;
    ok(quicly_decode_ack_frame(&src, end, &decoded, 1) == 0);
    ok(src == end);
    ok(decoded.ack_delay == 63);
    ok(decoded.num_gaps == 1);
    ok(decoded.largest_acknowledged == 0x13);
    ok(decoded.ack_block_lengths[0] == 2);
    ok(decoded.gaps[0] == 1);
    ok(decoded.ack_block_lengths[1] == 1);
    ok(decoded.ecn_counts[0] == 12);
    ok(decoded.ecn_counts[1] == 34);
    ok(decoded.ecn_counts[2] == 56);

    quicly_ranges_clear(&ranges);
}

static void test_ack_encode_capacity(void)
{
    quicly_ranges_t ranges;
    uint64_t ecn_counts[3] = {PTLS_QUICINT_MAX, 64, 16384};
    uint8_t buf[128], reference[128];
    quicly_ranges_init(&ranges);
    ok(quicly_ranges_add(&ranges, PTLS_QUICINT_MAX - 2, PTLS_QUICINT_MAX + 1) == 0);

    for (int path = 0; path != 2; ++path) {
        uint8_t *end =
            path ? quicly_encode_path_ack_frame(reference, reference + sizeof(reference), PTLS_QUICINT_MAX, &ranges, ecn_counts,
                                                PTLS_QUICINT_MAX)
                 : quicly_encode_ack_frame(reference, reference + sizeof(reference), &ranges, ecn_counts, PTLS_QUICINT_MAX);
        ok(end != NULL);
        size_t required = (size_t)(end - reference);
        for (size_t capacity = 0; capacity <= required; ++capacity) {
            memset(buf, 0xaa, sizeof(buf));
            end = path ? quicly_encode_path_ack_frame(buf, buf + capacity, PTLS_QUICINT_MAX, &ranges, ecn_counts, PTLS_QUICINT_MAX)
                       : quicly_encode_ack_frame(buf, buf + capacity, &ranges, ecn_counts, PTLS_QUICINT_MAX);
            ok(capacity < required ? end == NULL : end == buf + required);
            int intact = 1;
            for (size_t i = capacity; i != sizeof(buf); ++i)
                intact &= buf[i] == 0xaa;
            ok(intact);
            if (capacity == required)
                ok(memcmp(buf, reference, required) == 0);
        }
    }
    quicly_ranges_clear(&ranges);
}

static quicly_flexicast_flow_id_t make_fc_flow_id(size_t len)
{
    quicly_flexicast_flow_id_t flow_id = {0};
    flow_id.len = (uint8_t)len;
    for (size_t i = 0; i != len && i != sizeof(flow_id.bytes); ++i)
        flow_id.bytes[i] = (uint8_t)(0xa0 + i);
    return flow_id;
}

static void test_flexicast_frames(void)
{
    uint8_t encoded[256], key_bytes[32], v6_source[16], v6_group[16], *end;
    const uint8_t *src;

    for (size_t i = 0; i != sizeof(key_bytes); ++i)
        key_bytes[i] = (uint8_t)i;
    for (size_t i = 0; i != 16; ++i) {
        v6_source[i] = (uint8_t)(0x20 + i);
        v6_group[i] = (uint8_t)(0xff - i);
    }

    { /* FC_ANNOUNCE IPv4 and IPv6 */
        quicly_flexicast_announce_frame_t announce = {
            .flow_id = make_fc_flow_id(8),
            .sequence = 63,
            .ip_version = 4,
            .source_ip = {192, 0, 2, 1},
            .group_ip = {232, 1, 2, 3},
            .udp_port = 4433,
            .ack_delay_msec = 25,
        };
        size_t cap = quicly_fc_announce_frame_capacity(&announce);
        ok(cap != 0);
        end = quicly_encode_fc_announce_frame(encoded, &announce);
        ok((size_t)(end - encoded) == cap);
        ok(memcmp(encoded, "\x80\x17\x3e\x00\x08", 5) == 0);
        encoded[cap] = 0xaa;
        quicly_flexicast_announce_frame_t decoded;
        src = encoded;
        ok(quicly_decodev(&src, end + 1) == QUICLY_FRAME_TYPE_FC_ANNOUNCE);
        ok(quicly_decode_fc_announce_frame(&src, end + 1, &decoded) == 0);
        ok(src == end);
        ok(decoded.flow_id.len == announce.flow_id.len &&
           memcmp(decoded.flow_id.bytes, announce.flow_id.bytes, announce.flow_id.len) == 0);
        ok(decoded.sequence == announce.sequence && decoded.ip_version == 4);
        ok(memcmp(decoded.source_ip, announce.source_ip, 4) == 0 && memcmp(decoded.group_ip, announce.group_ip, 4) == 0);
        ok(decoded.udp_port == announce.udp_port && decoded.ack_delay_msec == announce.ack_delay_msec);
        for (size_t i = 4; i != cap; ++i) {
            src = encoded + 4;
            ok(quicly_decode_fc_announce_frame(&src, encoded + i, &decoded) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
        }

        announce.flow_id = make_fc_flow_id(QUICLY_FLEXICAST_MAX_FLOW_ID_SIZE);
        announce.sequence = 16384;
        announce.ip_version = 6;
        memcpy(announce.source_ip, v6_source, 16);
        memcpy(announce.group_ip, v6_group, 16);
        cap = quicly_fc_announce_frame_capacity(&announce);
        end = quicly_encode_fc_announce_frame(encoded, &announce);
        ok((size_t)(end - encoded) == cap);
        src = encoded + 4;
        ok(quicly_decode_fc_announce_frame(&src, end, &decoded) == 0 && src == end && decoded.ip_version == 6);
        ok(memcmp(decoded.source_ip, v6_source, 16) == 0 && memcmp(decoded.group_ip, v6_group, 16) == 0);
        announce.flow_id.len = 0;
        ok(quicly_fc_announce_frame_capacity(&announce) == 0);
        announce.flow_id = make_fc_flow_id(8);
        announce.ip_version = 5;
        ok(quicly_fc_announce_frame_capacity(&announce) == 0);
    }

    { /* FC_STATE */
        quicly_flexicast_state_frame_t state = {
            .flow_id = make_fc_flow_id(3), .sequence = 64, .action = QUICLY_FLEXICAST_STATE_LISTEN};
        static const uint8_t listen_wire[] = {0x80, 0x17, 0x3e, 0x01, 3, 0xa0, 0xa1, 0xa2, 0x40, 0x40, 0, 0, 0, 0, 0, 0, 0, 3};
        size_t cap = quicly_fc_state_frame_capacity(&state);
        end = quicly_encode_fc_state_frame(encoded, &state);
        ok((size_t)(end - encoded) == cap && cap == sizeof(listen_wire) && memcmp(encoded, listen_wire, sizeof(listen_wire)) == 0);
        quicly_flexicast_state_frame_t decoded;
        src = encoded + 4;
        ok(quicly_decode_fc_state_frame(&src, end, &decoded) == 0 && src == end);
        ok(decoded.sequence == state.sequence && decoded.action == QUICLY_FLEXICAST_STATE_LISTEN);
        ok(memcmp(decoded.flow_id.bytes, state.flow_id.bytes, state.flow_id.len) == 0);
        for (size_t i = 4; i != cap; ++i) {
            src = encoded + 4;
            ok(quicly_decode_fc_state_frame(&src, encoded + i, &decoded) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
        }
        encoded[cap - 1] = 4;
        src = encoded + 4;
        ok(quicly_decode_fc_state_frame(&src, end, &decoded) == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
        state.action = 4;
        ok(quicly_fc_state_frame_capacity(&state) == 0);
    }

    { /* FC_KEY and malformed flow_id / key lengths */
        quicly_flexicast_key_frame_t key = {.flow_id = make_fc_flow_id(20),
                                            .sequence = 1073741824,
                                            .first_packet_number = 16383,
                                            .key = ptls_iovec_init(key_bytes, sizeof(key_bytes)),
                                            .algorithm = UINT64_C(0x1301000000000001)};
        size_t cap = quicly_fc_key_frame_capacity(&key);
        end = quicly_encode_fc_key_frame(encoded, &key);
        ok((size_t)(end - encoded) == cap);
        quicly_flexicast_key_frame_t decoded;
        src = encoded + 4;
        ok(quicly_decode_fc_key_frame(&src, end, &decoded) == 0 && src == end);
        ok(decoded.flow_id.len == key.flow_id.len && memcmp(decoded.flow_id.bytes, key.flow_id.bytes, key.flow_id.len) == 0);
        ok(decoded.sequence == key.sequence && decoded.first_packet_number == key.first_packet_number);
        ok(decoded.key.len == key.key.len && memcmp(decoded.key.base, key.key.base, key.key.len) == 0);
        ok(decoded.algorithm == key.algorithm);
        for (size_t i = 4; i != cap; ++i) {
            src = encoded + 4;
            ok(quicly_decode_fc_key_frame(&src, encoded + i, &decoded) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
        }

        quicly_flexicast_announce_frame_t bad_ann;
        quicly_flexicast_state_frame_t bad_state;
        for (size_t i = 0; i != 2; ++i) {
            uint8_t bad = i == 0 ? 0 : QUICLY_FLEXICAST_MAX_FLOW_ID_SIZE + 1;
            src = &bad;
            ok(quicly_decode_fc_announce_frame(&src, &bad + 1, &bad_ann) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
            src = &bad;
            ok(quicly_decode_fc_state_frame(&src, &bad + 1, &bad_state) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
            src = &bad;
            ok(quicly_decode_fc_key_frame(&src, &bad + 1, &decoded) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
        }

        static const uint8_t oversized_key[] = {1, 0xa0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0};
        src = oversized_key;
        ok(quicly_decode_fc_key_frame(&src, oversized_key + sizeof(oversized_key), &decoded) ==
           QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }
}

static void test_mozquic(void)
{
    quicly_stream_frame_t frame;
    static const char *mess = "\xc5\0\0\0\0\0\0\xb6\x16\x03";
    const uint8_t *p = (void *)mess, type_flags = *p++;
    quicly_decode_stream_frame(type_flags, &p, p + 9, &frame);
}

static void test_multipath_frames(void)
{
    uint8_t buf[256], *end;
    const uint8_t *src;

    { /* MAX_PATH_ID */
        quicly_max_path_id_frame_t frame = {0};
        end = quicly_encode_max_path_id_frame(buf, 0x1234);
        ok((size_t)(end - buf) == quicly_max_path_id_frame_capacity(0x1234));
        src = buf + 2;
        ok(quicly_decode_max_path_id_frame(&src, end, &frame) == 0 && src == end && frame.max_path_id == 0x1234);
        src = buf + 2;
        ok(quicly_decode_max_path_id_frame(&src, end - 1, &frame) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }

    { /* PATHS_BLOCKED */
        quicly_paths_blocked_frame_t frame = {0};
        end = quicly_encode_paths_blocked_frame(buf, 7);
        ok((size_t)(end - buf) == quicly_paths_blocked_frame_capacity(7));
        src = buf + 2;
        ok(quicly_decode_paths_blocked_frame(&src, end, &frame) == 0 && src == end && frame.max_path_id == 7);
        src = buf + 2;
        ok(quicly_decode_paths_blocked_frame(&src, buf + 2, &frame) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }

    { /* PATH_CIDS_BLOCKED */
        quicly_path_cids_blocked_frame_t frame = {0};
        end = quicly_encode_path_cids_blocked_frame(buf, 3, 42);
        ok((size_t)(end - buf) == quicly_path_cids_blocked_frame_capacity(3, 42));
        src = buf + 2;
        ok(quicly_decode_path_cids_blocked_frame(&src, end, &frame) == 0 && src == end);
        ok(frame.path_id == 3 && frame.next_sequence == 42);
        src = buf + 2;
        ok(quicly_decode_path_cids_blocked_frame(&src, end - 1, &frame) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }

    { /* PATH_STATUS_AVAILABLE and PATH_STATUS_BACKUP */
        for (int is_backup = 0; is_backup < 2; ++is_backup) {
            quicly_path_status_frame_t frame = {0};
            end = quicly_encode_path_status_frame(buf, is_backup, 2, 99);
            ok((size_t)(end - buf) == quicly_path_status_frame_capacity(is_backup, 2, 99));
            src = buf;
            uint64_t type = ptls_decode_quicint(&src, end);
            ok(type == (is_backup ? QUICLY_FRAME_TYPE_PATH_STATUS_BACKUP : QUICLY_FRAME_TYPE_PATH_STATUS_AVAILABLE));
            ok(quicly_decode_path_status_frame(&src, end, &frame) == 0 && src == end);
            ok(frame.path_id == 2 && frame.sequence == 99);
            src = buf + 2;
            ok(quicly_decode_path_status_frame(&src, end - 1, &frame) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
        }
    }

    { /* PATH_ABANDON */
        quicly_path_abandon_frame_t frame = {0};
        end = quicly_encode_path_abandon_frame(buf, 5, QUICLY_PATH_ABANDON_ERROR_UNSTABLE_OR_POOR);
        ok((size_t)(end - buf) == quicly_path_abandon_frame_capacity(5, QUICLY_PATH_ABANDON_ERROR_UNSTABLE_OR_POOR));
        src = buf + 2;
        ok(quicly_decode_path_abandon_frame(&src, end, &frame) == 0 && src == end);
        ok(frame.path_id == 5 && frame.error_code == QUICLY_PATH_ABANDON_ERROR_UNSTABLE_OR_POOR);
        src = buf + 2;
        ok(quicly_decode_path_abandon_frame(&src, end - 1, &frame) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }

    { /* PATH_NEW_CONNECTION_ID */
        static const uint8_t cid[8] = {1, 2, 3, 4, 5, 6, 7, 8}, srt[16] = {9, 8, 7, 6};
        quicly_path_new_connection_id_frame_t frame = {0};
        end = quicly_encode_path_new_connection_id_frame(buf, 2, 4, 1, cid, sizeof(cid), srt);
        ok((size_t)(end - buf) == quicly_path_new_connection_id_frame_capacity(2, 4, 1, sizeof(cid)));
        src = buf + 2;
        ok(quicly_decode_path_new_connection_id_frame(&src, end, &frame) == 0 && src == end);
        ok(frame.path_id == 2 && frame.base.sequence == 4 && frame.base.retire_prior_to == 1);
        ok(frame.base.cid.len == sizeof(cid) && memcmp(frame.base.cid.base, cid, sizeof(cid)) == 0);
        ok(memcmp(frame.base.stateless_reset_token, srt, sizeof(srt)) == 0);
        src = buf + 2;
        ok(quicly_decode_path_new_connection_id_frame(&src, end - 1, &frame) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }

    { /* PATH_RETIRE_CONNECTION_ID */
        quicly_path_retire_connection_id_frame_t frame = {0};
        end = quicly_encode_path_retire_connection_id_frame(buf, 1, 12);
        ok((size_t)(end - buf) == quicly_path_retire_connection_id_frame_capacity(1, 12));
        src = buf + 2;
        ok(quicly_decode_path_retire_connection_id_frame(&src, end, &frame) == 0 && src == end);
        ok(frame.path_id == 1 && frame.sequence == 12);
        src = buf + 2;
        ok(quicly_decode_path_retire_connection_id_frame(&src, end - 1, &frame) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
    }

    { /* PATH_ACK and PATH_ACK_ECN */
        quicly_ranges_t ranges;
        uint64_t zero_ecn[3] = {0}, ecn_counts[3] = {10, 20, 30};
        uint64_t path_id;
        quicly_ack_frame_t ack;
        quicly_ranges_init(&ranges);
        quicly_ranges_add(&ranges, 5, 8);
        for (int is_ecn = 0; is_ecn < 2; ++is_ecn) {
            end = quicly_encode_path_ack_frame(buf, buf + sizeof(buf), 3, &ranges, is_ecn ? ecn_counts : zero_ecn, 15);
            ok(end != NULL);
            src = buf;
            uint64_t type = ptls_decode_quicint(&src, end);
            ok(type == (is_ecn ? QUICLY_FRAME_TYPE_PATH_ACK_ECN : QUICLY_FRAME_TYPE_PATH_ACK));
            ok(quicly_decode_path_ack_frame(&src, end, &path_id, &ack, is_ecn) == 0 && src == end);
            ok(path_id == 3 && ack.largest_acknowledged == 7 && ack.smallest_acknowledged == 5 && ack.ack_delay == 15);
            if (is_ecn)
                ok(ack.ecn_counts[0] == 10 && ack.ecn_counts[1] == 20 && ack.ecn_counts[2] == 30);
            src = buf;
            (void)ptls_decode_quicint(&src, end);
            ok(quicly_decode_path_ack_frame(&src, end - 1, &path_id, &ack, is_ecn) == QUICLY_TRANSPORT_ERROR_FRAME_ENCODING);
        }
        quicly_ranges_clear(&ranges);
    }
}

void test_frame(void)
{
    subtest("ack-decode", test_ack_decode);
    subtest("ack-encode", test_ack_encode);
    subtest("ack-encode-capacity", test_ack_encode_capacity);
    subtest("multipath-frames", test_multipath_frames);
    subtest("flexicast-frames", test_flexicast_frames);
    subtest("mozquic", test_mozquic);
}
