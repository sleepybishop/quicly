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
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/flexicast.h"
#include "test.h"

static quicly_flexicast_flow_t *create_flow_at(uint64_t flow_id, const uint8_t *secret, uint64_t first_packet_number)
{
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t config = {.flow_id = flow_id,
                                        .first_packet_number = first_packet_number,
                                        .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                        .crypto_engine = &quicly_default_crypto_engine,
                                        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size)};
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    ok(flow != NULL);
    return flow;
}

static quicly_flexicast_flow_t *create_flow(uint64_t flow_id, const uint8_t *secret)
{
    return create_flow_at(flow_id, secret, 0);
}

typedef struct st_test_flexicast_cc_state_t {
    uint64_t feedback_events;
    uint64_t acked_packets;
    uint64_t lost_packets;
} test_flexicast_cc_state_t;

static int test_cc_init(void *state, const quicly_flexicast_cc_config_t *config, int64_t now, quicly_flexicast_cc_output_t *output)
{
    (void)state;
    (void)now;
    output->rate_bytes_per_second = config->startup_rate_bytes_per_second;
    return 0;
}

static void test_cc_on_feedback(void *_state, const quicly_flexicast_feedback_t *feedback, quicly_flexicast_cc_output_t *output)
{
    test_flexicast_cc_state_t *state = _state;
    ++state->feedback_events;
    state->acked_packets += feedback->acked_packets;
    state->lost_packets += feedback->lost_packets;
    output->rate_bytes_per_second = 10000 + state->acked_packets * 100 + state->lost_packets * 10;
    output->limiting_member_id = feedback->member_id;
    output->reason = (feedback->acked_packets != 0 ? QUICLY_FLEXICAST_CC_REASON_ACK : 0) |
                     (feedback->lost_packets != 0 ? QUICLY_FLEXICAST_CC_REASON_LOSS : 0);
}

static quicly_flexicast_cc_type_t test_cc_type = {
    .name = "test",
    .state_size = sizeof(test_flexicast_cc_state_t),
    .init = test_cc_init,
    .on_feedback = test_cc_on_feedback,
};

static quicly_flexicast_flow_t *create_cc_flow(uint64_t flow_id, const uint8_t *secret)
{
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t config = {
        .flow_id = flow_id,
        .cipher_suite = &ptls_openssl_aes128gcmsha256,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
        .cc_type = &test_cc_type,
        .cc_config = {.startup_rate_bytes_per_second = 10000,
                      .minimum_rate_bytes_per_second = 100,
                      .maximum_rate_bytes_per_second = 1000000,
                      .maximum_datagram_size = 1400,
                      .packet_reordering_threshold = 3},
        .now = 100,
    };
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    ok(flow != NULL);
    return flow;
}

static quicly_flexicast_flow_id_t make_flow_id(size_t len)
{
    quicly_flexicast_flow_id_t flow_id = {0};
    flow_id.len = (uint8_t)len;
    for (size_t i = 0; i != len && i != sizeof(flow_id.bytes); ++i)
        flow_id.bytes[i] = (uint8_t)(0xa0 + i);
    return flow_id;
}

static void test_frame_codecs(void)
{
    uint8_t encoded[256], key_bytes[32], v6_source[16], v6_group[16];
    size_t encoded_size, consumed;

    for (size_t i = 0; i != sizeof(key_bytes); ++i)
        key_bytes[i] = (uint8_t)i;
    for (size_t i = 0; i != 16; ++i) {
        v6_source[i] = (uint8_t)(0x20 + i);
        v6_group[i] = (uint8_t)(0xff - i);
    }

    quicly_flexicast_announce_frame_t announce = {
        .flow_id = make_flow_id(8),
        .sequence = 63,
        .ip_version = 4,
        .source_ip = {192, 0, 2, 1},
        .group_ip = {232, 1, 2, 3},
        .udp_port = 4433,
        .ack_delay_msec = 25,
    };
    size_t announce_capacity = quicly_flexicast_announce_frame_capacity(&announce);
    ok(announce_capacity != 0);
    ok(quicly_flexicast_encode_announce_frame(encoded, announce_capacity - 1, &announce, &encoded_size) ==
       QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL);
    ok(quicly_flexicast_encode_announce_frame(encoded, sizeof(encoded), &announce, &encoded_size) == QUICLY_FLEXICAST_OK);
    ok(encoded_size == announce_capacity);
    ok(memcmp(encoded, "\x80\x17\x3e\x00\x08", 5) == 0);
    encoded[encoded_size] = 0xaa;
    quicly_flexicast_announce_frame_t decoded_announce;
    ok(quicly_flexicast_decode_announce_frame(encoded, encoded_size + 1, &decoded_announce, &consumed) == QUICLY_FLEXICAST_OK);
    ok(consumed == encoded_size);
    ok(decoded_announce.flow_id.len == announce.flow_id.len);
    ok(memcmp(decoded_announce.flow_id.bytes, announce.flow_id.bytes, announce.flow_id.len) == 0);
    ok(decoded_announce.sequence == announce.sequence);
    ok(decoded_announce.ip_version == 4);
    ok(memcmp(decoded_announce.source_ip, announce.source_ip, 4) == 0);
    ok(memcmp(decoded_announce.group_ip, announce.group_ip, 4) == 0);
    ok(decoded_announce.udp_port == announce.udp_port);
    ok(decoded_announce.ack_delay_msec == announce.ack_delay_msec);
    for (size_t i = 0; i != encoded_size; ++i)
        ok(quicly_flexicast_decode_announce_frame(encoded, i, &decoded_announce, &consumed) ==
           QUICLY_FLEXICAST_ERROR_FRAME_ENCODING);

    announce.flow_id = make_flow_id(QUICLY_FLEXICAST_MAX_FLOW_ID_SIZE);
    announce.sequence = 16384;
    announce.ip_version = 6;
    memcpy(announce.source_ip, v6_source, 16);
    memcpy(announce.group_ip, v6_group, 16);
    ok(quicly_flexicast_encode_announce_frame(encoded, sizeof(encoded), &announce, &encoded_size) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_decode_announce_frame(encoded, encoded_size, &decoded_announce, &consumed) == QUICLY_FLEXICAST_OK);
    ok(decoded_announce.ip_version == 6);
    ok(memcmp(decoded_announce.source_ip, v6_source, 16) == 0);
    ok(memcmp(decoded_announce.group_ip, v6_group, 16) == 0);
    announce.flow_id.len = 0;
    ok(quicly_flexicast_announce_frame_capacity(&announce) == 0);
    announce.flow_id = make_flow_id(8);
    announce.ip_version = 5;
    ok(quicly_flexicast_announce_frame_capacity(&announce) == 0);

    quicly_flexicast_state_frame_t state = {.flow_id = make_flow_id(3), .sequence = 64, .action = QUICLY_FLEXICAST_STATE_READY};
    ok(quicly_flexicast_encode_state_frame(encoded, sizeof(encoded), &state, &encoded_size) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_state_frame_t decoded_state;
    ok(quicly_flexicast_decode_state_frame(encoded, encoded_size, &decoded_state, &consumed) == QUICLY_FLEXICAST_OK);
    ok(consumed == encoded_size);
    ok(decoded_state.sequence == state.sequence);
    ok(decoded_state.action == QUICLY_FLEXICAST_STATE_READY);
    ok(memcmp(decoded_state.flow_id.bytes, state.flow_id.bytes, state.flow_id.len) == 0);
    for (size_t i = 0; i != encoded_size; ++i)
        ok(quicly_flexicast_decode_state_frame(encoded, i, &decoded_state, &consumed) == QUICLY_FLEXICAST_ERROR_FRAME_ENCODING);
    encoded[encoded_size - 1] = 4;
    ok(quicly_flexicast_decode_state_frame(encoded, encoded_size, &decoded_state, &consumed) ==
       QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION);
    state.action = 4;
    ok(quicly_flexicast_state_frame_capacity(&state) == 0);

    quicly_flexicast_key_frame_t key = {.flow_id = make_flow_id(20),
                                        .sequence = 1073741824,
                                        .first_packet_number = 16383,
                                        .key = ptls_iovec_init(key_bytes, sizeof(key_bytes)),
                                        .algorithm = UINT64_C(0x1301000000000001)};
    ok(quicly_flexicast_encode_key_frame(encoded, sizeof(encoded), &key, &encoded_size) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_key_frame_t decoded_key;
    ok(quicly_flexicast_decode_key_frame(encoded, encoded_size, &decoded_key, &consumed) == QUICLY_FLEXICAST_OK);
    ok(consumed == encoded_size);
    ok(decoded_key.flow_id.len == key.flow_id.len);
    ok(memcmp(decoded_key.flow_id.bytes, key.flow_id.bytes, key.flow_id.len) == 0);
    ok(decoded_key.sequence == key.sequence);
    ok(decoded_key.first_packet_number == key.first_packet_number);
    ok(decoded_key.key.len == key.key.len);
    ok(memcmp(decoded_key.key.base, key.key.base, key.key.len) == 0);
    ok(decoded_key.algorithm == key.algorithm);
    for (size_t i = 0; i != encoded_size; ++i)
        ok(quicly_flexicast_decode_key_frame(encoded, i, &decoded_key, &consumed) == QUICLY_FLEXICAST_ERROR_FRAME_ENCODING);
}

static void test_congestion_feedback(void)
{
    static const uint64_t flow_id = UINT64_C(0x1020304050607081);
    static const uint8_t payload[] = "feedback";
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[256];
    uint64_t packet_numbers[5];
    size_t packet_size, num_acked, num_lost, num_completed, pending;
    quicly_flexicast_member_stats_t stats;
    quicly_flexicast_cc_output_t output;

    memset(secret, 0x3c, ptls_openssl_aes128gcmsha256.hash->digest_size);
    quicly_flexicast_flow_t *flow = create_cc_flow(flow_id, secret);
    ok(quicly_flexicast_attach_at(flow, 101, 100) == QUICLY_FLEXICAST_OK);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(packet_numbers); ++i)
        ok(quicly_flexicast_send_datagram_at(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                             packet_numbers + i, 100 + i) == QUICLY_FLEXICAST_OK);

    quicly_ack_frame_t ack = {
        .largest_acknowledged = packet_numbers[4], .smallest_acknowledged = packet_numbers[4], .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame_at(flow, 101, &ack, &num_acked, &num_lost, &num_completed, 200) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1);
    ok(num_lost == 2);
    ok(num_completed == 3);
    ok(quicly_flexicast_get_pending_members(flow, packet_numbers[0], &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    ok(quicly_flexicast_get_pending_members(flow, packet_numbers[2], &pending) == QUICLY_FLEXICAST_OK);

    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.feedback_epoch == 1);
    ok(stats.delivered_packets == 1);
    ok(stats.lost_packets == 2);
    ok(stats.latest_rtt_msec == 96);
    ok(stats.minimum_rtt_msec == 96);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == 10120);
    ok(output.limiting_member_id == 101);
    ok(output.reason == (QUICLY_FLEXICAST_CC_REASON_ACK | QUICLY_FLEXICAST_CC_REASON_LOSS));

    /* Repeated feedback is idempotent and does not create a new controller epoch. */
    ok(quicly_flexicast_ack_frame_at(flow, 101, &ack, &num_acked, &num_lost, &num_completed, 210) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 0 && num_lost == 0 && num_completed == 0);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.feedback_epoch == 1);

    ack = (quicly_ack_frame_t){
        .largest_acknowledged = packet_numbers[3], .smallest_acknowledged = packet_numbers[2], .ack_block_lengths = {2}};
    ok(quicly_flexicast_ack_frame_at(flow, 101, &ack, &num_acked, &num_lost, &num_completed, 220) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 2 && num_lost == 0 && num_completed == 2);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.feedback_epoch == 2);
    ok(stats.delivered_packets == 3 && stats.lost_packets == 2);

    /* Rekey resets delivery membership and packet epoch, but not learned
     * controller output or member measurements. */
    uint8_t next_secret[PTLS_MAX_DIGEST_SIZE];
    memset(next_secret, 0x7e, ptls_openssl_aes128gcmsha256.hash->digest_size);
    ok(quicly_flexicast_attach_at(flow, 202, 224) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    uint64_t learned_rate = output.rate_bytes_per_second;
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(next_secret, ptls_openssl_aes128gcmsha256.hash->digest_size), 1000, 225) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(flow) == 0);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.delivered_packets == 3 && stats.lost_packets == 2);
    ok(quicly_flexicast_detach_at(flow, 202, 225) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_member_stats(flow, 202, &stats) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == learned_rate);
    ok(quicly_flexicast_attach_at(flow, 101, 226) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram_at(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                         packet_numbers, 227) == QUICLY_FLEXICAST_OK);
    ok(packet_numbers[0] == 1000);
    int complete;
    ok(quicly_flexicast_abandon_datagram(flow, 101, packet_numbers[0], &complete) == QUICLY_FLEXICAST_OK);
    ok(complete);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.delivered_packets == 3 && stats.lost_packets == 2);

    ok(quicly_flexicast_detach_at(flow, 101, 230) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_flow_free(flow);
}

static void test_ack_aggregation(void)
{
    static const uint64_t flow_id = UINT64_C(0x1020304050607082);
    static const uint8_t payload[] = "ack ranges";
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0};
    uint8_t packets[3][256], encoded[QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE];
    size_t packet_sizes[3], encoded_size;
    uint64_t packet_numbers[3], received_packet_number;
    ptls_iovec_t received;

    memset(secret, 0x4d, ptls_openssl_aes128gcmsha256.hash->digest_size);
    quicly_flexicast_flow_t *source = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *receiver = create_flow(flow_id, secret);
    ok(quicly_flexicast_attach(source, 101) == QUICLY_FLEXICAST_OK);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(packet_numbers); ++i)
        ok(quicly_flexicast_send_datagram_at(source, ptls_iovec_init(payload, sizeof(payload)), packets[i], sizeof(packets[i]),
                                             packet_sizes + i, packet_numbers + i, 100 + i) == QUICLY_FLEXICAST_OK);

    ok(quicly_flexicast_receive_datagram_at(receiver, packets[0], packet_sizes[0], &received, &received_packet_number, 110) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_receive_datagram_at(receiver, packets[2], packet_sizes[2], &received, &received_packet_number, 112) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_ack_deadline(receiver) == 135);
    /* The first ACK in an epoch is immediate so a short flow does not end
     * before it produces any congestion-control feedback. */
    ok(quicly_flexicast_ack_is_due(receiver, 134));
    ok(quicly_flexicast_ack_is_due(receiver, 135));
    ok(quicly_flexicast_encode_pending_ack(receiver, encoded, sizeof(encoded), 135, &encoded_size) == QUICLY_FLEXICAST_OK);

    const uint8_t *src = encoded, *end = encoded + encoded_size;
    ok(*src++ == QUICLY_FRAME_TYPE_PATH_ACK);
    ok(quicly_decodev(&src, end) == flow_id);
    quicly_ack_frame_t ack;
    ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
    ok(ack.largest_acknowledged == packet_numbers[2]);
    ok(ack.ack_delay == 23);
    ok(ack.smallest_acknowledged == packet_numbers[0]);
    ok(ack.num_gaps == 1);
    ok(ack.ack_block_lengths[0] == 1 && ack.ack_block_lengths[1] == 1);
    ok(src != end && *src++ == QUICLY_FRAME_TYPE_PING && src == end);

    quicly_flexicast_ack_sent(receiver);
    ok(quicly_flexicast_get_ack_deadline(receiver) == INT64_MAX);
    ok(!quicly_flexicast_ack_is_due(receiver, 1000));

    ok(quicly_flexicast_receive_datagram_at(receiver, packets[1], packet_sizes[1], &received, &received_packet_number, 200) ==
       QUICLY_FLEXICAST_OK);
    ok(!quicly_flexicast_ack_is_due(receiver, 224));
    ok(quicly_flexicast_ack_is_due(receiver, 225));
    quicly_flexicast_flow_free(receiver);
    quicly_flexicast_flow_free(source);
}

static void test_builtin_controllers(void)
{
    quicly_flexicast_cc_config_t config = {
        .startup_rate_bytes_per_second = 100000,
        .minimum_rate_bytes_per_second = 2000,
        .maximum_rate_bytes_per_second = 1000000,
        .maximum_datagram_size = 1200,
        .feedback_timeout_msec = 100,
        .packet_reordering_threshold = 3,
    };
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_t *cc = NULL;

    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_multicast, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    quicly_flexicast_cc_on_member_added(cc, 202, 100);
    quicly_flexicast_feedback_t feedback = {.member_id = 101,
                                            .epoch = 1,
                                            .acked_packets = 8,
                                            .acked_bytes = 9600,
                                            .minimum_rtt_msec = 20,
                                            .latest_rtt_msec = 20,
                                            .smoothed_rtt_msec = 20,
                                            .now = 120};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000); /* member 202 still limits */
    feedback.member_id = 202;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second > 100000);
    uint64_t multicast_growth = output.rate_bytes_per_second;
    feedback.member_id = 101;
    feedback.epoch = 2;
    feedback.acked_packets = 0;
    feedback.acked_bytes = 0;
    feedback.lost_packets = 1;
    feedback.lost_bytes = 1200;
    feedback.now = 140;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second < multicast_growth);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_LOSS);
    uint64_t loss_rate = output.rate_bytes_per_second;
    feedback.epoch = 3;
    feedback.now = 145;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == loss_rate);
    ok(output.rate_reduction_events == 1 && output.loss_reduction_events == 1);
    quicly_flexicast_cc_on_member_removed(cc, 101, 150);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.limiting_member_id == 202 && output.rate_bytes_per_second == multicast_growth);
    quicly_flexicast_cc_on_timeout(cc, 220);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_NONE && output.rate_bytes_per_second == multicast_growth &&
       output.next_timeout == 320);
    quicly_flexicast_cc_on_timeout(cc, 320);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_NONE && output.rate_bytes_per_second == multicast_growth &&
       output.next_timeout == 420);
    quicly_flexicast_cc_on_timeout(cc, 420);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_TIMEOUT && output.rate_bytes_per_second == multicast_growth / 2 &&
       output.next_timeout == 520);
    ok(output.rate_increase_events == 2);
    ok(output.ack_growth_events == 1 && output.other_growth_events == 1);
    ok(output.rate_reduction_events == 2);
    ok(output.loss_reduction_events == 1 && output.timeout_reduction_events == 1);
    quicly_flexicast_cc_free(cc);

    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    quicly_flexicast_cc_hints_t hints = {.active_senders = 4, .median_sender_rate_bytes_per_second = 200000};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    feedback = (quicly_flexicast_feedback_t){.member_id = 101,
                                             .epoch = 1,
                                             .acked_packets = 8,
                                             .lost_packets = 2,
                                             .delivery_rate_bytes_per_second = 100000,
                                             .minimum_rtt_msec = 20,
                                             .latest_rtt_msec = 20,
                                             .smoothed_rtt_msec = 20,
                                             .now = 120};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000); /* ambiguous flat loss holds */
    feedback.epoch = 2;
    feedback.acked_packets = 10;
    feedback.lost_packets = 0;
    feedback.now = 140;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 106250); /* conservative group growth */
    hints.median_sender_rate_bytes_per_second = 0;
    quicly_flexicast_cc_set_hints(cc, &hints, 145);
    feedback.epoch = 3;
    feedback.minimum_rtt_msec = 20;
    feedback.latest_rtt_msec = 40;
    feedback.now = 160;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 106250); /* one high RTT sample is noise */
    feedback.epoch = 4;
    feedback.now = 170;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 106250);
    feedback.epoch = 5;
    feedback.delivery_rate_bytes_per_second = 50000;
    feedback.now = 180;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136); /* degraded delivery plus delay selects a proportional cut */
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_RTT);
    ok(output.rate_increase_events == 1 && output.ack_growth_events == 1);
    ok(output.rate_reduction_events == 1 && output.rtt_reduction_events == 1);
    feedback.now = 181;
    quicly_flexicast_cc_on_feedback(cc, &feedback); /* duplicate member epoch is idempotent */
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136 && output.reason == QUICLY_FLEXICAST_CC_REASON_NONE);
    ok(output.rate_reduction_events == 1 && output.rtt_reduction_events == 1);
    quicly_flexicast_cc_on_member_added(cc, 202, 180);
    feedback.member_id = 202;
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 180 + (int64_t)epoch;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136); /* one shared RTT episode, not one cut per member */
    ok(output.rate_reduction_events == 1 && output.rtt_reduction_events == 1);
    quicly_flexicast_cc_on_member_added(cc, 303, 190);
    feedback = (quicly_flexicast_feedback_t){.member_id = 303,
                                             .epoch = 1,
                                             .acked_packets = 10,
                                             .delivery_rate_bytes_per_second = 90000,
                                             .minimum_rtt_msec = 20,
                                             .latest_rtt_msec = 20,
                                             .smoothed_rtt_msec = 20,
                                             .now = 210};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136); /* a non-limiting clean member cannot grow during the episode */
    feedback.member_id = 101;
    feedback.delivery_rate_bytes_per_second = 50000;
    feedback.latest_rtt_msec = 40;
    feedback.epoch = 6;
    feedback.now = 220;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback.epoch = 7;
    feedback.now = 280;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback.epoch = 8;
    feedback.now = 290;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136); /* one full aggregate horizon is held after a cut */
    ok(output.rate_reduction_events == 1 && output.rtt_reduction_events == 1);
    for (uint64_t epoch = 9; epoch <= 11; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 370 + (int64_t)(epoch - 8) * 10;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136); /* persistent reports remain one aggregate congestion episode */
    ok(output.rate_reduction_events == 1 && output.rtt_reduction_events == 1);
    feedback.epoch = 12;
    feedback.delivery_rate_bytes_per_second = 100000;
    feedback.latest_rtt_msec = 20;
    feedback.now = 410;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136); /* clean hysteresis freezes growth */
    feedback.epoch = 13;
    feedback.now = 420;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 90136);
    for (uint64_t epoch = 14; epoch <= 18; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 430 + (int64_t)(epoch - 14) * 30;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second > 90136); /* sustained clean limiting-receiver feedback rearms growth */
    uint64_t episode_recovered_rate = output.rate_bytes_per_second;
    feedback.delivery_rate_bytes_per_second = 20000;
    feedback.latest_rtt_msec = 40;
    for (uint64_t epoch = 19; epoch <= 21; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 600 + (int64_t)(epoch - 19) * 10;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second < episode_recovered_rate); /* a new cleanly separated episode can reduce again */
    ok(output.rate_reduction_events == 2 && output.rtt_reduction_events == 2);
    quicly_flexicast_cc_free(cc);

    /* Stable delivery loss without queue growth becomes the learned radio
     * baseline. The same ratio accompanied by delay then holds rather than
     * causing a false congestion reduction. */
    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    feedback = (quicly_flexicast_feedback_t){.member_id = 101,
                                             .lost_packets = 2,
                                             .delivery_rate_bytes_per_second = 60000,
                                             .minimum_rtt_msec = 20,
                                             .latest_rtt_msec = 20,
                                             .smoothed_rtt_msec = 20};
    for (uint64_t epoch = 1; epoch <= 5; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 100 + (int64_t)epoch * 100;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    feedback.latest_rtt_msec = 50;
    for (uint64_t epoch = 6; epoch <= 8; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 100 + (int64_t)epoch * 100;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000);
    ok(output.rate_reduction_events == 0 && output.rtt_reduction_events == 0);
    quicly_flexicast_cc_free(cc);

    /* Startup probing is bounded even before a delivery-rate sample exists. */
    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    feedback = (quicly_flexicast_feedback_t){
        .member_id = 101, .acked_packets = 1, .minimum_rtt_msec = 20, .latest_rtt_msec = 20, .smoothed_rtt_msec = 20};
    for (uint64_t epoch = 1; epoch <= 5; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 95 + (int64_t)epoch * 30;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t startup_probe_rate = output.rate_bytes_per_second;
    for (uint64_t epoch = 6; epoch <= 8; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 95 + (int64_t)epoch * 30;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == startup_probe_rate);
    ok(output.rate_increase_events == 5 && output.ack_growth_events == 5);
    quicly_flexicast_cc_free(cc);

    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = 1,
                                          .external_load_queued_bytes = 4800,
                                          .external_load_oldest_age_msec = 100,
                                          .external_load_fraction_ppm = 500000};
    quicly_flexicast_cc_set_hints(cc, &hints, 200);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000);
    ok((output.reason & QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD) != 0);
    quicly_flexicast_cc_set_hints(cc, &hints, 201);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000);
    feedback = (quicly_flexicast_feedback_t){.member_id = 101,
                                             .epoch = 1,
                                             .acked_packets = 10,
                                             .delivery_rate_bytes_per_second = 100000,
                                             .minimum_rtt_msec = 20,
                                             .latest_rtt_msec = 80,
                                             .smoothed_rtt_msec = 20,
                                             .now = 220};
    for (uint64_t epoch = 1; epoch <= 4; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 210 + (int64_t)epoch * 10;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000); /* delay without degraded delivery is not enough */
    ok(output.rtt_reduction_events == 0);
    for (uint64_t epoch = 2; epoch <= 32; ++epoch) {
        hints.external_load_epoch = epoch;
        quicly_flexicast_cc_set_hints(cc, &hints, 200 + (int64_t)epoch * 100);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000); /* repair pressure cannot ratchet the path rate to its floor */
    feedback.latest_rtt_msec = 20;
    feedback.epoch = 5;
    feedback.now = 3500;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000); /* debt freezes growth */
    ok(output.external_load_growth_freeze_events >= 1);
    for (uint64_t epoch = 33; epoch <= 35; ++epoch) {
        hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = epoch};
        quicly_flexicast_cc_set_hints(cc, &hints, 200 + (int64_t)epoch * 100);
    }
    feedback.epoch = 6;
    feedback.now = 3700;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second > 100000); /* sustained low load resumes growth */
    ok(output.rate_increase_events == 1 && output.ack_growth_events == 1);
    quicly_flexicast_cc_free(cc);

    /* Repair load freezes growth but does not hide corroborated queue
     * congestion. Correlated feedback remains one aggregate RTT episode. */
    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = 1,
                                          .external_load_queued_bytes = 4800,
                                          .external_load_oldest_age_msec = 100,
                                          .external_load_fraction_ppm = 500000};
    quicly_flexicast_cc_set_hints(cc, &hints, 110);
    feedback = (quicly_flexicast_feedback_t){.member_id = 101,
                                             .acked_packets = 2,
                                             .delivery_rate_bytes_per_second = 20000,
                                             .minimum_rtt_msec = 20,
                                             .latest_rtt_msec = 80,
                                             .smoothed_rtt_msec = 40};
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 110 + (int64_t)epoch * 10;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t repair_congested_rate = output.rate_bytes_per_second;
    ok(repair_congested_rate < config.startup_rate_bytes_per_second);
    for (uint64_t epoch = 4; epoch <= 20; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 110 + (int64_t)epoch * 10;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == repair_congested_rate);
    ok(output.rtt_reduction_events == 1);
    quicly_flexicast_cc_free(cc);

    config.startup_rate_bytes_per_second = 8000;
    config.minimum_rate_bytes_per_second = 4000;
    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_multicast, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    feedback = (quicly_flexicast_feedback_t){.member_id = 101,
                                             .epoch = 1,
                                             .lost_packets = 1,
                                             .minimum_rtt_msec = 20,
                                             .latest_rtt_msec = 20,
                                             .smoothed_rtt_msec = 20,
                                             .now = 120};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback.epoch = 2;
    feedback.now = 1120; /* a new feedback horizon permits a second reduction */
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 4000 && output.floor_entry_events == 1);
    feedback.epoch = 3;
    feedback.acked_packets = 1;
    feedback.lost_packets = 0;
    feedback.now = 1140;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second > 4000 && output.floor_exit_events == 1);
    ok(output.rate_reduction_events == 2 && output.loss_reduction_events == 2);
    quicly_flexicast_cc_free(cc);

    /* Adaptive delay evidence is persistent and clean feedback raises a flow
     * off its configured floor. Missing feedback cuts at most once per three
     * unanswered recovery probes. */
    config.startup_rate_bytes_per_second = 5000;
    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 101, 100);
    feedback = (quicly_flexicast_feedback_t){.member_id = 101,
                                             .acked_packets = 1,
                                             .delivery_rate_bytes_per_second = 5000,
                                             .minimum_rtt_msec = 20,
                                             .latest_rtt_msec = 40,
                                             .smoothed_rtt_msec = 20};
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        feedback.epoch = epoch;
        if (epoch > 1)
            feedback.delivery_rate_bytes_per_second = 1000;
        feedback.now = 100 + (int64_t)epoch * 10;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 4000 && output.floor_entry_events == 1 && output.rtt_reduction_events == 1);
    hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = 1,
                                          .external_load_queued_bytes = 4800,
                                          .external_load_oldest_age_msec = 100,
                                          .external_load_fraction_ppm = 500000};
    quicly_flexicast_cc_set_hints(cc, &hints, 135);
    feedback.latest_rtt_msec = 20;
    for (uint64_t epoch = 4; epoch <= 6; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 100 + (int64_t)epoch * 10;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 5000 && output.floor_exit_events == 1);
    uint64_t recovered_rate = output.rate_bytes_per_second;
    uint64_t previous_timeout_reductions = output.timeout_reduction_events;
    for (size_t probe = 0; probe != 2; ++probe) {
        quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
        quicly_flexicast_cc_get_output(cc, &output);
        ok(output.rate_bytes_per_second == recovered_rate);
    }
    quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == recovered_rate * 2 && output.timeout_reduction_events == previous_timeout_reductions);
    quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == recovered_rate * 4);
    quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == config.minimum_rate_bytes_per_second * 8);
    uint64_t probe_rate = output.rate_bytes_per_second;
    for (size_t epoch = 0; epoch != 10; ++epoch) {
        quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
        quicly_flexicast_cc_get_output(cc, &output);
        ok(output.rate_bytes_per_second == probe_rate);
    }
    quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == probe_rate / 2 && output.timeout_reduction_events == previous_timeout_reductions + 1);
    quicly_flexicast_cc_free(cc);
}

static void test_scalable_members(void)
{
    static const size_t member_count = 1000;
    static const uint64_t first_member_id = 10000;
    static const uint8_t payload[] = "large group";
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[256];
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t config = {
        .flow_id = UINT64_C(0x1020304050607083),
        .cipher_suite = &ptls_openssl_aes128gcmsha256,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
        .max_members = member_count,
        .cc_type = &quicly_flexicast_cc_type_multicast,
        .cc_config = {.startup_rate_bytes_per_second = 100000,
                      .minimum_rate_bytes_per_second = 2000,
                      .maximum_datagram_size = 1200,
                      .feedback_timeout_msec = 100,
                      .packet_reordering_threshold = 3},
    };
    uint64_t packet_number;
    size_t packet_size, pending;
    int all_ok = 1, complete = 0;

    memset(secret, 0x6b, ptls_openssl_aes128gcmsha256.hash->digest_size);
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    for (size_t i = 0; i != member_count; ++i)
        if (quicly_flexicast_attach(flow, first_member_id + i) != QUICLY_FLEXICAST_OK)
            all_ok = 0;
    ok(all_ok);
    ok(quicly_flexicast_num_members(flow) == member_count);
    ok(quicly_flexicast_attach(flow, first_member_id + member_count) == QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                      &packet_number) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == member_count);

    /* Removing an outstanding member clears only its bit. Reusing that slot
     * must not make the replacement responsible for an older packet. */
    uint64_t removed_id = first_member_id + 500, replacement_id = first_member_id + member_count;
    ok(quicly_flexicast_detach(flow, removed_id) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, replacement_id) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_ack(flow, replacement_id, packet_number, &complete) == QUICLY_FLEXICAST_ERROR_REPLAY);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == member_count - 1);

    all_ok = 1;
    for (size_t i = 0; i != member_count; ++i) {
        if (first_member_id + i == removed_id)
            continue;
        if (quicly_flexicast_ack(flow, first_member_id + i, packet_number, &complete) != QUICLY_FLEXICAST_OK)
            all_ok = 0;
    }
    ok(all_ok && complete);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);

    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                      &packet_number) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == member_count);
    all_ok = 1;
    for (size_t i = 0; i != member_count; ++i) {
        uint64_t member_id = first_member_id + i;
        if (member_id == removed_id)
            member_id = replacement_id;
        if (quicly_flexicast_ack(flow, member_id, packet_number, &complete) != QUICLY_FLEXICAST_OK)
            all_ok = 0;
    }
    ok(all_ok && complete);
    quicly_flexicast_flow_free(flow);

    /* The adaptive controller uses the same dynamic capacity and hash-based
     * lookup independently of the flow member table. */
    quicly_flexicast_cc_config_t cc_config = config.cc_config;
    quicly_flexicast_cc_t *cc = NULL;
    quicly_flexicast_cc_output_t output;
    cc_config.maximum_members = member_count;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &cc_config, 100) == 0);
    for (size_t i = 0; i != member_count; ++i)
        quicly_flexicast_cc_on_member_added(cc, first_member_id + i, 100);
    quicly_flexicast_feedback_t feedback = {.member_id = first_member_id + member_count - 1,
                                            .epoch = 1,
                                            .acked_packets = 1,
                                            .minimum_rtt_msec = 20,
                                            .latest_rtt_msec = 20,
                                            .smoothed_rtt_msec = 20,
                                            .now = 120};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.limiting_member_id == feedback.member_id && output.reason == QUICLY_FLEXICAST_CC_REASON_ACK);
    quicly_flexicast_cc_free(cc);
}

void test_flexicast(void)
{
    static const uint64_t flow_id = UINT64_C(0x1020304050607080);
    static const uint8_t payload_bytes[] = "shared datagram";
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, wrong_secret[PTLS_MAX_DIGEST_SIZE] = {0};
    uint8_t encrypted[256], receiver_a_packet[256], receiver_b_packet[256], bad_packet[256];
    size_t encrypted_size, pending;
    uint64_t packet_number, received_packet_number;
    ptls_iovec_t received;
    int complete;

    test_frame_codecs();
    test_congestion_feedback();
    test_ack_aggregation();
    test_builtin_controllers();
    test_scalable_members();

    memset(secret, 0x5a, ptls_openssl_aes128gcmsha256.hash->digest_size);
    memset(wrong_secret, 0xa5, ptls_openssl_aes128gcmsha256.hash->digest_size);
    quicly_flexicast_flow_t *source = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *receiver_a = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *receiver_b = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *wrong_receiver = create_flow(flow_id, wrong_secret);

    ok(quicly_flexicast_get_flow_id(source) == flow_id);
    ok(quicly_flexicast_attach(source, 101) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 202) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 202) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(source) == 2);

    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(payload_bytes, sizeof(payload_bytes)), encrypted, sizeof(encrypted),
                                      &encrypted_size, &packet_number) == QUICLY_FLEXICAST_OK);
    ok(packet_number == 0);
    ok(quicly_flexicast_get_next_packet_number(source) == 1);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_OK);
    ok(pending == 2);

    memcpy(receiver_a_packet, encrypted, encrypted_size);
    memcpy(receiver_b_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(receiver_a, receiver_a_packet, encrypted_size, &received, &received_packet_number) ==
       QUICLY_FLEXICAST_OK);
    ok(received_packet_number == packet_number);
    ok(received.len == sizeof(payload_bytes));
    ok(memcmp(received.base, payload_bytes, sizeof(payload_bytes)) == 0);
    ok(quicly_flexicast_receive_datagram(receiver_b, receiver_b_packet, encrypted_size, &received, &received_packet_number) ==
       QUICLY_FLEXICAST_OK);
    ok(received_packet_number == packet_number);
    ok(memcmp(received.base, payload_bytes, sizeof(payload_bytes)) == 0);

    memcpy(bad_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(receiver_a, bad_packet, encrypted_size, &received, &received_packet_number) ==
       QUICLY_FLEXICAST_ERROR_REPLAY);
    memcpy(bad_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(wrong_receiver, bad_packet, encrypted_size, &received, &received_packet_number) ==
       QUICLY_FLEXICAST_ERROR_CRYPTO);
    memcpy(bad_packet, encrypted, encrypted_size);
    bad_packet[1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver_b, bad_packet, encrypted_size, &received, &received_packet_number) ==
       QUICLY_FLEXICAST_ERROR_WRONG_FLOW);

    ok(quicly_flexicast_ack(source, 101, packet_number, &complete) == QUICLY_FLEXICAST_OK);
    ok(!complete);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_OK);
    ok(pending == 1);
    ok(quicly_flexicast_ack(source, 101, packet_number, &complete) == QUICLY_FLEXICAST_ERROR_REPLAY);
    ok(quicly_flexicast_ack(source, 202, packet_number, &complete) == QUICLY_FLEXICAST_OK);
    ok(complete);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);

    ok(quicly_flexicast_detach(source, 202) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(source) == 1);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(payload_bytes, 0), encrypted, sizeof(encrypted), &encrypted_size,
                                      &packet_number) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_OK);
    ok(pending == 1);

    size_t num_acked, num_completed;
    quicly_ack_frame_t ack_frame = {
        .largest_acknowledged = packet_number, .smallest_acknowledged = packet_number, .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(source, 101, &ack_frame, &num_acked, &num_completed) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1);
    ok(num_completed == 1);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);

    uint64_t range_packets[3];
    for (size_t i = 0; i != 3; ++i) {
        ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(payload_bytes, 0), encrypted, sizeof(encrypted), &encrypted_size,
                                          range_packets + i) == QUICLY_FLEXICAST_OK);
    }
    ack_frame = (quicly_ack_frame_t){.largest_acknowledged = range_packets[2],
                                     .smallest_acknowledged = range_packets[0],
                                     .num_gaps = 1,
                                     .ack_block_lengths = {1, 1},
                                     .gaps = {1}};
    ok(quicly_flexicast_ack_frame(source, 101, &ack_frame, &num_acked, &num_completed) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 2);
    ok(num_completed == 2);
    ok(quicly_flexicast_get_pending_members(source, range_packets[1], &pending) == QUICLY_FLEXICAST_OK);
    ok(pending == 1);
    ack_frame = (quicly_ack_frame_t){
        .largest_acknowledged = range_packets[1], .smallest_acknowledged = range_packets[1], .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(source, 101, &ack_frame, &num_acked, &num_completed) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1 && num_completed == 1);

    /* FC_KEY can admit a receiver after the flow has already advanced. Verify
     * that the advertised First Packet Number drives both egress numbering and
     * ingress reconstruction across the 16-bit truncated-PN boundary. */
    quicly_flexicast_flow_t *late_source = create_flow_at(flow_id, secret, 65536);
    quicly_flexicast_flow_t *late_receiver = create_flow_at(flow_id, secret, 65536);
    ok(quicly_flexicast_attach(late_source, 303) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(late_source, ptls_iovec_init(payload_bytes, sizeof(payload_bytes)), encrypted,
                                      sizeof(encrypted), &encrypted_size, &packet_number) == QUICLY_FLEXICAST_OK);
    ok(packet_number == 65536);
    memcpy(receiver_a_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(late_receiver, receiver_a_packet, encrypted_size, &received, &received_packet_number) ==
       QUICLY_FLEXICAST_OK);
    ok(received_packet_number == 65536);
    ok(memcmp(received.base, payload_bytes, sizeof(payload_bytes)) == 0);
    quicly_flexicast_flow_free(late_receiver);
    quicly_flexicast_flow_free(late_source);

    quicly_flexicast_flow_free(wrong_receiver);
    quicly_flexicast_flow_free(receiver_b);
    quicly_flexicast_flow_free(receiver_a);
    quicly_flexicast_flow_free(source);
}
