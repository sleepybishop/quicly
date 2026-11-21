#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/flexicast.h"
#include "test.h"

static quicly_flexicast_flow_id_t make_test_flow_id(uint64_t raw_id)
{
    uint8_t bytes[8];
    quicly_encode64(bytes, raw_id);
    return quicly_flexicast_flow_id_init(bytes, sizeof(bytes));
}

static quicly_flexicast_flow_t *create_flow_at(uint64_t flow_id, const uint8_t *secret, uint64_t first_packet_number)
{
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t config = {.flow_id = make_test_flow_id(flow_id),
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

typedef struct st_test_flexicast_cc_t {
    quicly_flexicast_cc_t super;
    uint64_t feedback_events;
    uint64_t acked_packets;
    uint64_t lost_packets;
} test_flexicast_cc_t;

static quicly_flexicast_feedback_t test_last_feedback;

static void test_cc_on_feedback(quicly_flexicast_cc_t *_cc, const quicly_flexicast_feedback_t *feedback)
{
    test_flexicast_cc_t *cc = (test_flexicast_cc_t *)_cc;
    test_last_feedback = *feedback;
    ++cc->feedback_events;
    cc->acked_packets += feedback->acked_packets;
    cc->lost_packets += feedback->lost_packets;
    cc->super.output.rate_bytes_per_second = 10000 + cc->acked_packets * 100 + cc->lost_packets * 10;
    cc->super.output.limiting_member_id = feedback->member_id;
    cc->super.output.reason = (feedback->acked_packets != 0 ? QUICLY_FLEXICAST_CC_REASON_ACK : 0) |
                              (feedback->lost_packets != 0 ? QUICLY_FLEXICAST_CC_REASON_LOSS : 0);
}

static quicly_flexicast_cc_type_t test_cc_type = {
    .name = "test",
    .on_feedback = test_cc_on_feedback,
};

static quicly_flexicast_flow_t *create_cc_flow(uint64_t flow_id, const uint8_t *secret, test_flexicast_cc_t *cc)
{
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_cc_config_t cc_config = {.startup_rate_bytes_per_second = 10000,
                                              .minimum_rate_bytes_per_second = 100,
                                              .maximum_rate_bytes_per_second = 1000000,
                                              .maximum_datagram_size = 1400};
    memset(cc, 0, sizeof(*cc));
    ok(quicly_flexicast_cc_init(&cc->super, &test_cc_type, &cc_config) == 0);
    quicly_flexicast_config_t config = {
        .flow_id = make_test_flow_id(flow_id),
        .cipher_suite = &ptls_openssl_aes128gcmsha256,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
        .cc = &cc->super,
        .packet_reordering_threshold = 3,
        .now = 100,
    };
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    ok(flow != NULL);
    return flow;
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
    test_flexicast_cc_t cc;

    memset(secret, 0x3c, ptls_openssl_aes128gcmsha256.hash->digest_size);
    quicly_flexicast_flow_t *flow = create_cc_flow(flow_id, secret, &cc);
    ok(quicly_flexicast_attach(flow, 101, 100) == QUICLY_FLEXICAST_OK);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(packet_numbers); ++i)
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                          packet_numbers + i, 100 + i) == QUICLY_FLEXICAST_OK);

    quicly_ack_frame_t ack = {
        .largest_acknowledged = packet_numbers[4], .smallest_acknowledged = packet_numbers[4], .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(flow, 101, &ack, 0, &num_acked, &num_lost, &num_completed, 200) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1 && num_lost == 2 && num_completed == 3);
    ok(quicly_flexicast_get_pending_members(flow, packet_numbers[0], &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    ok(quicly_flexicast_get_pending_members(flow, packet_numbers[2], &pending) == QUICLY_FLEXICAST_OK);

    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.feedback_epoch == 1 && stats.delivered_packets == 1 && stats.lost_packets == 2);
    ok(stats.latest_rtt_msec == 96 && stats.minimum_rtt_msec == 96);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == 10120 && output.limiting_member_id == 101);
    ok(output.reason == (QUICLY_FLEXICAST_CC_REASON_ACK | QUICLY_FLEXICAST_CC_REASON_LOSS));

    /* repeated feedback is idempotent and does not advance the feedback epoch */
    ok(quicly_flexicast_ack_frame(flow, 101, &ack, 0, &num_acked, &num_lost, &num_completed, 210) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 0 && num_lost == 0 && num_completed == 0);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK && stats.feedback_epoch == 1);

    ack = (quicly_ack_frame_t){
        .largest_acknowledged = packet_numbers[3], .smallest_acknowledged = packet_numbers[2], .ack_block_lengths = {2}};
    ok(quicly_flexicast_ack_frame(flow, 101, &ack, 0, &num_acked, &num_lost, &num_completed, 220) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 2 && num_lost == 0 && num_completed == 2);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.feedback_epoch == 2 && stats.delivered_packets == 3 && stats.lost_packets == 2);

    /* rekey resets active membership and packet epoch while preserving learned stats */
    uint8_t next_secret[PTLS_MAX_DIGEST_SIZE];
    memset(next_secret, 0x7e, ptls_openssl_aes128gcmsha256.hash->digest_size);
    ok(quicly_flexicast_attach(flow, 202, 224) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    uint64_t learned_rate = output.rate_bytes_per_second;
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(next_secret, ptls_openssl_aes128gcmsha256.hash->digest_size), 1000, 225) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(flow) == 0);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.delivered_packets == 3 && stats.lost_packets == 2);
    ok(quicly_flexicast_detach(flow, 202, 225) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_member_stats(flow, 202, &stats) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == learned_rate);
    ok(quicly_flexicast_attach(flow, 101, 226) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                      packet_numbers, 227) == QUICLY_FLEXICAST_OK);
    ok(packet_numbers[0] == 1000);
    int complete;
    ok(quicly_flexicast_abandon_datagram(flow, 101, packet_numbers[0], &complete) == QUICLY_FLEXICAST_OK && complete);
    ok(quicly_flexicast_get_member_stats(flow, 101, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.delivered_packets == 3 && stats.lost_packets == 2);

    ok(quicly_flexicast_detach(flow, 101, 230) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_flow_free(flow);
}

static void test_ack_aggregation(void)
{
    static const uint64_t flow_id = UINT64_C(0x1020304050607082);
    static const uint8_t payload[] = "ack ranges";
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0};
    uint8_t packets[12][256], encoded[QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE];
    size_t packet_sizes[12], encoded_size;
    uint64_t packet_numbers[12], received_packet_number;
    ptls_iovec_t received;

    memset(secret, 0x4d, ptls_openssl_aes128gcmsha256.hash->digest_size);
    quicly_flexicast_flow_t *source = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *receiver = create_flow(flow_id, secret);
    ok(!quicly_flexicast_flow_has_sender_state(receiver));
    ok(quicly_flexicast_attach(source, 101, 100) == QUICLY_FLEXICAST_OK);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(packet_numbers); ++i)
        ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(payload, sizeof(payload)), packets[i], sizeof(packets[i]),
                                          packet_sizes + i, packet_numbers + i, 100 + (int64_t)i) == QUICLY_FLEXICAST_OK);

    ok(quicly_flexicast_receive_datagram(receiver, packets[0], packet_sizes[0], &received, &received_packet_number, 0, 110) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_receive_datagram(receiver, packets[2], packet_sizes[2], &received, &received_packet_number, 0, 112) ==
       QUICLY_FLEXICAST_OK);
    /* first ACK in an epoch has immediate deadline == ack_pending_since */
    ok(quicly_flexicast_get_ack_deadline(receiver) == 110);
    ok(quicly_flexicast_ack_is_due(receiver, 110));
    ok(quicly_flexicast_encode_pending_ack(receiver, flow_id, encoded, sizeof(encoded), 135, &encoded_size) == QUICLY_FLEXICAST_OK);

    const uint8_t *src = encoded, *end = encoded + encoded_size;
    ok(*src++ == QUICLY_FRAME_TYPE_PATH_ACK);
    ok(quicly_decodev(&src, end) == flow_id);
    quicly_ack_frame_t ack;
    ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
    ok(ack.largest_acknowledged == packet_numbers[2]);
    ok(ack.ack_delay == (23000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT));
    ok(ack.smallest_acknowledged == packet_numbers[0]);
    ok(ack.num_gaps == 1 && ack.ack_block_lengths[0] == 1 && ack.ack_block_lengths[1] == 1);
    ok(src != end && *src++ == QUICLY_FRAME_TYPE_PING && src == end);

    quicly_flexicast_ack_sent(receiver);
    ok(quicly_flexicast_get_ack_deadline(receiver) == INT64_MAX);
    ok(!quicly_flexicast_ack_is_due(receiver, 1000));

    ok(quicly_flexicast_receive_datagram(receiver, packets[1], packet_sizes[1], &received, &received_packet_number, 0, 200) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_ack_deadline(receiver) == 225);
    ok(!quicly_flexicast_ack_is_due(receiver, 224));
    ok(quicly_flexicast_ack_is_due(receiver, 225));
    /* reordered arrivals fill gaps without changing the largest packet timestamp */
    ok(quicly_flexicast_encode_pending_ack(receiver, flow_id, encoded, sizeof(encoded), 201, &encoded_size) == QUICLY_FLEXICAST_OK);
    src = encoded + 1;
    end = encoded + encoded_size;
    ok(quicly_decodev(&src, end) == flow_id);
    ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
    ok(ack.largest_acknowledged == packet_numbers[2]);
    ok(ack.num_gaps == 0 && ack.ack_block_lengths[0] == 3);
    ok(ack.ack_delay == (89000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT));

    /* reaching ack_frequency (default 8) switches deadline from delayed to immediate */
    quicly_flexicast_ack_sent(receiver);
    for (size_t i = 3; i < 11; ++i) {
        ok(quicly_flexicast_receive_datagram(receiver, packets[i], packet_sizes[i], &received, &received_packet_number, 0,
                                             300 + (int64_t)(i - 3)) == QUICLY_FLEXICAST_OK);
        if (i < 10)
            ok(quicly_flexicast_get_ack_deadline(receiver) == 325);
        else
            ok(quicly_flexicast_get_ack_deadline(receiver) == 300 && quicly_flexicast_ack_is_due(receiver, 307));
    }

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
    };
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&config, 100);

    ok(cc != NULL);
    ok(quicly_flexicast_cc_on_member_added(cc, 101, 100) == 0);
    ok(quicly_flexicast_cc_on_member_added(cc, 202, 100) == 0);
    quicly_flexicast_cc_on_packet_sent(cc, 7, 1200, 100);
    quicly_flexicast_feedback_t feedback = {.member_id = 101,
                                            .epoch = 1,
                                            .largest_acknowledged = 7,
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
    ok(output.rate_bytes_per_second > 100000 && output.reason == QUICLY_FLEXICAST_CC_REASON_ACK);
    uint64_t multicast_growth = output.rate_bytes_per_second;
    quicly_flexicast_cc_on_packet_sent(cc, 8, 1200, 125);
    feedback.member_id = 101;
    feedback.epoch = 2;
    feedback.largest_acknowledged = 8;
    feedback.acked_packets = 0;
    feedback.acked_bytes = 0;
    feedback.lost_packets = 1;
    feedback.lost_bytes = 1200;
    feedback.now = 140;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second < multicast_growth && output.reason == QUICLY_FLEXICAST_CC_REASON_LOSS);
    uint64_t loss_rate = output.rate_bytes_per_second;
    feedback.epoch = 3;
    feedback.now = 145;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == loss_rate);
    quicly_flexicast_cc_on_member_removed(cc, 101, 150);
    quicly_flexicast_cc_get_output(cc, &output);
    /* packet 8 sent at t=125 remains unacknowledged for member 202, arming 3 unanswered timeout probes at 225/325/425 */
    ok(output.limiting_member_id == 202 && output.rate_bytes_per_second == multicast_growth && output.next_timeout == 225);
    quicly_flexicast_cc_on_timeout(cc, 225);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_NONE && output.rate_bytes_per_second == multicast_growth &&
       output.next_timeout == 325);
    quicly_flexicast_cc_on_timeout(cc, 325);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_NONE && output.rate_bytes_per_second == multicast_growth &&
       output.next_timeout == 425);
    quicly_flexicast_cc_on_timeout(cc, 425);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_TIMEOUT && output.rate_bytes_per_second == multicast_growth / 2 &&
       output.next_timeout == 525);
    quicly_flexicast_cc_free_multicast(cc);
}

static void test_scalable_members(void)
{
    static const size_t member_count = 1000;
    static const uint64_t first_member_id = 10000;
    static const uint8_t payload[] = "large group";
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[256];
    quicly_flexicast_cc_config_t cc_cfg = {.maximum_members = member_count,
                                           .startup_rate_bytes_per_second = 100000,
                                           .minimum_rate_bytes_per_second = 2000,
                                           .maximum_datagram_size = 1200,
                                           .feedback_timeout_msec = 100};
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&cc_cfg, 0);
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t config = {
        .flow_id = make_test_flow_id(UINT64_C(0x1020304050607083)),
        .cipher_suite = &ptls_openssl_aes128gcmsha256,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
        .max_members = member_count,
        .cc = cc,
        .packet_reordering_threshold = 3,
    };
    uint64_t packet_number;
    size_t packet_size, pending;
    int all_ok = 1, complete = 0;

    memset(secret, 0x6b, ptls_openssl_aes128gcmsha256.hash->digest_size);
    ok(cc != NULL && quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    for (size_t i = 0; i != member_count; ++i)
        if (quicly_flexicast_attach(flow, first_member_id + i, 0) != QUICLY_FLEXICAST_OK)
            all_ok = 0;
    ok(all_ok && quicly_flexicast_num_members(flow) == member_count);
    ok(quicly_flexicast_attach(flow, first_member_id + member_count, 0) == QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                      &packet_number, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == member_count);

    /* removing a member clears only its pending bit */
    uint64_t removed_id = first_member_id + 500, replacement_id = first_member_id + member_count;
    ok(quicly_flexicast_detach(flow, removed_id, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, replacement_id, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_ack_packet(flow, replacement_id, packet_number, &complete, 0) == QUICLY_FLEXICAST_ERROR_REPLAY);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == member_count - 1);

    all_ok = 1;
    for (size_t i = 0; i != member_count; ++i) {
        if (first_member_id + i == removed_id)
            continue;
        if (quicly_flexicast_ack_packet(flow, first_member_id + i, packet_number, &complete, 0) != QUICLY_FLEXICAST_OK)
            all_ok = 0;
    }
    ok(all_ok && complete);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);

    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &packet_size,
                                      &packet_number, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(flow, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == member_count);
    all_ok = 1;
    for (size_t i = 0; i != member_count; ++i) {
        uint64_t member_id = first_member_id + i;
        if (member_id == removed_id)
            member_id = replacement_id;
        if (quicly_flexicast_ack_packet(flow, member_id, packet_number, &complete, 0) != QUICLY_FLEXICAST_OK)
            all_ok = 0;
    }
    ok(all_ok && complete);
    quicly_flexicast_flow_free(flow);
    quicly_flexicast_cc_free_multicast(cc);
}

static void test_member_churn(void)
{
    quicly_flexicast_cc_config_t config = {
        .maximum_members = 2, .startup_rate_bytes_per_second = 100000, .maximum_datagram_size = 1200};
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&config, 100);
    quicly_flexicast_cc_output_t output;
    int all_ok = 1;
    ok(cc != NULL);
    quicly_flexicast_cc_on_member_added(cc, UINT64_MAX, 100);
    for (uint64_t id = 1; id <= 512; ++id) {
        quicly_flexicast_feedback_t feedback = {.member_id = id, .epoch = 1, .ecn_ce_count = 1, .now = 100 + (int64_t)id};
        quicly_flexicast_cc_on_member_added(cc, id, feedback.now);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        quicly_flexicast_cc_get_output(cc, &output);
        all_ok &= output.limiting_member_id == id && output.reason == QUICLY_FLEXICAST_CC_REASON_ECN;
        quicly_flexicast_cc_on_member_removed(cc, id, feedback.now);
    }
    ok(all_ok); /* joining must still work after every hash bucket has been used */
    quicly_flexicast_cc_free_multicast(cc);

    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[128];
    quicly_flexicast_flow_t *flow = create_flow(1000, secret);
    uint64_t ids[8], pn;
    size_t size;
    int complete;
    all_ok = 1;
    for (size_t i = 0; i != PTLS_ELEMENTSOF(ids); ++i) {
        ids[i] = i + 1;
        all_ok &= quicly_flexicast_attach(flow, ids[i], 0) == 0;
    }
    for (size_t turn = 0; turn != 512; ++turn) {
        size_t slot = turn % PTLS_ELEMENTSOF(ids);
        all_ok &= quicly_flexicast_detach(flow, ids[slot], 0) == 0;
        ids[slot] = turn + 100;
        all_ok &= quicly_flexicast_attach(flow, ids[slot], 0) == 0;
        all_ok &= quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 0) == 0;
        for (size_t i = 0; i != PTLS_ELEMENTSOF(ids); ++i) {
            all_ok &= quicly_flexicast_ack_packet(flow, ids[i], pn, &complete, 0) == 0;
            all_ok &= complete == (i + 1 == PTLS_ELEMENTSOF(ids));
        }
    }
    ok(all_ok);
    quicly_flexicast_flow_free(flow);

    /* suspended members from prior epochs must be evicted when max_members slots fill */
    quicly_flexicast_cc_t *rekey_cc = quicly_flexicast_cc_new_multicast(&config, 100);
    quicly_flexicast_config_t small_cfg = {
        .flow_id = make_test_flow_id(1001),
        .cipher_suite = &ptls_openssl_aes128gcmsha256,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
        .max_members = 2,
        .cc = rekey_cc,
    };
    ok(quicly_flexicast_flow_create(&flow, &small_cfg) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 10, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 20, 100) == QUICLY_FLEXICAST_OK);
    secret[0] = 1;
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size), 1, 200) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 30, 210) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 40, 210) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(flow) == 2);
    ok(quicly_flexicast_attach(flow, 50, 210) == QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT);
    quicly_flexicast_flow_free(flow);
    quicly_flexicast_cc_free_multicast(rekey_cc);
}

static void test_controller_boundaries(void)
{
    quicly_flexicast_cc_config_t config = {.maximum_datagram_size = 1200, .startup_rate_bytes_per_second = UINT64_MAX};
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&config, 100);
    quicly_flexicast_cc_output_t output;

    ok(cc != NULL);
    ok(quicly_flexicast_cc_on_member_added(cc, 1, 100) == 0);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == INT64_MAX);
    quicly_flexicast_cc_on_packet_sent(cc, 0, 1200, 100);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout > 100); /* zero timeout selects default, never a busy loop */
    quicly_flexicast_feedback_t feedback = {.member_id = 1, .largest_acknowledged = 0, .ecn_ce_count = 1, .now = 200};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t reduced = output.rate_bytes_per_second;
    ok(reduced > UINT64_MAX / 2 && reduced < UINT64_MAX && output.reason == QUICLY_FLEXICAST_CC_REASON_ECN);
    quicly_flexicast_cc_on_epoch_reset(cc, 201);
    quicly_flexicast_cc_on_packet_sent(cc, 1, 1200, 201);
    feedback.largest_acknowledged = 1;
    feedback.now = 202;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second < reduced);
    quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout > feedback.now);
    quicly_flexicast_cc_free_multicast(cc);

    test_flexicast_cc_t custom = {0};
    config = (quicly_flexicast_cc_config_t){.maximum_datagram_size = 1200, .startup_rate_bytes_per_second = 100000};
    ok(quicly_flexicast_cc_init(&custom.super, &test_cc_type, &config) == 0);
    feedback = (quicly_flexicast_feedback_t){.member_id = 1, .acked_packets = 1, .now = 200};
    quicly_flexicast_cc_on_feedback(&custom.super, &feedback);
    quicly_flexicast_cc_on_timeout(&custom.super, 201);
    quicly_flexicast_cc_get_output(&custom.super, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_NONE);
    config.minimum_rate_bytes_per_second = 2000;
    config.maximum_rate_bytes_per_second = 1000;
    ok(quicly_flexicast_cc_init(&custom.super, &test_cc_type, &config) != 0);
    ok(quicly_flexicast_cc_new_multicast(&config, 100) == NULL);
}

static void test_data_epoch_boundaries(void)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[128], copy[128];
    uint64_t pn, received_pn;
    size_t size, num_acked, num_lost, num_completed, pending;
    ptls_iovec_t payload;
    quicly_flexicast_member_stats_t stats;
    ptls_iovec_t secret_bytes = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size);
    quicly_flexicast_flow_t *source = create_flow_at(1000, secret, 100);
    quicly_flexicast_flow_t *receiver = create_flow_at(1000, secret, 101);

    ok(quicly_flexicast_attach(source, 1, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 100) ==
       QUICLY_FLEXICAST_OK);
    /* reject packets below the advertised first packet number */
    ok(quicly_flexicast_receive_datagram(receiver, packet, size, &payload, &received_pn, 0, 110) == QUICLY_FLEXICAST_ERROR_REPLAY);
    ok(quicly_flexicast_get_ack_deadline(receiver) == INT64_MAX);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 111) ==
       QUICLY_FLEXICAST_OK);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(receiver, packet, size, &payload, &received_pn, 0, 120) == QUICLY_FLEXICAST_OK);
    ok(received_pn == 101);
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &payload, &received_pn, 0, 121) == QUICLY_FLEXICAST_ERROR_REPLAY);

    /* reject bogus ECN totals exceeding packets sent in this epoch */
    quicly_ack_frame_t bogus_ecn = {
        .largest_acknowledged = 101, .smallest_acknowledged = 100, .ack_block_lengths = {2}, .ecn_counts = {0, 0, 10}};
    ok(quicly_flexicast_ack_frame(source, 1, &bogus_ecn, 0, &num_acked, &num_lost, &num_completed, 129) ==
       QUICLY_FLEXICAST_ERROR_INVALID);

    quicly_ack_frame_t ack = {
        .largest_acknowledged = 101, .smallest_acknowledged = 100, .ack_block_lengths = {2}, .ecn_counts = {0, 0, 2}};
    ok(quicly_flexicast_ack_frame(source, 1, &ack, 0, &num_acked, &num_lost, &num_completed, 130) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 2 && num_completed == 2);
    ok(quicly_flexicast_flow_rekey(source, secret_bytes, 101, 140) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_get_next_packet_number(source) == 102 && quicly_flexicast_num_members(source) == 1);
    ok(quicly_flexicast_flow_rekey(receiver, secret_bytes, 101, 140) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_flow_rekey(receiver, secret_bytes, 102, 140) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_ack_deadline(receiver) == INT64_MAX);

    ok(quicly_flexicast_flow_rekey(source, secret_bytes, 102, 140) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 1, 140) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_member_stats(source, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.delivered_packets == 2 && stats.ecn_ce_count == 0 && stats.last_feedback_at == 0);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 150) ==
       QUICLY_FLEXICAST_OK);
    ok(pn == 102);
    ok(quicly_flexicast_receive_datagram(receiver, packet, size, &payload, &received_pn, 0, 155) == QUICLY_FLEXICAST_OK);
    /* ignore stale feedback from the previous epoch */
    ok(quicly_flexicast_ack_frame(source, 1, &ack, 0, &num_acked, &num_lost, &num_completed, 160) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 0 && num_lost == 0 && num_completed == 0);
    ok(quicly_flexicast_get_pending_members(source, 102, &pending) == QUICLY_FLEXICAST_OK && pending == 1);
    ok(quicly_flexicast_get_member_stats(source, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.ecn_ce_count == 0 && stats.last_feedback_at == 0);
    ack = (quicly_ack_frame_t){
        .largest_acknowledged = 102, .smallest_acknowledged = 102, .ack_block_lengths = {1}, .ecn_counts = {0, 0, 1}};
    ok(quicly_flexicast_ack_frame(source, 1, &ack, 0, &num_acked, &num_lost, &num_completed, 170) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1 && num_completed == 1);
    ok(quicly_flexicast_get_member_stats(source, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.delivered_packets == 3 && stats.ecn_ce_count == 1 && stats.last_feedback_at == 170);

    quicly_flexicast_flow_free(receiver);
    quicly_flexicast_flow_free(source);
}

static void test_ack_rtt_largest_only(void)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[128];
    size_t size, num_acked, num_lost, num_completed;
    uint64_t pn;
    quicly_flexicast_member_stats_t stats;
    quicly_flexicast_flow_t *flow = create_flow(1000, secret);
    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    for (int64_t i = 0; i != 2; ++i)
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 100 + i * 10) ==
           QUICLY_FLEXICAST_OK);
    quicly_ack_frame_t ack = {.largest_acknowledged = 1, .smallest_acknowledged = 1, .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &num_acked, &num_lost, &num_completed, 150) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.latest_rtt_msec == 40 && stats.smoothed_rtt_msec == 40);
    ack.smallest_acknowledged = 0;
    ack.ack_block_lengths[0] = 2;
    ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &num_acked, &num_lost, &num_completed, 200) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.latest_rtt_msec == 40 && stats.smoothed_rtt_msec == 40);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 210) ==
       QUICLY_FLEXICAST_OK);
    ack = (quicly_ack_frame_t){.largest_acknowledged = 2, .smallest_acknowledged = 2, .ack_block_lengths = {1}, .ack_delay = 25};
    ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &num_acked, &num_lost, &num_completed, 275) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.latest_rtt_msec == 40 && stats.smoothed_rtt_msec == 40);
    /* subtract full ACK delay from established RTT */
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 300) == 0);
    ack = (quicly_ack_frame_t){.largest_acknowledged = 3, .smallest_acknowledged = 3, .ack_block_lengths = {1}, .ack_delay = 500};
    ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &num_acked, &num_lost, &num_completed, 840) == 0);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0);
    ok(stats.latest_rtt_msec == 40 && stats.smoothed_rtt_msec == 40);
    quicly_flexicast_flow_free(flow);
}

static void test_single_ack_loss_retirement(void)
{
    uint8_t secret[32] = {1}, packet[128];
    test_flexicast_cc_t cc;
    quicly_flexicast_flow_t *flow = create_cc_flow(1000, secret, &cc);
    size_t size, pending;
    uint64_t pn;
    int complete;
    quicly_flexicast_member_stats_t stats;
    ok(quicly_flexicast_attach(flow, 1, 100) == 0);
    ok(quicly_flexicast_attach(flow, 2, 100) == 0);
    for (int64_t i = 0; i != 5; ++i)
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 100 + i) == 0);
    ok(quicly_flexicast_ack_packet(flow, 2, 0, &complete, 110) == 0 && !complete);
    /* retiring packet 0 completes it without marking packet 4 complete */
    ok(quicly_flexicast_ack_packet(flow, 1, 4, &complete, 120) == 0 && !complete);
    ok(test_last_feedback.acked_packets == 1 && test_last_feedback.lost_packets == 2);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0);
    ok(stats.lost_packets == 2 && stats.lost_bytes == size * 2 && stats.largest_acknowledged == 4);
    ok(quicly_flexicast_get_pending_members(flow, 0, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    ok(quicly_flexicast_get_pending_members(flow, 1, &pending) == 0 && pending == 1);
    ok(quicly_flexicast_get_pending_members(flow, 2, &pending) == 0 && pending == 2);
    ok(quicly_flexicast_get_pending_members(flow, 4, &pending) == 0 && pending == 1);
    ok(quicly_flexicast_ack_packet(flow, 1, 3, &complete, 130) == 0 && !complete);
    ok(test_last_feedback.lost_packets == 0);
    ok(quicly_flexicast_ack_packet(flow, 2, 4, &complete, 0) == 0 && complete);
    ok(test_last_feedback.lost_packets == 1);
    ok(quicly_flexicast_get_pending_members(flow, 1, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    quicly_flexicast_flow_free(flow);
}

static void test_ack_range_history(void)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[128], encoded[QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE];
    size_t packet_size, encoded_size;
    uint64_t pn, received_pn;
    ptls_iovec_t payload;
    quicly_ack_frame_t ack;
    quicly_flexicast_flow_t *source = create_flow(1000, secret);
    quicly_flexicast_flow_t *receiver = create_flow(1000, secret);

    ok(quicly_flexicast_attach(source, 1, 0) == QUICLY_FLEXICAST_OK);
    for (size_t i = 0; i <= QUICLY_MAX_ACK_BLOCKS * 2; ++i) {
        ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &packet_size, &pn, 0) ==
           QUICLY_FLEXICAST_OK);
        if (i % 2 == 0) {
            ok(quicly_flexicast_receive_datagram(receiver, packet, packet_size, &payload, &received_pn, 0, (int64_t)i) ==
               QUICLY_FLEXICAST_OK);
            if (i == 0) {
                /* zero clock value is a valid receive timestamp */
                ok(quicly_flexicast_encode_pending_ack(receiver, 1000, encoded, sizeof(encoded), 5, &encoded_size) ==
                   QUICLY_FLEXICAST_OK);
                const uint8_t *src = encoded + 1, *end = encoded + encoded_size;
                ok(quicly_decodev(&src, end) == 1000);
                ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
                ok(ack.ack_delay == (5000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT));
            }
        }
    }
    ok(quicly_flexicast_ack_is_due(receiver, 140));
    ok(quicly_flexicast_get_ack_deadline(receiver) == 0);
    ok(quicly_flexicast_encode_pending_ack(receiver, 1000, encoded, sizeof(encoded), 140, &encoded_size) == QUICLY_FLEXICAST_OK);
    const uint8_t *src = encoded + 1, *end = encoded + encoded_size;
    ok(quicly_decodev(&src, end) == 1000);
    ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
    ok(ack.num_gaps == QUICLY_MAX_ACK_BLOCKS - 1 && ack.smallest_acknowledged == 2 && ack.largest_acknowledged == 128);
    ok(ack.ack_delay == (12000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT));
    quicly_flexicast_ack_sent(receiver);
    ok(!quicly_flexicast_ack_is_due(receiver, 140));
    ok(quicly_flexicast_encode_pending_ack(receiver, 1000, encoded, sizeof(encoded), 140, &encoded_size) == QUICLY_FLEXICAST_OK);
    src = encoded + 1;
    end = encoded + encoded_size;
    ok(quicly_decodev(&src, end) == 1000);
    ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
    ok(ack.num_gaps == QUICLY_MAX_ACK_BLOCKS - 1 && ack.smallest_acknowledged == 2 && ack.largest_acknowledged == 128);
    ok(ack.ack_delay == (12000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT));
    quicly_flexicast_ack_sent(receiver);
    ok(!quicly_flexicast_ack_is_due(receiver, 140) && quicly_flexicast_get_ack_deadline(receiver) == INT64_MAX);

    /* retained history does not force an immediate ACK for each new packet */
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &packet_size, &pn, 0) == 0);
    ok(quicly_flexicast_receive_datagram(receiver, packet, packet_size, &payload, &received_pn, 0, 150) == 0);
    ok(!quicly_flexicast_ack_is_due(receiver, 150) && quicly_flexicast_get_ack_deadline(receiver) == 175);

    quicly_flexicast_flow_free(receiver);
    quicly_flexicast_flow_free(source);
}

static void test_packet_number_limit(void)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0}, packet[128];
    quicly_flexicast_flow_t *flow = create_flow_at(1000, secret, PTLS_QUICINT_MAX);
    uint64_t pn;
    size_t size;
    ok(quicly_flexicast_attach(flow, 1, 0) == 0);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 0) == 0);
    ok(pn == PTLS_QUICINT_MAX && size == quicly_flexicast_datagram_size(flow, 0));
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 0) ==
       QUICLY_FLEXICAST_ERROR_INVALID);
    quicly_flexicast_flow_free(flow);
}

static void regression_send(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t capacity, size_t *size, uint64_t *pn,
                            int64_t now)
{
    uint8_t payload[1000] = {0};
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, capacity, size, pn, now) == 0);
}

static void regression_ack(quicly_flexicast_flow_t *flow, uint64_t member, uint64_t first, uint64_t last, uint64_t delay,
                           int64_t now)
{
    quicly_ack_frame_t ack = {
        .largest_acknowledged = last, .smallest_acknowledged = first, .ack_block_lengths = {last - first + 1}, .ack_delay = delay};
    size_t acked, lost, complete;
    ok(quicly_flexicast_ack_frame(flow, member, &ack, 0, &acked, &lost, &complete, now) == 0);
}

static void test_feedback_clock_and_submission(void)
{
    uint8_t secret[32] = {1}, packet[1300];
    size_t size;
    uint64_t pn;
    uint64_t rates[3];
    for (size_t mode = 0; mode != 3; ++mode) {
        test_flexicast_cc_t cc;
        quicly_flexicast_flow_t *flow = create_cc_flow(1000, secret, &cc);
        ok(quicly_flexicast_attach(flow, 1, 100) == 0);
        regression_send(flow, packet, sizeof(packet), &size, &pn, 100);
        regression_ack(flow, 1, 0, 0, 0, 200);
        for (size_t i = 0; i != 9; ++i)
            regression_send(flow, packet, sizeof(packet), &size, &pn, 201);
        if (mode == 2) {
            regression_ack(flow, 1, 0, 0, 0, 209); /* duplicate cannot move the sampler clock */
            quicly_flexicast_member_stats_t stats;
            ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0 && stats.last_feedback_at == 200);
        }
        if (mode == 1) {
            for (uint64_t n = 1; n <= 8; ++n) {
                regression_ack(flow, 1, n, n, 0, 210);
                quicly_flexicast_member_stats_t stats;
                ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0 && stats.delivery_rate_bytes_per_second == 0);
                ok(test_last_feedback.delivery_rate_sample_epoch == 0);
            }
        } else {
            regression_ack(flow, 1, 1, 8, 0, 210);
        }
        regression_ack(flow, 1, 9, 9, 0, 220); /* close the complete 210 ms bucket */
        quicly_flexicast_member_stats_t stats;
        ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0);
        rates[mode] = stats.delivery_rate_bytes_per_second;
        ok(rates[mode] == size * 8 * 1000 / 101);
        ok(test_last_feedback.delivery_rate_sample_epoch == 1 && test_last_feedback.delivery_rate_bytes_per_second == rates[mode]);
        if (mode == 0) {
            /* CE feedback without new delivery retains the published sample epoch */
            quicly_ack_frame_t ack = {
                .largest_acknowledged = 9, .smallest_acknowledged = 9, .ack_block_lengths = {1}, .ecn_counts = {0, 0, 1}};
            size_t acked, lost, complete;
            ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &acked, &lost, &complete, 221) == 0);
            ok(acked == 0 && test_last_feedback.ecn_ce_count == 1);
            ok(test_last_feedback.delivery_rate_sample_epoch == 1 &&
               test_last_feedback.delivery_rate_bytes_per_second == rates[mode]);

            /* keep learned stats across rekey without exposing a new CC sample epoch */
            uint8_t next_secret[32] = {2};
            ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(next_secret, sizeof(next_secret)), 100, 250) == 0);
            ok(quicly_flexicast_attach(flow, 1, 250) == 0);
            for (int64_t i = 0; i != 3; ++i) {
                regression_send(flow, packet, sizeof(packet), &size, &pn, 300 + i * 10);
                regression_ack(flow, 1, pn, pn, 0, 301 + i * 10);
                ok(test_last_feedback.delivery_rate_sample_epoch == (i == 2 ? 1 : 0));
                ok((test_last_feedback.delivery_rate_bytes_per_second != 0) == (i == 2));
                ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0 && stats.delivery_rate_bytes_per_second != 0);
            }
        }
        quicly_flexicast_flow_free(flow);
    }
    ok(rates[0] == rates[1] && rates[1] == rates[2]);

    quicly_flexicast_flow_t *flow = create_flow(1000, secret);
    ok(quicly_flexicast_attach(flow, 1, 100) == 0);
    ok(quicly_flexicast_attach(flow, 2, 100) == 0);
    regression_send(flow, packet, sizeof(packet), &size, &pn, 100);
    ok(quicly_flexicast_mark_submitted(flow, 1, pn, 110, NULL) == 0);
    ok(quicly_flexicast_mark_submitted(flow, 2, pn, 400, NULL) == 0);
    regression_ack(flow, 1, pn, pn, 0, 120);
    regression_ack(flow, 2, pn, pn, 0, 410);
    quicly_flexicast_member_stats_t stats;
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0 && stats.minimum_rtt_msec == 10 && stats.latest_rtt_msec == 10);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == 0 && stats.minimum_rtt_msec == 10 && stats.latest_rtt_msec == 10);
    regression_send(flow, packet, sizeof(packet), &size, &pn, 500);
    ok(quicly_flexicast_mark_submitted(flow, 0, pn, 600, NULL) == 0);
    regression_ack(flow, 1, pn, pn, 25, 635);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0 && stats.latest_rtt_msec == 10);
    regression_ack(flow, 2, pn, pn, 25, 636);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == 0 && stats.latest_rtt_msec == 11);
    regression_send(flow, packet, sizeof(packet), &size, &pn, 700);
    ok(quicly_flexicast_mark_submitted(flow, 0, pn, 0, NULL) == 0);
    regression_ack(flow, 1, pn, pn, 0, 10000);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0 && stats.latest_rtt_msec == 10);
    quicly_flexicast_flow_free(flow);
}

static void test_submission_timestamp_bound(void)
{
    uint8_t secret[32] = {1}, packet[1300];
    size_t size;
    uint64_t pn;
    quicly_flexicast_flow_t *flow = create_flow(1000, secret);
    for (uint64_t member = 1; member <= 4; ++member)
        ok(quicly_flexicast_attach(flow, member, 100) == 0);
    /* excess replica exceptions beyond 4096 are omitted without unbounded memory */
    for (size_t i = 0; i != QUICLY_FLEXICAST_SENT_WINDOW; ++i) {
        regression_send(flow, packet, sizeof(packet), &size, &pn, 100);
        for (uint64_t member = 1; member <= 4; ++member)
            ok(quicly_flexicast_mark_submitted(flow, member, pn, 110 + (int64_t)member, NULL) == 0);
    }
    for (uint64_t member = 1; member <= 4; ++member) {
        regression_ack(flow, member, pn, pn, 0, 1000);
        quicly_flexicast_member_stats_t stats;
        ok(quicly_flexicast_get_member_stats(flow, member, &stats) == 0 && stats.latest_rtt_msec == 0);
    }
    /* loss processing releases sparse entries so reused slots record timestamps again */
    regression_send(flow, packet, sizeof(packet), &size, &pn, 2000);
    ok(quicly_flexicast_mark_submitted(flow, 1, pn, 2300, NULL) == 0);
    regression_ack(flow, 1, pn, pn, 0, 2310);
    quicly_flexicast_member_stats_t stats;
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == 0 && stats.latest_rtt_msec == 10);
    quicly_flexicast_flow_free(flow);
}

static void decode_feedback(quicly_flexicast_flow_t *flow, int64_t now, quicly_ack_frame_t *ack, uint64_t *type)
{
    uint8_t encoded[QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE];
    size_t size;
    ok(quicly_flexicast_encode_pending_ack(flow, 1000, encoded, sizeof(encoded), now, &size) == 0);
    const uint8_t *src = encoded, *end = encoded + size;
    *type = quicly_decodev(&src, end);
    ok(*type == QUICLY_FRAME_TYPE_PATH_ACK || *type == QUICLY_FRAME_TYPE_PATH_ACK_ECN);
    ok(quicly_decodev(&src, end) == 1000);
    ok(quicly_decode_ack_frame(&src, end, ack, *type == QUICLY_FRAME_TYPE_PATH_ACK_ECN) == 0);
    ok(src + 1 == end && *src == QUICLY_FRAME_TYPE_PING);
}

static void test_feedback_backpressure_and_ecn(void)
{
    uint8_t secret[32] = {1}, packet[1300], duplicate[1300];
    size_t size;
    uint64_t pn, received_pn, type;
    ptls_iovec_t payload;
    quicly_ack_frame_t ack;
    quicly_flexicast_flow_t *tx = create_flow(1000, secret), *rx = create_flow(1000, secret);
    ok(quicly_flexicast_attach(tx, 1, 100) == 0);
    /* leave ACKs pending as if the reliable control queue were full */
    for (size_t i = 0; i != 201; ++i) {
        regression_send(tx, packet, sizeof(packet), &size, &pn, 100 + (int64_t)i);
        if (i % 2 == 0)
            ok(quicly_flexicast_receive_datagram(rx, packet, size, &payload, &received_pn, 0, 110 + (int64_t)i) == 0);
    }
    decode_feedback(rx, 400, &ack, &type);
    ok(ack.num_gaps + 1 == QUICLY_MAX_ACK_BLOCKS);
    quicly_flexicast_ack_sent(rx);
    decode_feedback(rx, 400, &ack, &type);
    ok(ack.largest_acknowledged == 200 && ack.smallest_acknowledged == 74 && ack.num_gaps == QUICLY_MAX_ACK_BLOCKS - 1);
    ok(ack.ack_delay == (90000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT));
    quicly_flexicast_ack_sent(rx);
    ok(quicly_flexicast_get_ack_deadline(rx) == INT64_MAX);
    regression_send(tx, packet, sizeof(packet), &size, &pn, 500);
    ok(quicly_flexicast_receive_datagram(rx, packet, size, &payload, &received_pn, 0, 510) == 0);
    decode_feedback(rx, 520, &ack, &type);
    ok(ack.largest_acknowledged == 201 && ack.num_gaps == QUICLY_MAX_ACK_BLOCKS - 1 && ack.ack_block_lengths[0] == 2);
    ok(ack.ack_delay == (10000 >> QUICLY_LOCAL_ACK_DELAY_EXPONENT));
    quicly_flexicast_flow_free(tx);
    quicly_flexicast_flow_free(rx);

    tx = create_flow(1000, secret);
    rx = create_flow(1000, secret);
    ok(quicly_flexicast_attach(tx, 1, 100) == 0);
    const uint8_t marks[] = {2, 1, 3, 3};
    for (size_t i = 0; i != sizeof(marks); ++i) {
        regression_send(tx, packet, sizeof(packet), &size, &pn, 100 + (int64_t)i);
        memcpy(duplicate, packet, size);
        ok(quicly_flexicast_receive_datagram(rx, packet, size, &payload, &received_pn, marks[i], 110 + (int64_t)i) == 0);
    }
    ok(quicly_flexicast_receive_datagram(rx, duplicate, size, &payload, &received_pn, 3, 120) == QUICLY_FLEXICAST_ERROR_REPLAY);
    decode_feedback(rx, 130, &ack, &type);
    ok(type == QUICLY_FRAME_TYPE_PATH_ACK_ECN && ack.ecn_counts[0] == 1 && ack.ecn_counts[1] == 1 && ack.ecn_counts[2] == 2);
    size_t acked, lost, complete;
    ok(quicly_flexicast_ack_frame(tx, 1, &ack, 0, &acked, &lost, &complete, 140) == 0);
    quicly_flexicast_member_stats_t stats;
    ok(quicly_flexicast_get_member_stats(tx, 1, &stats) == 0);
    uint64_t epoch = stats.feedback_epoch;
    ok(stats.ecn_ce_count == 2);
    ok(quicly_flexicast_ack_frame(tx, 1, &ack, 0, &acked, &lost, &complete, 141) == 0);
    ok(quicly_flexicast_get_member_stats(tx, 1, &stats) == 0 && stats.feedback_epoch == epoch && stats.ecn_ce_count == 2);
    quicly_flexicast_ack_sent(rx);
    regression_send(tx, packet, sizeof(packet), &size, &pn, 150);
    ok(quicly_flexicast_receive_datagram(rx, packet, size, &payload, &received_pn, 2, 160) == 0);
    quicly_ack_frame_t old_ack;
    decode_feedback(rx, 170, &old_ack, &type);
    ok(old_ack.ecn_counts[0] == 2 && old_ack.ecn_counts[1] == 1 && old_ack.ecn_counts[2] == 2);
    secret[0] = 2;
    ok(quicly_flexicast_flow_rekey(tx, ptls_iovec_init(secret, sizeof(secret)), 10, 180) == 0);
    ok(quicly_flexicast_flow_rekey(rx, ptls_iovec_init(secret, sizeof(secret)), 10, 180) == 0);
    ok(quicly_flexicast_attach(tx, 1, 180) == 0);
    ok(quicly_flexicast_ack_frame(tx, 1, &old_ack, 0, &acked, &lost, &complete, 181) == 0);
    ok(quicly_flexicast_get_member_stats(tx, 1, &stats) == 0 && stats.ecn_ce_count == 0 && acked == 0);
    regression_send(tx, packet, sizeof(packet), &size, &pn, 190);
    ok(quicly_flexicast_receive_datagram(rx, packet, size, &payload, &received_pn, 3, 200) == 0);
    decode_feedback(rx, 210, &ack, &type);
    ok(ack.ecn_counts[0] == 0 && ack.ecn_counts[1] == 0 && ack.ecn_counts[2] == 1);
    ok(quicly_flexicast_ack_frame(tx, 1, &ack, 0, &acked, &lost, &complete, 220) == 0);
    ok(quicly_flexicast_get_member_stats(tx, 1, &stats) == 0 && stats.ecn_ce_count == 1 && stats.feedback_epoch == epoch + 1);
    quicly_flexicast_flow_free(tx);
    quicly_flexicast_flow_free(rx);
}

#include "flexicast-provenance.inc"

static void test_sparse_control_and_member_lifecycle(void)
{
    uint8_t secret[32] = {0x33}, packet[1300];
    size_t size, acked, lost, completed, pending, num_ranges;
    uint64_t pn, received_pn, history_lb, ecn_counts[3];
    int64_t largest_at;
    const quicly_range_t *ranges;
    ptls_iovec_t payload;
    quicly_flexicast_member_stats_t stats;

    /* test receive state borrowing and history_lower_bound updates */
    quicly_flexicast_flow_t *tx = create_flow_at(2000, secret, 50);
    quicly_flexicast_flow_t *rx = create_flow_at(2000, secret, 50);
    ok(quicly_flexicast_attach(tx, 1, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_receive_state(rx, &ranges, &num_ranges, &history_lb, &largest_at, ecn_counts) == QUICLY_FLEXICAST_OK);
    ok(num_ranges == 0 && history_lb == 50 && largest_at == 0);
    for (size_t i = 0; i != 132; ++i) {
        regression_send(tx, packet, sizeof(packet), &size, &pn, 100 + (int64_t)i);
        if (i % 2 == 0)
            ok(quicly_flexicast_receive_datagram(rx, packet, size, &payload, &received_pn, 3, 200 + (int64_t)i) == 0);
    }
    ok(quicly_flexicast_get_receive_state(rx, &ranges, &num_ranges, &history_lb, &largest_at, ecn_counts) == QUICLY_FLEXICAST_OK);
    ok(num_ranges == 66 && history_lb == 50 && largest_at == 330 && ecn_counts[2] == 66);
    quicly_flexicast_ack_sent(rx);
    ok(quicly_flexicast_get_receive_state(rx, &ranges, &num_ranges, &history_lb, &largest_at, ecn_counts) == QUICLY_FLEXICAST_OK);
    ok(num_ranges == QUICLY_MAX_ACK_BLOCKS && history_lb == ranges[0].start && history_lb > 50);
    quicly_flexicast_flow_free(rx);
    quicly_flexicast_flow_free(tx);

    /* test ack_frame flags, deferred loss commit, and detach cleanup */
    test_flexicast_cc_t cc;
    quicly_flexicast_flow_t *flow = create_cc_flow(2001, secret, &cc);
    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 2, 100) == QUICLY_FLEXICAST_OK);
    for (int i = 0; i != 6; ++i)
        regression_send(flow, packet, sizeof(packet), &size, &pn, 100 + i * 10);

    quicly_ack_frame_t ack = {.largest_acknowledged = 5, .smallest_acknowledged = 5, .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0x80u, &acked, &lost, &completed, 200) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_ack_frame(
           flow, 1, &ack, QUICLY_FLEXICAST_ACK_OMIT_RTT | QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE | QUICLY_FLEXICAST_ACK_DEFER_LOSS,
           &acked, &lost, &completed, 200) == QUICLY_FLEXICAST_OK);
    ok(acked == 1 && lost == 0 && completed == 0);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.latest_rtt_msec == 0 && test_last_feedback.latest_rtt_msec == 0 && test_last_feedback.delivery_rate_sample_epoch == 0);

    /* commit loss only from pn 1..2, leaving pn 0 unresolved below coverage */
    ok(quicly_flexicast_commit_ack_loss(flow, 1, 1, 5, &lost, &completed, 205) == QUICLY_FLEXICAST_OK);
    ok(lost == 2 && completed == 0);
    ok(quicly_flexicast_ack_packet(flow, 2, 0, &(int){0}, 205) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(flow, 0, &pending) == QUICLY_FLEXICAST_OK && pending == 1);
    ok(quicly_flexicast_detach(flow, 1, 206) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(flow, 0, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);

    /* test suspend, resume, reset_member_path, and note_member_feedback */
    regression_ack(flow, 2, 5, 5, 0, 210);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == QUICLY_FLEXICAST_OK && stats.latest_rtt_msec > 0);
    uint64_t epoch_before = stats.feedback_epoch;
    ok(quicly_flexicast_note_member_feedback(flow, 2, 210) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == QUICLY_FLEXICAST_OK && stats.feedback_epoch == epoch_before);
    ok(quicly_flexicast_note_member_feedback(flow, 2, 220) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.feedback_epoch == epoch_before + 1 && stats.last_feedback_at == 220 && test_last_feedback.acked_packets == 0);

    regression_send(flow, packet, sizeof(packet), &size, &pn, 225); /* pn 6 sent before suspend/reset */
    uint64_t pre_suspend_pn;
    regression_send(flow, packet, sizeof(packet), &size, &pre_suspend_pn, 226); /* pn 7 retired via abandon while suspended */
    uint64_t pre_suspend_ack_pn;
    regression_send(flow, packet, sizeof(packet), &size, &pre_suspend_ack_pn,
                    227); /* pn 8 retired via ack_packet while suspended */
    ok(quicly_flexicast_suspend(flow, 2, 230) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(flow) == 0);
    ok(quicly_flexicast_note_member_feedback(flow, 2, 235) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    /* suspended members can still retire pre-suspension packets via ack_frame (flags = 0), ack_packet, and abandon_datagram */
    ack = (quicly_ack_frame_t){.largest_acknowledged = 4, .smallest_acknowledged = 4, .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(flow, 2, &ack, 0, &acked, &lost, &completed, 235) == QUICLY_FLEXICAST_OK);
    ok(acked == 1);
    int abandoned_complete = 0, acked_complete = 0;
    ok(quicly_flexicast_abandon_datagram(flow, 2, pre_suspend_pn, &abandoned_complete) == QUICLY_FLEXICAST_OK &&
       abandoned_complete);
    ok(quicly_flexicast_ack_packet(flow, 2, pre_suspend_ack_pn, &acked_complete, 236) == QUICLY_FLEXICAST_OK && acked_complete);

    /* resume resets path baselines and suppresses old-route samples and CC ACK counts below path_sample_floor */
    ok(quicly_flexicast_resume(flow, 2, 240) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(flow) == 1);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == QUICLY_FLEXICAST_OK && stats.latest_rtt_msec == 0);
    uint64_t cc_events_before = cc.feedback_events;
    regression_ack(flow, 2, 6, 6, 0, 250);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == QUICLY_FLEXICAST_OK);
    /* pre-reset packet 6 still increments lifetime delivered_packets without feeding new-route CC growth */
    ok(stats.latest_rtt_msec == 0 && cc.feedback_events == cc_events_before);
    regression_send(flow, packet, sizeof(packet), &size, &pn, 260); /* pn 9 on new route */
    regression_ack(flow, 2, pn, pn, 0, 275);
    ok(quicly_flexicast_get_member_stats(flow, 2, &stats) == QUICLY_FLEXICAST_OK && stats.latest_rtt_msec == 15);
    ok(cc.feedback_events == cc_events_before + 1 && test_last_feedback.acked_packets == 1);

    quicly_flexicast_flow_free(flow);
}

static int reject_add_cc_enabled;
static int reject_add_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    (void)cc;
    (void)member_id;
    (void)now;
    return reject_add_cc_enabled ? -1 : 0;
}

static void test_sparse_control_regressions(void)
{
    uint8_t secret[32] = {0x44}, packet[1300];
    size_t size, acked, lost, completed, pending;
    uint64_t pn;
    quicly_flexicast_member_stats_t stats;
    quicly_flexicast_send_context_t ctx = provenance_context(500000, 1, 0);
    test_flexicast_cc_t cc;

    /* deferred loss + commit_ack_loss preserves in-progress delivery-rate buckets */
    quicly_flexicast_flow_t *flow = create_cc_flow(2002, secret, &cc);
    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    for (int step = 0; step != 3; ++step) {
        for (int j = 0; j != 4; ++j)
            provenance_send(flow, 100 + step * 50 + j * 5, &ctx, &size);
        uint64_t first = (uint64_t)step * 4, last = first + 3;
        quicly_ack_frame_t ack = {.largest_acknowledged = last, .smallest_acknowledged = first, .ack_block_lengths = {4}};
        ok(quicly_flexicast_ack_frame(flow, 1, &ack, QUICLY_FLEXICAST_ACK_DEFER_LOSS, &acked, &lost, &completed, 130 + step * 50) ==
           QUICLY_FLEXICAST_OK);
        /* duplicate OMIT_DELIVERY_RATE frame does not wipe the active bucket */
        ok(quicly_flexicast_ack_frame(flow, 1, &ack, QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE | QUICLY_FLEXICAST_ACK_DEFER_LOSS,
                                      &acked, &lost, &completed, 131 + step * 50) == QUICLY_FLEXICAST_OK);
        ok(quicly_flexicast_commit_ack_loss(flow, 1, 0, last, &lost, &completed, 132 + step * 50) == QUICLY_FLEXICAST_OK);
        ok(lost == 0);
    }
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
    ok(stats.delivery_rate_bytes_per_second > 0 && test_last_feedback.delivery_rate_sample_epoch == 1);

    /* reset_member_path hides stale sample epochs until fresh samples complete and isolates old-route packets */
    uint64_t old_rate_epoch = test_last_feedback.delivery_rate_sample_epoch;
    uint64_t old_rtt_epoch = test_last_feedback.rtt_sample_epoch;
    uint64_t old_pn_lost = provenance_send(flow, 300, &ctx, &size); /* pn 12: lost on old route */
    uint64_t old_pn_late = provenance_send(flow, 305, &ctx, &size); /* pn 13: delayed on old route */
    ok(quicly_flexicast_reset_member_path(flow, 1, 310) == QUICLY_FLEXICAST_OK);

    /* untracked new-route packet before bucket completion reports zero rate/RTT sample epochs */
    uint64_t new_pn0 = provenance_send(flow, 320, &ctx, &size); /* pn 14 */
    ok(quicly_flexicast_mark_submitted(flow, 0, new_pn0, 0, NULL) == QUICLY_FLEXICAST_OK);
    regression_ack(flow, 1, new_pn0, new_pn0, 0, 330);
    ok(test_last_feedback.delivery_rate_sample_epoch == 0 && test_last_feedback.rtt_sample_epoch == 0);

    /* establish clean new-route clock (retiring old_pn_lost without CC loss) and span ACK across old_pn_late + new_pn2 */
    uint64_t new_pn1 = provenance_send(flow, 340, &ctx, &size); /* pn 15 retires pn 12 */
    quicly_ack_frame_t ack1 = {.largest_acknowledged = new_pn1, .smallest_acknowledged = new_pn1, .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(flow, 1, &ack1, 0, &acked, &lost, &completed, 350) == QUICLY_FLEXICAST_OK);
    ok(acked == 1 && lost == 1 && test_last_feedback.lost_packets == 0);
    ok(quicly_flexicast_get_pending_members(flow, old_pn_lost, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    ok(test_last_feedback.rtt_sample_epoch == old_rtt_epoch + 1);
    uint64_t new_pn2 = provenance_send(flow, 360, &ctx, &size); /* pn 16 */
    quicly_ack_frame_t span = {
        .largest_acknowledged = new_pn2, .smallest_acknowledged = old_pn_late, .ack_block_lengths = {new_pn2 - old_pn_late + 1}};
    ok(quicly_flexicast_ack_frame(flow, 1, &span, 0, &acked, &lost, &completed, 370) == QUICLY_FLEXICAST_OK);
    ok(acked == 2 && lost == 0 && test_last_feedback.acked_packets == 1 &&
       test_last_feedback.delivery_rate_sample_epoch == old_rate_epoch + 1);

    uint64_t new_pn3 = provenance_send(flow, 380, &ctx, &size); /* pn 17 closes the [350..370] bucket */
    regression_ack(flow, 1, new_pn3, new_pn3, 0, 390);
    ok(test_last_feedback.delivery_rate_sample_epoch == old_rate_epoch + 2);
    ok(test_last_feedback.delivery_sample_bytes == size);
    ok(test_last_feedback.delivery_sample_sent_at_start == 340);
    ok((test_last_feedback.delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_VALID) != 0);
    quicly_flexicast_flow_free(flow);

    /* suspend followed by attach preserves loss_cursor so pre-suspend packets retire cleanly */
    flow = create_cc_flow(2003, secret, &cc);
    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 2, 100) == QUICLY_FLEXICAST_OK);
    regression_send(flow, packet, sizeof(packet), &size, &pn, 100);
    ok(quicly_flexicast_ack_packet(flow, 2, 0, &(int){0}, 105) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_suspend(flow, 1, 110) == QUICLY_FLEXICAST_OK);
    for (int i = 0; i != 3; ++i)
        regression_send(flow, packet, sizeof(packet), &size, &pn, 120 + i);
    ok(quicly_flexicast_attach(flow, 1, 130) == QUICLY_FLEXICAST_OK);
    regression_send(flow, packet, sizeof(packet), &size, &pn, 140);
    regression_ack(flow, 1, 4, 4, 0, 150);
    ok(quicly_flexicast_get_pending_members(flow, 0, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);
    quicly_flexicast_flow_free(flow);

    /* validate loss threshold < send window, exclusive CC binding, and borrowed CC cleanup on flow_free */
    quicly_flexicast_cc_config_t small_cc_cfg = {
        .maximum_members = 2, .startup_rate_bytes_per_second = 50000, .maximum_datagram_size = 1200};
    quicly_flexicast_cc_t *borrowed_cc = quicly_flexicast_cc_new_multicast(&small_cc_cfg, 100);
    quicly_flexicast_config_t invalid_cfg = {
        .flow_id = make_test_flow_id(2004),
        .cipher_suite = &ptls_openssl_aes128gcmsha256,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(secret, sizeof(secret)),
        .packet_reordering_threshold = QUICLY_FLEXICAST_SENT_WINDOW,
    };
    ok(quicly_flexicast_flow_create(&flow, &invalid_cfg) == QUICLY_FLEXICAST_ERROR_INVALID);
    invalid_cfg.packet_reordering_threshold = QUICLY_FLEXICAST_SENT_WINDOW - 1;
    invalid_cfg.max_members = 4;
    invalid_cfg.cc = borrowed_cc;
    ok(quicly_flexicast_flow_create(&flow, &invalid_cfg) == QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT);
    invalid_cfg.max_members = 2;
    quicly_flexicast_flow_t *flow_a = NULL, *flow_b = NULL;
    ok(quicly_flexicast_flow_create(&flow_a, &invalid_cfg) == QUICLY_FLEXICAST_OK);
    invalid_cfg.flow_id = make_test_flow_id(2005);
    /* concurrent attachment of one controller to two flows is rejected */
    ok(quicly_flexicast_flow_create(&flow_b, &invalid_cfg) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_attach(flow_a, 10, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow_a, 20, 100) == QUICLY_FLEXICAST_OK);
    /* freeing flow_a unbinds borrowed_cc and resets its epoch so flow_b can reuse it cleanly */
    quicly_flexicast_flow_free(flow_a);
    quicly_flexicast_cc_output_t borrowed_out;
    quicly_flexicast_cc_get_output(borrowed_cc, &borrowed_out);
    ok(borrowed_out.limiting_member_id == 0 && borrowed_out.next_timeout == INT64_MAX);
    ok(quicly_flexicast_flow_create(&flow_b, &invalid_cfg) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow_b, 30, 110) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow_b, 40, 110) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_flow_free(flow_b);
    quicly_flexicast_cc_free_multicast(borrowed_cc);

    /* suspended or re-attached members do not stall active receivers at the 2048-slot ring wrap */
    for (int reattach_before_wrap = 0; reattach_before_wrap != 2; ++reattach_before_wrap) {
        flow = create_flow(2006 + (uint64_t)reattach_before_wrap, secret);
        ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
        ok(quicly_flexicast_attach(flow, 2, 100) == QUICLY_FLEXICAST_OK);
        regression_send(flow, packet, sizeof(packet), &size, &pn, 100);
        ok(quicly_flexicast_ack_packet(flow, 2, pn, &(int){0}, 101) == QUICLY_FLEXICAST_OK);
        ok(quicly_flexicast_suspend(flow, 1, 102) == QUICLY_FLEXICAST_OK);
        int wrap_ok = 1;
        for (size_t step = 1; step <= QUICLY_FLEXICAST_SENT_WINDOW + 4; ++step) {
            if (reattach_before_wrap && step == QUICLY_FLEXICAST_SENT_WINDOW - 1)
                wrap_ok &= quicly_flexicast_attach(flow, 1, 200) == QUICLY_FLEXICAST_OK;
            wrap_ok &= quicly_flexicast_send_datagram(flow, ptls_iovec_init("x", 1), packet, sizeof(packet), &size, &pn,
                                                      100 + (int64_t)step) == QUICLY_FLEXICAST_OK;
            wrap_ok &= quicly_flexicast_ack_packet(flow, 2, pn, &(int){0}, 101 + (int64_t)step) == QUICLY_FLEXICAST_OK;
        }
        ok(wrap_ok);
        ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK && stats.lost_packets == 1);
        quicly_flexicast_flow_free(flow);
    }

    /* continuously active unacknowledged member still enforces SEND_WINDOW at wrap */
    flow = create_flow(2008, secret);
    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 2, 100) == QUICLY_FLEXICAST_OK);
    for (size_t step = 0; step != QUICLY_FLEXICAST_SENT_WINDOW; ++step) {
        regression_send(flow, packet, sizeof(packet), &size, &pn, 100 + (int64_t)step);
        ok(quicly_flexicast_ack_packet(flow, 2, pn, &(int){0}, 101 + (int64_t)step) == QUICLY_FLEXICAST_OK);
    }
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init("x", 1), packet, sizeof(packet), &size, &pn, 3000) ==
       QUICLY_FLEXICAST_ERROR_SEND_WINDOW);
    quicly_flexicast_flow_free(flow);

    /* failed path reset suspends the member so flow and controller stay consistent */
    static quicly_flexicast_cc_type_t reject_add_type = {
        .name = "reject-add",
        .on_member_added = reject_add_on_member_added,
    };
    quicly_flexicast_cc_t custom_cc = {0};
    quicly_flexicast_cc_config_t custom_cc_cfg = {.maximum_members = 4};
    ok(quicly_flexicast_cc_init(&custom_cc, &reject_add_type, &custom_cc_cfg) == 0);
    invalid_cfg.flow_id = make_test_flow_id(2009);
    invalid_cfg.cc = &custom_cc;
    reject_add_cc_enabled = 0;
    ok(quicly_flexicast_flow_create(&flow, &invalid_cfg) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 7, 100) == QUICLY_FLEXICAST_OK && quicly_flexicast_num_members(flow) == 1);
    reject_add_cc_enabled = 1;
    ok(quicly_flexicast_reset_member_path(flow, 7, 110) == QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT);
    ok(quicly_flexicast_num_members(flow) == 0);
    ok(quicly_flexicast_attach(flow, 7, 120) == QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT);
    reject_add_cc_enabled = 0;
    ok(quicly_flexicast_attach(flow, 7, 130) == QUICLY_FLEXICAST_OK && quicly_flexicast_num_members(flow) == 1);
    quicly_flexicast_flow_free(flow);

    /* in-place ack_delay updates support live changes, 0 ms immediate ACK, and >UINT32_MAX clamping */
    quicly_flexicast_flow_t *tx_delay = create_flow(2010, secret), *rx_delay = create_flow(2010, secret);
    ptls_iovec_t rx_payload;
    uint64_t rx_pn;
    ok(quicly_flexicast_set_ack_delay(NULL, 10) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_set_ack_delay(rx_delay, PTLS_QUICINT_MAX + 1) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_attach(tx_delay, 1, 100) == QUICLY_FLEXICAST_OK);
    regression_send(tx_delay, packet, sizeof(packet), &size, &pn, 100);
    ok(quicly_flexicast_receive_datagram(rx_delay, packet, size, &rx_payload, &rx_pn, 0, 100) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_ack_sent(rx_delay);
    regression_send(tx_delay, packet, sizeof(packet), &size, &pn, 110);
    ok(quicly_flexicast_receive_datagram(rx_delay, packet, size, &rx_payload, &rx_pn, 0, 110) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_ack_deadline(rx_delay) == 135 && !quicly_flexicast_ack_is_due(rx_delay, 115));
    ok(quicly_flexicast_set_ack_delay(rx_delay, 5) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_ack_deadline(rx_delay) == 115 && quicly_flexicast_ack_is_due(rx_delay, 115));
    quicly_flexicast_ack_sent(rx_delay);
    ok(quicly_flexicast_set_ack_delay(rx_delay, 0) == QUICLY_FLEXICAST_OK);
    regression_send(tx_delay, packet, sizeof(packet), &size, &pn, 120);
    ok(quicly_flexicast_receive_datagram(rx_delay, packet, size, &rx_payload, &rx_pn, 0, 120) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_ack_deadline(rx_delay) == 120 && quicly_flexicast_ack_is_due(rx_delay, 120));
    ok(quicly_flexicast_set_ack_delay(rx_delay, (uint64_t)UINT32_MAX + 500) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_ack_deadline(rx_delay) == 120 + (int64_t)UINT32_MAX);
    quicly_flexicast_flow_free(rx_delay);
    quicly_flexicast_flow_free(tx_delay);

    /* later APP_LIMITED or HOST_LIMITED sends do not taint an earlier completed send interval */
    flow = create_cc_flow(2011, secret, &cc);
    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_send_context_t app_limited = provenance_context(500000, 1, QUICLY_FLEXICAST_SAMPLE_APP_LIMITED);
    provenance_send(flow, 100, &ctx, &size); /* pn 0 */
    regression_ack(flow, 1, 0, 0, 0, 110);
    provenance_send(flow, 120, &ctx, &size);         /* pn 1 */
    regression_ack(flow, 1, 1, 1, 0, 130);           /* bucket spans [100, 120] */
    provenance_send(flow, 160, &app_limited, &size); /* pn 2 sent after [100, 120] ended, before closing ACK arrives */
    regression_ack(flow, 1, 2, 2, 0, 170);           /* closes [100, 120] */
    ok(test_last_feedback.delivery_rate_sample_epoch == 1);
    ok(test_last_feedback.delivery_sample_sent_at_start == 100 && test_last_feedback.delivery_sample_sent_at_end == 120);
    ok((test_last_feedback.delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_APP_LIMITED) == 0);
    provenance_send(flow, 180, &ctx, &size); /* pn 3 */
    regression_ack(flow, 1, 3, 3, 0, 190);   /* closes [120, 160], which contains pn 2 */
    ok(test_last_feedback.delivery_rate_sample_epoch == 2);
    ok((test_last_feedback.delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_APP_LIMITED) != 0);
    quicly_flexicast_flow_free(flow);
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

    test_congestion_feedback();
    test_ack_aggregation();
    test_builtin_controllers();
    test_scalable_members();
    test_member_churn();
    test_controller_boundaries();
    test_packet_number_limit();
    test_data_epoch_boundaries();
    test_ack_range_history();
    test_ack_rtt_largest_only();
    test_single_ack_loss_retirement();
    test_flexicast_cc_regressions();
    test_flexicast_crypto();
    test_flexicast_packets();
    test_feedback_clock_and_submission();
    test_submission_timestamp_bound();
    test_feedback_backpressure_and_ecn();
    test_feedback_provenance();
    test_sparse_control_and_member_lifecycle();
    test_sparse_control_regressions();

    memset(secret, 0x5a, ptls_openssl_aes128gcmsha256.hash->digest_size);
    memset(wrong_secret, 0xa5, ptls_openssl_aes128gcmsha256.hash->digest_size);
    quicly_flexicast_flow_t *source = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *receiver_a = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *receiver_b = create_flow(flow_id, secret);
    quicly_flexicast_flow_t *wrong_receiver = create_flow(flow_id, wrong_secret);

    quicly_flexicast_flow_id_t expected_fid = make_test_flow_id(flow_id);
    ok(quicly_flexicast_flow_id_equal(quicly_flexicast_get_flow_id(source), &expected_fid));
    ok(quicly_flexicast_attach(source, 101, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 202, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 202, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(source) == 2);

    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(payload_bytes, sizeof(payload_bytes)), encrypted, sizeof(encrypted),
                                      &encrypted_size, &packet_number, 0) == QUICLY_FLEXICAST_OK);
    ok(packet_number == 0 && quicly_flexicast_get_next_packet_number(source) == 1);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == 2);

    memcpy(receiver_a_packet, encrypted, encrypted_size);
    memcpy(receiver_b_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(receiver_a, receiver_a_packet, encrypted_size, &received, &received_packet_number, 0, 0) ==
       QUICLY_FLEXICAST_OK);
    ok(received_packet_number == packet_number && received.len == sizeof(payload_bytes));
    ok(memcmp(received.base, payload_bytes, sizeof(payload_bytes)) == 0);
    ok(quicly_flexicast_receive_datagram(receiver_b, receiver_b_packet, encrypted_size, &received, &received_packet_number, 0, 0) ==
       QUICLY_FLEXICAST_OK);
    ok(received_packet_number == packet_number && memcmp(received.base, payload_bytes, sizeof(payload_bytes)) == 0);

    memcpy(bad_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(receiver_a, bad_packet, encrypted_size, &received, &received_packet_number, 0, 0) ==
       QUICLY_FLEXICAST_ERROR_REPLAY);
    memcpy(bad_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(wrong_receiver, bad_packet, encrypted_size, &received, &received_packet_number, 0, 0) ==
       QUICLY_FLEXICAST_ERROR_CRYPTO);
    memcpy(bad_packet, encrypted, encrypted_size);
    bad_packet[1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver_b, bad_packet, encrypted_size, &received, &received_packet_number, 0, 0) ==
       QUICLY_FLEXICAST_ERROR_WRONG_FLOW);

    ok(quicly_flexicast_ack_packet(source, 101, packet_number, &complete, 0) == QUICLY_FLEXICAST_OK && !complete);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == 1);
    ok(quicly_flexicast_ack_packet(source, 101, packet_number, &complete, 0) == QUICLY_FLEXICAST_ERROR_REPLAY);
    ok(quicly_flexicast_ack_packet(source, 202, packet_number, &complete, 0) == QUICLY_FLEXICAST_OK && complete);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);

    ok(quicly_flexicast_detach(source, 202, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_num_members(source) == 1);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(payload_bytes, 0), encrypted, sizeof(encrypted), &encrypted_size,
                                      &packet_number, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_OK && pending == 1);

    size_t num_acked, num_completed;
    quicly_ack_frame_t ack_frame = {
        .largest_acknowledged = packet_number, .smallest_acknowledged = packet_number, .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(source, 101, &ack_frame, 0, &num_acked, NULL, &num_completed, 0) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1 && num_completed == 1);
    ok(quicly_flexicast_get_pending_members(source, packet_number, &pending) == QUICLY_FLEXICAST_ERROR_NOT_FOUND);

    uint64_t range_packets[3];
    for (size_t i = 0; i != 3; ++i) {
        ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(payload_bytes, 0), encrypted, sizeof(encrypted), &encrypted_size,
                                          range_packets + i, 0) == QUICLY_FLEXICAST_OK);
    }
    ack_frame = (quicly_ack_frame_t){.largest_acknowledged = range_packets[2],
                                     .smallest_acknowledged = range_packets[0],
                                     .num_gaps = 1,
                                     .ack_block_lengths = {1, 1},
                                     .gaps = {1}};
    ok(quicly_flexicast_ack_frame(source, 101, &ack_frame, 0, &num_acked, NULL, &num_completed, 0) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 2 && num_completed == 2);
    ok(quicly_flexicast_get_pending_members(source, range_packets[1], &pending) == QUICLY_FLEXICAST_OK && pending == 1);
    ack_frame = (quicly_ack_frame_t){
        .largest_acknowledged = range_packets[1], .smallest_acknowledged = range_packets[1], .ack_block_lengths = {1}};
    ok(quicly_flexicast_ack_frame(source, 101, &ack_frame, 0, &num_acked, NULL, &num_completed, 0) == QUICLY_FLEXICAST_OK);
    ok(num_acked == 1 && num_completed == 1);

    /* verify first_packet_number across the 16-bit truncated PN boundary */
    quicly_flexicast_flow_t *late_source = create_flow_at(flow_id, secret, 65536);
    quicly_flexicast_flow_t *late_receiver = create_flow_at(flow_id, secret, 65536);
    ok(quicly_flexicast_attach(late_source, 303, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(late_source, ptls_iovec_init(payload_bytes, sizeof(payload_bytes)), encrypted,
                                      sizeof(encrypted), &encrypted_size, &packet_number, 0) == QUICLY_FLEXICAST_OK);
    ok(packet_number == 65536);
    memcpy(receiver_a_packet, encrypted, encrypted_size);
    ok(quicly_flexicast_receive_datagram(late_receiver, receiver_a_packet, encrypted_size, &received, &received_packet_number, 0,
                                         0) == QUICLY_FLEXICAST_OK);
    ok(received_packet_number == 65536 && memcmp(received.base, payload_bytes, sizeof(payload_bytes)) == 0);
    quicly_flexicast_flow_free(late_receiver);
    quicly_flexicast_flow_free(late_source);

    quicly_flexicast_flow_free(wrong_receiver);
    quicly_flexicast_flow_free(receiver_b);
    quicly_flexicast_flow_free(receiver_a);
    quicly_flexicast_flow_free(source);
}
