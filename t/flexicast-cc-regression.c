#include "picotest.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/flexicast.h"
#include "quicly/flexicast_cc.h"
#include "../lib/flexicast_member_map.h"

static quicly_flexicast_cc_config_t regression_config(void)
{
    return (quicly_flexicast_cc_config_t){.maximum_members = 64,
                                          .startup_rate_bytes_per_second = 100000,
                                          .minimum_rate_bytes_per_second = 2000,
                                          .maximum_rate_bytes_per_second = 1000000,
                                          .maximum_datagram_size = 1200,
                                          .feedback_timeout_msec = 100};
}

static void test_multicast_zero_time(void)
{
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_t *cc;
    quicly_flexicast_cc_output_t output;

    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_multicast, &config, 0) == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 0);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == 100);
    for (int64_t now = 100; now <= 300; now += 100)
        quicly_flexicast_cc_on_timeout(cc, now);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 50000 && output.timeout_reduction_events == 1);
    quicly_flexicast_cc_on_epoch_reset(cc, 0);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == 100);

    quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 1, .lost_packets = 1, .now = 0};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 35000);
    feedback.epoch = 2;
    feedback.now = 1;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 35000 && output.loss_reduction_events == 1);

    quicly_flexicast_cc_on_epoch_reset(cc, 0);
    feedback = (quicly_flexicast_feedback_t){.member_id = 1, .epoch = 1, .ecn_ce_count = 1, .now = 0};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t rate = output.rate_bytes_per_second;
    feedback.epoch = 2;
    feedback.now = 1;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == rate && output.ecn_reduction_events == 1);
    quicly_flexicast_cc_free(cc);
}

static void test_multicast_feedback_epochs(void)
{
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_t *cc;
    quicly_flexicast_cc_output_t output;
    config.startup_rate_bytes_per_second = 2000000;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_multicast, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 100);
    quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 2, .lost_packets = 1, .now = 200};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 700000); /* reduce the clamped starting rate */
    feedback.now = 400;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback.epoch = 1;
    feedback.now = 500;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 700000 && output.loss_reduction_events == 1);
    /* replayed reports do not defer the missing-feedback deadline */
    quicly_flexicast_cc_on_timeout(cc, 500);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == 600);
    quicly_flexicast_cc_on_epoch_reset(cc, 510);
    feedback.now = 520;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 490000 && output.loss_reduction_events == 2);
    feedback.epoch = 2;
    feedback.lost_packets = 0;
    feedback.acked_packets = 1;
    feedback.now = 530;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t rate = output.rate_bytes_per_second;
    feedback.now = 540;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == rate && output.ack_growth_events == 1);
    quicly_flexicast_cc_free(cc);
}

static void test_adaptive_rate_limit(void)
{
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_t *cc;
    quicly_flexicast_cc_output_t output;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 100);
    quicly_flexicast_cc_hints_t hints = {.aggregate_rate_limit_bytes_per_second = 12000};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 1, .acked_packets = 1, .now = 200};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 12000);
    ok(output.rate_limit_reduction_events == 1 && output.ack_growth_events == 0);
    int bounded = 1;
    for (unsigned i = 0; i != 24; ++i) {
        quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
        quicly_flexicast_cc_get_output(cc, &output);
        bounded &= output.rate_bytes_per_second <= 12000;
    }
    ok(bounded); /* floor recovery also honors the ongoing aggregate ceiling */
    quicly_flexicast_cc_free(cc);
}

static void test_adaptive_hint_epochs(void)
{
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_t *cc;
    quicly_flexicast_cc_output_t output;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 100);
    quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 1, .acked_packets = 1, .now = 110};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_hints_t hints = {
        .aggregate_rate_limit_bytes_per_second = 10000, .external_load_epoch = 10, .external_load_queued_bytes = 4800};
    quicly_flexicast_cc_set_hints(cc, &hints, 120);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 10000);
    hints.aggregate_rate_limit_bytes_per_second = 0;
    quicly_flexicast_cc_set_hints(cc, &hints, 121);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 10000); /* the same measurement cannot trigger another recovery increase */
    hints.external_load_epoch = 11;
    quicly_flexicast_cc_set_hints(cc, &hints, 122);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 10000);
    /* older clean measurements do not clear the current load episode */
    for (uint64_t epoch = 1; epoch != 4; ++epoch) {
        hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = epoch};
        quicly_flexicast_cc_set_hints(cc, &hints, 130 + (int64_t)epoch);
    }
    feedback.epoch = 2;
    feedback.delivery_rate_bytes_per_second = 10000;
    feedback.now = 200;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 10000);
    ok((output.reason & QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN) != 0);
    for (uint64_t epoch = 12; epoch != 15; ++epoch) {
        hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = epoch};
        quicly_flexicast_cc_set_hints(cc, &hints, 210 + (int64_t)epoch);
    }
    feedback.epoch = 3;
    feedback.now = 250;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second > 10000);
    quicly_flexicast_cc_free(cc);
}

static void test_adaptive_sender_growth(void)
{
    const struct {
        uint32_t active_senders;
        uint64_t increase[2];
    } cases[] = {{0, {125000, 125000000}},
                 {1, {125000, 125000000}},
                 {4, {62500, 62500000}},
                 {9, {41666, 41666666}},
                 {16, {31250, 31250000}},
                 {18446744, {1200, 29103}},
                 {18446745, {1200, 29103}},
                 {UINT32_MAX, {1200, 1907}}};
    const uint64_t rates[] = {1000000, 1000000000};

    /* exercise both the datagram floor and proportional growth around the old scaled-sender overflow */
    for (size_t i = 0; i != PTLS_ELEMENTSOF(cases); ++i) {
        for (size_t j = 0; j != PTLS_ELEMENTSOF(rates); ++j) {
            quicly_flexicast_cc_config_t config = regression_config();
            quicly_flexicast_cc_t *cc;
            quicly_flexicast_cc_output_t output;
            config.startup_rate_bytes_per_second = rates[j];
            config.maximum_rate_bytes_per_second = 0;
            ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 0) == 0);
            quicly_flexicast_cc_on_member_added(cc, 1, 0);
            quicly_flexicast_cc_hints_t hints = {.active_senders = cases[i].active_senders};
            quicly_flexicast_cc_set_hints(cc, &hints, 0);
            quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 1, .acked_packets = 1, .now = 100};
            quicly_flexicast_cc_on_feedback(cc, &feedback);
            quicly_flexicast_cc_get_output(cc, &output);
            ok(output.rate_bytes_per_second == rates[j] + cases[i].increase[j]);
            ok(output.ack_growth_events == 1);
            quicly_flexicast_cc_free(cc);
        }
    }
}

static void test_adaptive_maximum_rate_recovery(void)
{
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_t *cc;
    quicly_flexicast_cc_output_t output;
    config.startup_rate_bytes_per_second = UINT64_MAX;
    config.minimum_rate_bytes_per_second = UINT64_MAX / 2;
    config.maximum_rate_bytes_per_second = 0;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 0) == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 0);
    quicly_flexicast_cc_get_output(cc, &output);
    for (unsigned i = 0; i != 3; ++i) {
        quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
        quicly_flexicast_cc_get_output(cc, &output);
    }
    ok(output.rate_bytes_per_second == UINT64_MAX / 2);
    quicly_flexicast_cc_free(cc);
}

static void test_member_map_collisions(void)
{
    flexicast_member_map_t map = {0};
    uint64_t ids[32];
    ok(flexicast_member_map_init(&map, 32) == 0);
    /* all probe chains wrap around the end of the table */
    for (uint64_t id = 1, count = 0; count != 32; ++id) {
        if ((flexicast_member_hash(id) & (map.capacity - 1)) == map.capacity - 1)
            ids[count++] = id;
    }
    for (size_t i = 0; i != 32; ++i)
        flexicast_member_map_set(&map, ids[i], i);
    int intact = 1;
    for (size_t i = 0; i != 32; ++i) {
        size_t removed = i * 13 % 32;
        flexicast_member_map_remove(&map, ids[removed]);
        intact &= flexicast_member_map_find(&map, ids[removed]) == -1;
        for (size_t j = 0; j != 32; ++j) {
            if (j != removed)
                intact &= flexicast_member_map_find(&map, ids[j]) == (int)j;
        }
        flexicast_member_map_set(&map, ids[removed], removed);
    }
    ok(intact);
    flexicast_member_map_dispose(&map);
}

static quicly_flexicast_flow_t *create_regression_flow(quicly_flexicast_cc_type_t *type)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0};
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t config = {.flow_id = 1000,
                                        .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                        .crypto_engine = &quicly_default_crypto_engine,
                                        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
                                        .cc_type = type,
                                        .cc_config = regression_config(),
                                        .now = 100};
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    return flow;
}

static void test_rekey_inactive_members(void)
{
    quicly_flexicast_cc_type_t *types[] = {&quicly_flexicast_cc_type_multicast, &quicly_flexicast_cc_type_adaptive};
    for (size_t t = 0; t != sizeof(types) / sizeof(types[0]); ++t) {
        quicly_flexicast_flow_t *flow = create_regression_flow(types[t]);
        uint8_t packet[128], next_secret[PTLS_MAX_DIGEST_SIZE] = {1};
        uint64_t pn;
        size_t size, acked, lost, completed;
        quicly_flexicast_cc_output_t output;
        quicly_flexicast_member_stats_t stats;
        ok(quicly_flexicast_attach_at(flow, 1, 100) == QUICLY_FLEXICAST_OK);
        ok(quicly_flexicast_attach_at(flow, 2, 100) == QUICLY_FLEXICAST_OK);
        for (unsigned i = 0; i != 4; ++i)
            ok(quicly_flexicast_send_datagram_at(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 110) ==
               QUICLY_FLEXICAST_OK);
        quicly_ack_frame_t ack = {
            .largest_acknowledged = 3, .smallest_acknowledged = 3, .ack_block_lengths = {1}, .ecn_counts = {0, 0, 1}};
        ok(quicly_flexicast_ack_frame_at(flow, 1, &ack, &acked, &lost, &completed, 200) == QUICLY_FLEXICAST_OK);
        quicly_flexicast_cc_get_flow_output(flow, &output);
        uint64_t learned_rate = output.rate_bytes_per_second;
        ok(learned_rate == 85000);
        ack = (quicly_ack_frame_t){.largest_acknowledged = 3, .smallest_acknowledged = 0, .ack_block_lengths = {4}};
        ok(quicly_flexicast_ack_frame_at(flow, 2, &ack, &acked, &lost, &completed, 201) == QUICLY_FLEXICAST_OK);

        ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(next_secret, ptls_openssl_aes128gcmsha256.hash->digest_size), 4,
                                       300) == QUICLY_FLEXICAST_OK);
        quicly_flexicast_cc_get_flow_output(flow, &output);
        ok(quicly_flexicast_num_members(flow) == 0 && output.next_timeout == INT64_MAX);
        ok(output.limiting_member_id == 0);
        uint64_t idle_rate = output.rate_bytes_per_second;
        quicly_flexicast_cc_on_flow_timeout(flow, 1300);
        quicly_flexicast_cc_get_flow_output(flow, &output);
        ok(output.timeout_reduction_events == 0 && output.rate_bytes_per_second == idle_rate);

        /* suspended member 1 does not constrain rate or collect missing-feedback probes */
        ok(quicly_flexicast_attach_at(flow, 2, 1400) == QUICLY_FLEXICAST_OK);
        quicly_flexicast_cc_get_flow_output(flow, &output);
        ok(output.next_timeout > 1400 && output.next_timeout != INT64_MAX);
        for (int64_t now = 1500; now <= 1700; now += 100) {
            ok(quicly_flexicast_send_datagram_at(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, now - 10) ==
               QUICLY_FLEXICAST_OK);
            ack = (quicly_ack_frame_t){.largest_acknowledged = pn, .smallest_acknowledged = pn, .ack_block_lengths = {1}};
            ok(quicly_flexicast_ack_frame_at(flow, 2, &ack, &acked, &lost, &completed, now - 1) == QUICLY_FLEXICAST_OK);
            quicly_flexicast_cc_on_flow_timeout(flow, now);
        }
        quicly_flexicast_cc_get_flow_output(flow, &output);
        ok(output.timeout_reduction_events == 0);
        if (types[t] == &quicly_flexicast_cc_type_multicast)
            ok(output.limiting_member_id == 2 && output.rate_bytes_per_second > learned_rate);

        /* suspending preserves path history */
        ok(quicly_flexicast_detach_at(flow, 2, 1800) == QUICLY_FLEXICAST_OK);
        ok(quicly_flexicast_attach_at(flow, 1, 1800) == QUICLY_FLEXICAST_OK);
        quicly_flexicast_cc_get_flow_output(flow, &output);
        ok(output.rate_bytes_per_second == learned_rate && output.next_timeout > 1800);
        ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK && stats.delivered_packets == 1);
        quicly_flexicast_flow_free(flow);
    }
}

static void test_duplicate_ack_delivery_clock(void)
{
    quicly_flexicast_cc_type_t *types[] = {&quicly_flexicast_cc_type_multicast, &quicly_flexicast_cc_type_adaptive};
    for (size_t t = 0; t != sizeof(types) / sizeof(types[0]); ++t) {
        uint64_t delivery_rate = 0;
        for (unsigned replay = 0; replay != 2; ++replay) {
            quicly_flexicast_flow_t *flow = create_regression_flow(types[t]);
            uint8_t packet[256], payload[100] = {0};
            uint64_t pn;
            size_t size, acked, lost, completed;
            quicly_flexicast_member_stats_t stats;
            ok(quicly_flexicast_attach_at(flow, 1, 100) == QUICLY_FLEXICAST_OK);
            for (unsigned i = 0; i != 3; ++i)
                ok(quicly_flexicast_send_datagram_at(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size,
                                                     &pn, 100 + i) == QUICLY_FLEXICAST_OK);
            quicly_ack_frame_t ack = {.largest_acknowledged = 0, .smallest_acknowledged = 0, .ack_block_lengths = {1}};
            ok(quicly_flexicast_ack_frame_at(flow, 1, &ack, &acked, &lost, &completed, 200) == QUICLY_FLEXICAST_OK);
            if (replay) {
                ok(quicly_flexicast_ack_frame_at(flow, 1, &ack, &acked, &lost, &completed, 299) == QUICLY_FLEXICAST_OK);
                ok(acked == 0 && lost == 0 && completed == 0);
                ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
                ok(stats.last_feedback_at == 200 && stats.feedback_epoch == 1);
            }
            ack.largest_acknowledged = ack.smallest_acknowledged = 1;
            ok(quicly_flexicast_ack_frame_at(flow, 1, &ack, &acked, &lost, &completed, 300) == QUICLY_FLEXICAST_OK);
            ack.largest_acknowledged = ack.smallest_acknowledged = 2;
            ok(quicly_flexicast_ack_frame_at(flow, 1, &ack, &acked, &lost, &completed, 400) == QUICLY_FLEXICAST_OK);
            ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
            ok(stats.delivery_rate_bytes_per_second == size * 10 && stats.feedback_epoch == 3);
            if (replay)
                ok(stats.delivery_rate_bytes_per_second == delivery_rate);
            else
                delivery_rate = stats.delivery_rate_bytes_per_second;
            quicly_flexicast_flow_free(flow);
        }
    }
}

static void test_suspend_legacy_controller(void)
{
    struct st_quicly_flexicast_cc_type_t type = quicly_flexicast_cc_type_multicast;
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_t *cc;
    quicly_flexicast_cc_output_t output;
    type.on_member_suspended = NULL;
    ok(quicly_flexicast_cc_create(&cc, &type, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 100);
    quicly_flexicast_cc_on_member_suspended(cc, 1, 200);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == INT64_MAX && output.limiting_member_id == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 300);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == 400 && output.limiting_member_id == 1);
    quicly_flexicast_cc_free(cc);
}

void test_flexicast_cc_regressions(void)
{
    subtest("multicast-zero-time", test_multicast_zero_time);
    subtest("multicast-feedback-epochs", test_multicast_feedback_epochs);
    subtest("adaptive-rate-limit", test_adaptive_rate_limit);
    subtest("adaptive-hint-epochs", test_adaptive_hint_epochs);
    subtest("adaptive-sender-growth", test_adaptive_sender_growth);
    subtest("adaptive-maximum-rate-recovery", test_adaptive_maximum_rate_recovery);
    subtest("member-map-collisions", test_member_map_collisions);
    subtest("rekey-inactive-members", test_rekey_inactive_members);
    subtest("duplicate-ack-delivery-clock", test_duplicate_ack_delivery_clock);
    subtest("suspend-legacy-controller", test_suspend_legacy_controller);
}
