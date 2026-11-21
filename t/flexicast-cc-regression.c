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

static void test_multicast_zero_time_and_idle(void)
{
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&config, 0);
    quicly_flexicast_cc_output_t output;

    ok(cc != NULL);
    ok(quicly_flexicast_cc_on_member_added(cc, 1, 0) == 0);
    quicly_flexicast_cc_get_output(cc, &output);
    /* idle group has no packets awaiting feedback and does not decay its rate */
    ok(output.next_timeout == INT64_MAX);
    for (int64_t now = 100; now <= 600; now += 100)
        quicly_flexicast_cc_on_timeout(cc, now);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100000 && output.reason == QUICLY_FLEXICAST_CC_REASON_NONE);

    /* sending a packet arms the feedback deadline at 0 + 100 ms */
    quicly_flexicast_cc_on_packet_sent(cc, 0, 1200, 0);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == 100);
    for (int64_t now = 100; now <= 300; now += 100)
        quicly_flexicast_cc_on_timeout(cc, now);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 50000 && output.reason == QUICLY_FLEXICAST_CC_REASON_TIMEOUT);

    /* once the sent packet is acknowledged, the timer disarms and further idle periods do not halve the rate */
    quicly_flexicast_feedback_t caught_up = {
        .member_id = 1, .epoch = 1, .largest_acknowledged = 0, .acked_packets = 1, .acked_bytes = 1200, .now = 310};
    quicly_flexicast_cc_on_feedback(cc, &caught_up);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == INT64_MAX);
    uint64_t post_ack_rate = output.rate_bytes_per_second;
    for (int64_t now = 410; now <= 1010; now += 100)
        quicly_flexicast_cc_on_timeout(cc, now);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == post_ack_rate && output.next_timeout == INT64_MAX &&
       output.reason == QUICLY_FLEXICAST_CC_REASON_NONE);
    /* sending another packet rearms the feedback timer */
    quicly_flexicast_cc_on_packet_sent(cc, 1, 1200, 1050);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == 1150);

    quicly_flexicast_cc_on_epoch_reset(cc, 0);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == INT64_MAX);

    quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 1, .lost_packets = 1, .now = 0};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t after_loss = post_ack_rate * 7 / 10;
    ok(output.rate_bytes_per_second == after_loss && output.reason == QUICLY_FLEXICAST_CC_REASON_LOSS);
    feedback.epoch = 2;
    feedback.now = 1;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == after_loss);

    quicly_flexicast_cc_on_epoch_reset(cc, 0);
    feedback = (quicly_flexicast_feedback_t){.member_id = 1, .epoch = 1, .ecn_ce_count = 1, .now = 0};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t rate = output.rate_bytes_per_second;
    ok(rate < after_loss && output.reason == QUICLY_FLEXICAST_CC_REASON_ECN);
    feedback.epoch = 2;
    feedback.now = 1;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == rate);
    quicly_flexicast_cc_free_multicast(cc);
}

static void test_multicast_ack_grouping_invariance(void)
{
    uint64_t rates[2] = {0};
    for (int split = 0; split != 2; ++split) {
        quicly_flexicast_cc_config_t config = regression_config();
        quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&config, 100);
        quicly_flexicast_cc_output_t output;
        ok(cc != NULL);
        ok(quicly_flexicast_cc_on_member_added(cc, 1, 100) == 0);
        if (!split) {
            quicly_flexicast_feedback_t fb = {.member_id = 1,
                                              .epoch = 1,
                                              .largest_acknowledged = 7,
                                              .acked_packets = 8,
                                              .acked_bytes = 8 * 1200,
                                              .minimum_rtt_msec = 20,
                                              .latest_rtt_msec = 20,
                                              .smoothed_rtt_msec = 20,
                                              .now = 120};
            quicly_flexicast_cc_on_feedback(cc, &fb);
        } else {
            for (uint64_t i = 0; i != 8; ++i) {
                quicly_flexicast_feedback_t fb = {.member_id = 1,
                                                  .epoch = i + 1,
                                                  .largest_acknowledged = i,
                                                  .acked_packets = 1,
                                                  .acked_bytes = 1200,
                                                  .minimum_rtt_msec = 20,
                                                  .latest_rtt_msec = 20,
                                                  .smoothed_rtt_msec = 20,
                                                  .now = 120 + (int64_t)i};
                quicly_flexicast_cc_on_feedback(cc, &fb);
            }
        }
        quicly_flexicast_cc_get_output(cc, &output);
        rates[split] = output.rate_bytes_per_second;
        quicly_flexicast_cc_free_multicast(cc);
    }
    ok(rates[0] > 100000 && rates[1] > 100000);
    /* 1x8-packet ACK and 8x1-packet ACKs for the same 9600 bytes stay tightly aligned */
    uint64_t diff = rates[0] > rates[1] ? rates[0] - rates[1] : rates[1] - rates[0];
    ok(diff <= rates[0] / 20);
}

static void test_multicast_feedback_epochs(void)
{
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_output_t output;
    config.startup_rate_bytes_per_second = 2000000;
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&config, 100);
    ok(cc != NULL);
    ok(quicly_flexicast_cc_on_member_added(cc, 1, 100) == 0);
    quicly_flexicast_cc_on_packet_sent(cc, 0, 1200, 150);
    quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 2, .largest_acknowledged = 0, .lost_packets = 1, .now = 200};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 700000); /* reduce the clamped starting rate */
    quicly_flexicast_cc_on_packet_sent(cc, 1, 1200, 210);
    feedback.now = 400;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback.epoch = 1;
    feedback.now = 500;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 700000 && output.reason == QUICLY_FLEXICAST_CC_REASON_NONE);
    /* replayed reports do not defer the missing-feedback deadline */
    quicly_flexicast_cc_on_timeout(cc, 500);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.next_timeout == 600);
    quicly_flexicast_cc_on_epoch_reset(cc, 510);
    feedback.now = 520;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 490000 && output.reason == QUICLY_FLEXICAST_CC_REASON_LOSS);
    feedback.epoch = 2;
    feedback.lost_packets = 0;
    feedback.acked_packets = 1;
    feedback.acked_bytes = 1200;
    feedback.now = 530;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    uint64_t rate = output.rate_bytes_per_second;
    ok(rate > 490000 && output.reason == QUICLY_FLEXICAST_CC_REASON_ACK);
    feedback.now = 540;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == rate && output.reason == QUICLY_FLEXICAST_CC_REASON_NONE);
    quicly_flexicast_cc_free_multicast(cc);
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

static quicly_flexicast_flow_t *create_regression_flow(quicly_flexicast_cc_t **out_cc)
{
    static const uint8_t fid[2] = {0x03, 0xe8};
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0};
    quicly_flexicast_cc_config_t cc_cfg = regression_config();
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&cc_cfg, 100);
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t config = {.flow_id = quicly_flexicast_flow_id_init(fid, sizeof(fid)),
                                        .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                        .crypto_engine = &quicly_default_crypto_engine,
                                        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
                                        .cc = cc,
                                        .now = 100};
    ok(cc != NULL);
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    *out_cc = cc;
    return flow;
}

static void test_rekey_inactive_members(void)
{
    quicly_flexicast_cc_t *cc = NULL;
    quicly_flexicast_flow_t *flow = create_regression_flow(&cc);
    uint8_t packet[128], next_secret[PTLS_MAX_DIGEST_SIZE] = {1};
    uint64_t pn;
    size_t size, acked, lost, completed;
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_member_stats_t stats;

    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 2, 100) == QUICLY_FLEXICAST_OK);
    for (unsigned i = 0; i != 4; ++i)
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 110) ==
           QUICLY_FLEXICAST_OK);
    quicly_ack_frame_t ack = {
        .largest_acknowledged = 3, .smallest_acknowledged = 3, .ack_block_lengths = {1}, .ecn_counts = {0, 0, 1}};
    ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &acked, &lost, &completed, 200) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    uint64_t learned_rate = output.rate_bytes_per_second;
    ok(learned_rate == 85000);
    ack = (quicly_ack_frame_t){.largest_acknowledged = 3, .smallest_acknowledged = 0, .ack_block_lengths = {4}};
    ok(quicly_flexicast_ack_frame(flow, 2, &ack, 0, &acked, &lost, &completed, 201) == QUICLY_FLEXICAST_OK);

    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(next_secret, ptls_openssl_aes128gcmsha256.hash->digest_size), 4, 300) ==
       QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(quicly_flexicast_num_members(flow) == 0 && output.next_timeout == INT64_MAX);
    ok(output.limiting_member_id == 0);
    uint64_t idle_rate = output.rate_bytes_per_second;
    quicly_flexicast_cc_on_flow_timeout(flow, 1300);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_NONE && output.rate_bytes_per_second == idle_rate);

    /* suspended member 1 does not constrain rate or collect missing-feedback probes */
    ok(quicly_flexicast_attach(flow, 2, 1400) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == INT64_MAX);
    for (int64_t now = 1500; now <= 1700; now += 100) {
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, now - 10) ==
           QUICLY_FLEXICAST_OK);
        ack = (quicly_ack_frame_t){.largest_acknowledged = pn, .smallest_acknowledged = pn, .ack_block_lengths = {1}};
        ok(quicly_flexicast_ack_frame(flow, 2, &ack, 0, &acked, &lost, &completed, now - 1) == QUICLY_FLEXICAST_OK);
        quicly_flexicast_cc_on_flow_timeout(flow, now);
    }
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.reason == QUICLY_FLEXICAST_CC_REASON_NONE);
    ok(output.limiting_member_id == 2 && output.rate_bytes_per_second > learned_rate);

    /* suspending preserves path history */
    ok(quicly_flexicast_detach(flow, 2, 1800) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1, 1800) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == learned_rate);
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK && stats.delivered_packets == 1);
    quicly_flexicast_flow_free(flow);
    quicly_flexicast_cc_free_multicast(cc);
}

static void test_rekey_16k_member_replacement(void)
{
    static const uint8_t fid[4] = {0x16, 0x38, 0x40, 0x01};
    uint8_t secret0[32] = {1}, secret1[32] = {2};
    quicly_flexicast_cc_config_t cc_cfg = regression_config();
    cc_cfg.maximum_members = QUICLY_FLEXICAST_HARD_MAX_MEMBERS;
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&cc_cfg, 0);
    quicly_flexicast_flow_t *flow = NULL;
    quicly_flexicast_config_t cfg = {.flow_id = quicly_flexicast_flow_id_init(fid, sizeof(fid)),
                                     .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                     .crypto_engine = &quicly_default_crypto_engine,
                                     .traffic_secret = ptls_iovec_init(secret0, sizeof(secret0)),
                                     .max_members = QUICLY_FLEXICAST_HARD_MAX_MEMBERS,
                                     .cc = cc};
    ok(cc != NULL && quicly_flexicast_flow_create(&flow, &cfg) == QUICLY_FLEXICAST_OK);
    int attached = 1;
    for (uint64_t id = 1; id <= QUICLY_FLEXICAST_HARD_MAX_MEMBERS; ++id)
        attached &= quicly_flexicast_attach(flow, id, 0) == QUICLY_FLEXICAST_OK;
    ok(attached && quicly_flexicast_num_members(flow) == QUICLY_FLEXICAST_HARD_MAX_MEMBERS);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secret1, sizeof(secret1)), 1, 1) == QUICLY_FLEXICAST_OK);

    int replaced = 1;
    for (uint64_t id = 1; id <= QUICLY_FLEXICAST_HARD_MAX_MEMBERS; ++id)
        replaced &= quicly_flexicast_attach(flow, QUICLY_FLEXICAST_HARD_MAX_MEMBERS + id, 2) == QUICLY_FLEXICAST_OK;
    ok(replaced && quicly_flexicast_num_members(flow) == QUICLY_FLEXICAST_HARD_MAX_MEMBERS);

    quicly_flexicast_flow_free(flow);
    quicly_flexicast_cc_free_multicast(cc);
}

static void test_duplicate_ack_delivery_clock(void)
{
    uint64_t delivery_rate = 0;
    for (unsigned replay = 0; replay != 2; ++replay) {
        quicly_flexicast_cc_t *cc = NULL;
        quicly_flexicast_flow_t *flow = create_regression_flow(&cc);
        uint8_t packet[256], payload[100] = {0};
        uint64_t pn;
        size_t size, acked, lost, completed;
        quicly_flexicast_member_stats_t stats;
        ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
        for (unsigned i = 0; i != 3; ++i)
            ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size, &pn,
                                              100 + i) == QUICLY_FLEXICAST_OK);
        quicly_ack_frame_t ack = {.largest_acknowledged = 0, .smallest_acknowledged = 0, .ack_block_lengths = {1}};
        ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &acked, &lost, &completed, 200) == QUICLY_FLEXICAST_OK);
        if (replay) {
            ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &acked, &lost, &completed, 299) == QUICLY_FLEXICAST_OK);
            ok(acked == 0 && lost == 0 && completed == 0);
            ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
            ok(stats.last_feedback_at == 200 && stats.feedback_epoch == 1);
        }
        ack.largest_acknowledged = ack.smallest_acknowledged = 1;
        ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &acked, &lost, &completed, 300) == QUICLY_FLEXICAST_OK);
        ack.largest_acknowledged = ack.smallest_acknowledged = 2;
        ok(quicly_flexicast_ack_frame(flow, 1, &ack, 0, &acked, &lost, &completed, 400) == QUICLY_FLEXICAST_OK);
        ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK);
        ok(stats.delivery_rate_bytes_per_second == size * 10 && stats.feedback_epoch == 3);
        if (replay)
            ok(stats.delivery_rate_bytes_per_second == delivery_rate);
        else
            delivery_rate = stats.delivery_rate_bytes_per_second;
        quicly_flexicast_flow_free(flow);
        quicly_flexicast_cc_free_multicast(cc);
    }
}

typedef struct st_legacy_cc_t {
    quicly_flexicast_cc_t super;
    uint64_t active_member;
} legacy_cc_t;

static int legacy_on_member_added(quicly_flexicast_cc_t *_cc, uint64_t member_id, int64_t now)
{
    legacy_cc_t *cc = (legacy_cc_t *)_cc;
    cc->active_member = member_id;
    cc->super.output.limiting_member_id = member_id;
    cc->super.output.next_timeout = now + cc->super.config.feedback_timeout_msec;
    return 0;
}

static void legacy_on_member_removed(quicly_flexicast_cc_t *_cc, uint64_t member_id, int64_t now)
{
    legacy_cc_t *cc = (legacy_cc_t *)_cc;
    (void)now;
    if (cc->active_member == member_id) {
        cc->active_member = 0;
        cc->super.output.limiting_member_id = 0;
        cc->super.output.next_timeout = INT64_MAX;
    }
}

static void test_suspend_legacy_controller(void)
{
    static quicly_flexicast_cc_type_t type = {
        .name = "legacy",
        .on_member_added = legacy_on_member_added,
        .on_member_removed = legacy_on_member_removed,
    };
    legacy_cc_t cc = {0};
    quicly_flexicast_cc_config_t config = regression_config();
    quicly_flexicast_cc_output_t output;

    ok(quicly_flexicast_cc_init(&cc.super, &type, &config) == 0);
    ok(quicly_flexicast_cc_on_member_added(&cc.super, 1, 100) == 0);
    /* controller without on_member_suspended falls back cleanly to on_member_removed */
    quicly_flexicast_cc_on_member_suspended(&cc.super, 1, 200);
    quicly_flexicast_cc_get_output(&cc.super, &output);
    ok(output.next_timeout == INT64_MAX && output.limiting_member_id == 0);
    ok(quicly_flexicast_cc_on_member_added(&cc.super, 1, 300) == 0);
    quicly_flexicast_cc_get_output(&cc.super, &output);
    ok(output.next_timeout == 400 && output.limiting_member_id == 1);
}

static void test_abandon_and_exclusive_reuse(void)
{
    quicly_flexicast_cc_t *cc = NULL;
    quicly_flexicast_flow_t *flow = create_regression_flow(&cc);
    quicly_flexicast_cc_output_t output;
    uint8_t packet[256], payload[64] = {0};
    uint64_t pn0, pn1;
    size_t size;
    int complete = 0;

    ok(quicly_flexicast_attach(flow, 1, 100) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size, &pn0, 110) ==
       QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == 210);

    /* abandoning the last pending datagram retires the member's feedback obligation */
    ok(quicly_flexicast_abandon_datagram(flow, 1, pn0, &complete) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == INT64_MAX && output.rate_bytes_per_second == 100000);
    for (int64_t now = 210; now <= 510; now += 100)
        quicly_flexicast_cc_on_flow_timeout(flow, now);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == 100000 && output.next_timeout == INT64_MAX);

    /* abandoning a newer packet while an older packet remains pending keeps feedback armed until all are retired */
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size, &pn0, 600) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size, &pn1, 620) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_abandon_datagram(flow, 1, pn1, &complete) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == 700);
    ok(quicly_flexicast_abandon_datagram(flow, 1, pn0, &complete) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == INT64_MAX);

    /* old-route ECN feedback after reset_member_path updates stats without cutting the new route's rate */
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size, &pn0, 700) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_reset_member_path(flow, 1, 710) == QUICLY_FLEXICAST_OK);
    quicly_ack_frame_t old_ce_ack = {
        .largest_acknowledged = pn0, .smallest_acknowledged = pn0, .ack_block_lengths = {1}, .ecn_counts = {0, 0, 1}};
    ok(quicly_flexicast_ack_frame(flow, 1, &old_ce_ack, 0, NULL, NULL, NULL, 720) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_member_stats_t stats;
    ok(quicly_flexicast_get_member_stats(flow, 1, &stats) == QUICLY_FLEXICAST_OK && stats.ecn_ce_count == 1);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == 100000 && output.next_timeout == INT64_MAX);

    /* sequential controller reuse after sending starts with a clean epoch so an idle second flow never times out */
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size, &pn1, 730) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_ack_packet(flow, 1, pn1, &complete, 740) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_flow_free(flow);

    static const uint8_t fid2[4] = {0x99, 0x88, 0x77, 0x66};
    uint8_t secret[32] = {0x5a};
    quicly_flexicast_flow_t *flow2 = NULL;
    quicly_flexicast_config_t cfg2 = {.flow_id = quicly_flexicast_flow_id_init(fid2, sizeof(fid2)),
                                      .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                      .crypto_engine = &quicly_default_crypto_engine,
                                      .traffic_secret = ptls_iovec_init(secret, sizeof(secret)),
                                      .cc = cc,
                                      .now = 800};
    ok(quicly_flexicast_flow_create(&flow2, &cfg2) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow2, 2, 800) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_get_flow_output(flow2, &output);
    ok(output.next_timeout == INT64_MAX && output.rate_bytes_per_second == 100000);
    for (int64_t now = 900; now <= 1300; now += 100)
        quicly_flexicast_cc_on_flow_timeout(flow2, now);
    quicly_flexicast_cc_get_flow_output(flow2, &output);
    ok(output.rate_bytes_per_second == 100000 && output.next_timeout == INT64_MAX);
    quicly_flexicast_flow_free(flow2);
    quicly_flexicast_cc_free_multicast(cc);
}

static size_t positional_cc_feedback_calls;
static size_t positional_cc_timeout_calls;

static void positional_cc_on_feedback(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback)
{
    (void)cc;
    (void)feedback;
    ++positional_cc_feedback_calls;
}

static void positional_cc_on_timeout(quicly_flexicast_cc_t *cc, int64_t now)
{
    (void)cc;
    (void)now;
    ++positional_cc_timeout_calls;
}

/* reordered ACKs, out-of-order abandonments, positional CC table init, and window-shrink growth remainder */
static void test_reordered_pending_and_remainder(void)
{
    static const uint8_t fid[4] = {0x77, 0x66, 0x55, 0x44};
    uint8_t secret[32] = {0x42};
    quicly_flexicast_cc_config_t default_cc_cfg = {.startup_rate_bytes_per_second = 100000, .feedback_timeout_msec = 300};
    quicly_flexicast_config_t cfg = {.flow_id = quicly_flexicast_flow_id_init(fid, sizeof(fid)),
                                     .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                     .crypto_engine = &quicly_default_crypto_engine,
                                     .traffic_secret = ptls_iovec_init(secret, sizeof(secret)),
                                     .now = 0};

    /* reordered ACK of pn 1 while pn 0 stays pending must keep the feedback timer armed */
    quicly_flexicast_cc_t *cc = quicly_flexicast_cc_new_multicast(&default_cc_cfg, 0);
    ok(cc != NULL);
    cfg.cc = cc;
    quicly_flexicast_flow_t *flow = NULL;
    ok(quicly_flexicast_flow_create(&flow, &cfg) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1, 0) == QUICLY_FLEXICAST_OK);
    uint8_t packet[256], payload = 0x55;
    size_t size = 0;
    uint64_t pn0 = 0, pn1 = 0, pn2 = 0;
    int complete = 0;
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(&payload, 1), packet, sizeof(packet), &size, &pn0, 10) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(&payload, 1), packet, sizeof(packet), &size, &pn1, 20) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_ack_packet(flow, 1, pn1, &complete, 25) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == 325);
    ok(quicly_flexicast_ack_packet(flow, 1, pn0, &complete, 30) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == INT64_MAX);
    quicly_flexicast_flow_free(flow);
    quicly_flexicast_cc_free_multicast(cc);

    /* abandoning an older timed-out packet leaves deadline anchored on the remaining packet sent at 1010 ms */
    cc = quicly_flexicast_cc_new_multicast(&default_cc_cfg, 0);
    ok(cc != NULL);
    cfg.cc = cc;
    ok(quicly_flexicast_flow_create(&flow, &cfg) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(&payload, 1), packet, sizeof(packet), &size, &pn0, 10) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_ack_packet(flow, 1, pn0, &complete, 11) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    uint64_t rate_before = output.rate_bytes_per_second;
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(&payload, 1), packet, sizeof(packet), &size, &pn1, 11) ==
       QUICLY_FLEXICAST_OK);
    quicly_flexicast_cc_on_flow_timeout(flow, 311);
    quicly_flexicast_cc_on_flow_timeout(flow, 611);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(&payload, 1), packet, sizeof(packet), &size, &pn2, 1010) ==
       QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_abandon_datagram(flow, 1, pn1, &complete) == QUICLY_FLEXICAST_OK && complete);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.next_timeout == 1310);
    quicly_flexicast_cc_on_flow_timeout(flow, 1010);
    quicly_flexicast_cc_get_flow_output(flow, &output);
    ok(output.rate_bytes_per_second == rate_before && output.next_timeout == 1310);
    quicly_flexicast_flow_free(flow);
    quicly_flexicast_cc_free_multicast(cc);

    /* positional 8-field quicly_flexicast_cc_type_t initializer binds on_feedback and on_timeout properly */
    static quicly_flexicast_cc_type_t positional_type = {
        "positional", NULL, NULL, NULL, NULL, NULL, positional_cc_on_feedback, positional_cc_on_timeout};
    quicly_flexicast_cc_t pos_cc = {0};
    ok(quicly_flexicast_cc_init(&pos_cc, &positional_type, &default_cc_cfg) == 0);
    positional_cc_feedback_calls = positional_cc_timeout_calls = 0;
    quicly_flexicast_feedback_t fb = {.member_id = 1, .acked_packets = 1, .now = 10};
    quicly_flexicast_cc_on_feedback(&pos_cc, &fb);
    quicly_flexicast_cc_on_timeout(&pos_cc, 20);
    ok(positional_cc_feedback_calls == 1 && positional_cc_timeout_calls == 1);

    /* shrinking window (via shorter smoothed RTT) converts carried growth_remainder even when delivered % window == 0 */
    cc = quicly_flexicast_cc_new_multicast(&default_cc_cfg, 0);
    ok(cc != NULL);
    ok(quicly_flexicast_cc_on_member_added(cc, 1, 0) == 0);
    /* step 1: rtt = 100 ms -> window = 10000, gain = 12000; delivered = 4 -> 4 * 12000 = 48000 (+4, rate 100004, rem = 8000) */
    quicly_flexicast_feedback_t step1 = {.member_id = 1,
                                         .epoch = 1,
                                         .acked_packets = 1,
                                         .acked_bytes = 4,
                                         .minimum_rtt_msec = 10,
                                         .smoothed_rtt_msec = 100,
                                         .now = 100};
    quicly_flexicast_cc_on_feedback(cc, &step1);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 100004);
    /* step 2: rtt = 10 ms -> window = min_window = 4800, gain = 120000; delivered = 4800 (rem_delivered == 0) + rem 8000/4800 = +1
     */
    quicly_flexicast_feedback_t step2 = {.member_id = 1,
                                         .epoch = 2,
                                         .acked_packets = 1,
                                         .acked_bytes = 4800,
                                         .minimum_rtt_msec = 10,
                                         .smoothed_rtt_msec = 10,
                                         .now = 110};
    quicly_flexicast_cc_on_feedback(cc, &step2);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 220005);
    quicly_flexicast_cc_free_multicast(cc);
}

void test_flexicast_cc_regressions(void)
{
    subtest("multicast-zero-time-and-idle", test_multicast_zero_time_and_idle);
    subtest("multicast-ack-grouping-invariance", test_multicast_ack_grouping_invariance);
    subtest("multicast-feedback-epochs", test_multicast_feedback_epochs);
    subtest("member-map-collisions", test_member_map_collisions);
    subtest("rekey-inactive-members", test_rekey_inactive_members);
    subtest("rekey-16k-member-replacement", test_rekey_16k_member_replacement);
    subtest("duplicate-ack-delivery-clock", test_duplicate_ack_delivery_clock);
    subtest("suspend-legacy-controller", test_suspend_legacy_controller);
    subtest("abandon-and-exclusive-reuse", test_abandon_and_exclusive_reuse);
    subtest("reordered-pending-and-remainder", test_reordered_pending_and_remainder);
}
