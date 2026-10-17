/*
 * Copyright (c) 2026 Joseph Calderon
 * SPDX-License-Identifier: MIT
 */
#include "picotest.h"
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
    /* Replayed reports must not defer the missing-feedback deadline. */
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
    ok(output.rate_bytes_per_second == 16000);
    /* Older clean measurements cannot clear the current load episode. */
    for (uint64_t epoch = 1; epoch != 4; ++epoch) {
        hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = epoch};
        quicly_flexicast_cc_set_hints(cc, &hints, 130 + (int64_t)epoch);
    }
    feedback.epoch = 2;
    feedback.delivery_rate_bytes_per_second = 16000;
    feedback.now = 200;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second == 16000);
    ok((output.reason & QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN) != 0);
    for (uint64_t epoch = 12; epoch != 15; ++epoch) {
        hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = epoch};
        quicly_flexicast_cc_set_hints(cc, &hints, 210 + (int64_t)epoch);
    }
    feedback.epoch = 3;
    feedback.now = 250;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    quicly_flexicast_cc_get_output(cc, &output);
    ok(output.rate_bytes_per_second > 16000);
    quicly_flexicast_cc_free(cc);
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
    ok(output.rate_bytes_per_second == UINT64_MAX);
    quicly_flexicast_cc_free(cc);
}

static void test_member_map_collisions(void)
{
    flexicast_member_map_t map = {0};
    uint64_t ids[32];
    ok(flexicast_member_map_init(&map, 32) == 0);
    /* All probe chains wrap around the end of the table. */
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

void test_flexicast_cc_regressions(void)
{
    subtest("multicast-zero-time", test_multicast_zero_time);
    subtest("multicast-feedback-epochs", test_multicast_feedback_epochs);
    subtest("adaptive-rate-limit", test_adaptive_rate_limit);
    subtest("adaptive-hint-epochs", test_adaptive_hint_epochs);
    subtest("adaptive-maximum-rate-recovery", test_adaptive_maximum_rate_recovery);
    subtest("member-map-collisions", test_member_map_collisions);
}
