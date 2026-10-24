/* deterministic adaptive controller regressions */
#include <stdbool.h>

static quicly_flexicast_cc_t *adaptive_test_new(uint64_t startup, uint64_t minimum, size_t members)
{
    quicly_flexicast_cc_config_t config = {.maximum_members = members,
        .startup_rate_bytes_per_second = startup, .minimum_rate_bytes_per_second = minimum,
        .maximum_rate_bytes_per_second = 1000000, .maximum_datagram_size = 1200,
        .feedback_timeout_msec = 1000};
    quicly_flexicast_cc_t *cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    for (size_t id = 1; id <= members; ++id)
        quicly_flexicast_cc_on_member_added(cc, id, 100);
    return cc;
}

static quicly_flexicast_cc_output_t adaptive_test_output(quicly_flexicast_cc_t *cc)
{
    quicly_flexicast_cc_output_t output;
    quicly_flexicast_cc_get_output(cc, &output);
    return output;
}

static void adaptive_test_delivery_buckets(bool split, bool explicit_sample_epoch, uint64_t rates[2])
{
    quicly_flexicast_cc_config_t config = {.maximum_members = 1,
        .startup_rate_bytes_per_second = 1000000, .minimum_rate_bytes_per_second = 1000,
        .maximum_rate_bytes_per_second = 1000000, .maximum_datagram_size = 1200,
        .feedback_timeout_msec = 100};
    quicly_flexicast_cc_t *cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 1) == 0);
    quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = 1, .acked_packets = 8,
        .acked_bytes = 8000, .delivery_rate_bytes_per_second = 1000000,
        .delivery_rate_sample_epoch = explicit_sample_epoch ? 1 : 0,
        .minimum_rtt_msec = 20, .latest_rtt_msec = 20, .now = 100};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    for (size_t bucket = 0; bucket != 2; ++bucket) {
        for (size_t frame = 0; frame != (split ? 8 : 1); ++frame) {
            ++feedback.epoch;
            feedback.acked_packets = split ? 1 : 8;
            feedback.acked_bytes = split ? 1000 : 8000;
            feedback.delivery_rate_bytes_per_second = 100000;
            feedback.delivery_rate_sample_epoch = explicit_sample_epoch ? bucket + 2 : 0;
            feedback.latest_rtt_msec = 80;
            feedback.now = 200 + bucket * 100 + (explicit_sample_epoch ? frame : 0);
            quicly_flexicast_cc_on_feedback(cc, &feedback);
        }
        rates[bucket] = adaptive_test_output(cc).rate_bytes_per_second;
    }
    quicly_flexicast_cc_free(cc);
}

static void test_adaptive_regressions(void)
{
    uint64_t grouped[2], split[2];
    for (size_t explicit_epoch = 0; explicit_epoch != 2; ++explicit_epoch) {
        adaptive_test_delivery_buckets(false, explicit_epoch != 0, grouped);
        adaptive_test_delivery_buckets(true, explicit_epoch != 0, split);
        ok(grouped[0] == split[0] && grouped[1] == split[1]);
        ok(grouped[1] < grouped[0]); /* a genuinely new sample still updates immediately */
    }
    quicly_flexicast_cc_t *cc = adaptive_test_new(100000, 2000, 2);
    quicly_flexicast_cc_hints_t hints = {.active_senders = 2, .median_sender_rate_bytes_per_second = 200000};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    quicly_flexicast_feedback_t feedback = {.member_id = 1, .acked_packets = 8,
        .delivery_rate_bytes_per_second = 20000, .minimum_rtt_msec = 20, .latest_rtt_msec = 80};
    for (uint64_t epoch = 1; epoch <= 40; ++epoch) {
        feedback.member_id = 1;
        feedback.epoch = epoch;
        feedback.now = 100 + epoch * 100;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        /* a healthy receiver does not offset the limiting receiver's cut */
        quicly_flexicast_feedback_t healthy = feedback;
        healthy.member_id = 2;
        healthy.delivery_rate_bytes_per_second = 100000;
        healthy.latest_rtt_msec = 20;
        healthy.lost_packets = 0;
        quicly_flexicast_cc_on_feedback(cc, &healthy);
    }
    quicly_flexicast_cc_output_t output = adaptive_test_output(cc);
    ok(output.rate_bytes_per_second <= 22000 && output.rate_bytes_per_second >= 15000);
    ok(output.rtt_reduction_events >= 2); /* sustained congestion converges despite a faster median */
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(100000, 2000, 32);
    for (uint64_t epoch = 1; epoch <= 2; ++epoch) {
        for (uint64_t member = 1; member <= 32; ++member) {
            feedback = (quicly_flexicast_feedback_t){.member_id = member, .epoch = epoch, .acked_packets = 8,
                .ecn_ce_count = 1, .minimum_rtt_msec = 20, .latest_rtt_msec = 20, .now = 250 * epoch};
            quicly_flexicast_cc_on_feedback(cc, &feedback);
        }
        output = adaptive_test_output(cc);
        ok(output.ecn_reduction_events == epoch);
        ok(output.rate_bytes_per_second == (epoch == 1 ? 85000 : 72250));
    }
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(100000, 2000, 1);
    hints = (quicly_flexicast_cc_hints_t){.aggregate_rate_limit_bytes_per_second = 10000,
        .external_load_epoch = 1, .external_load_queued_bytes = 4800};
    for (size_t i = 0; i != 100; ++i)
        quicly_flexicast_cc_set_hints(cc, &hints, 200);
    output = adaptive_test_output(cc);
    ok(output.rate_bytes_per_second == 10000 && output.rate_increase_events == 0);
    hints = (quicly_flexicast_cc_hints_t){.aggregate_rate_limit_bytes_per_second = 10000,
        .external_load_epoch = 2};
    for (uint64_t epoch = 2; epoch <= 4; ++epoch) {
        hints.external_load_epoch = epoch;
        quicly_flexicast_cc_set_hints(cc, &hints, epoch * 1000);
    }
    feedback = (quicly_flexicast_feedback_t){.member_id = 1, .epoch = 1, .acked_packets = 8,
        .delivery_rate_bytes_per_second = 10000, .minimum_rtt_msec = 20, .latest_rtt_msec = 20, .now = 4100};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 10000); /* clean growth also respects the cap */
    hints.aggregate_rate_limit_bytes_per_second = 1000; /* budget overrides the preferred minimum */
    quicly_flexicast_cc_set_hints(cc, &hints, 4200);
    feedback = (quicly_flexicast_feedback_t){.member_id = 1, .epoch = 2, .acked_packets = 8,
        .delivery_rate_bytes_per_second = 1000, .minimum_rtt_msec = 20, .latest_rtt_msec = 20, .now = 4300};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 1000);
    quicly_flexicast_cc_on_epoch_reset(cc, 4400);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 1000);
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(1250, 250, 1);
    feedback = (quicly_flexicast_feedback_t){.member_id = 1, .epoch = 1, .acked_packets = 1,
        .delivery_rate_bytes_per_second = 250, .minimum_rtt_msec = 20, .latest_rtt_msec = 80, .now = 200};
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    uint64_t congested_rate = adaptive_test_output(cc).rate_bytes_per_second;
    hints = (quicly_flexicast_cc_hints_t){.external_load_epoch = 1, .external_load_queued_bytes = 4800};
    for (size_t i = 0; i != 100; ++i)
        quicly_flexicast_cc_set_hints(cc, &hints, 200);
    ok(congested_rate == 625 && adaptive_test_output(cc).rate_bytes_per_second == congested_rate);
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(100000, 2000, 1);
    uint64_t previous_rate = 100000;
    for (size_t i = 0; i != 40; ++i) {
        output = adaptive_test_output(cc);
        quicly_flexicast_cc_on_timeout(cc, output.next_timeout);
        output = adaptive_test_output(cc);
        ok(output.rate_bytes_per_second <= previous_rate);
        previous_rate = output.rate_bytes_per_second;
    }
    ok(previous_rate == 2000); /* silence never ramps the rate or disables congestion */
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(100000, 2000, 1);
    for (uint64_t epoch = 1; epoch <= 40; ++epoch) {
        feedback = (quicly_flexicast_feedback_t){.member_id = 1, .epoch = epoch, .acked_packets = 8, .lost_packets = 2,
            .delivery_rate_bytes_per_second = adaptive_test_output(cc).rate_bytes_per_second * 4 / 5,
            .minimum_rtt_msec = 20, .latest_rtt_msec = 20, .now = 250 * epoch};
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    output = adaptive_test_output(cc);
    ok(output.rate_reduction_events == 0 && output.rate_bytes_per_second > 100000);
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(100000, 2000, 1);
    hints = (quicly_flexicast_cc_hints_t){.delivery_rate_divisor = 32};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    for (uint64_t epoch = 1; epoch <= 20; ++epoch) {
        feedback = (quicly_flexicast_feedback_t){.member_id = 1, .epoch = epoch, .acked_packets = 8,
            .delivery_rate_bytes_per_second = 3125, .minimum_rtt_msec = 20, .latest_rtt_msec = 80, .now = 250 * epoch};
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    output = adaptive_test_output(cc);
    ok(output.rate_bytes_per_second == 100000 && output.rate_reduction_events == 0);
    /* stable standing delay holds while a rising queue cuts rate */
    for (uint64_t epoch = 21; epoch <= 24; ++epoch) {
        feedback.epoch = epoch;
        feedback.now = 250 * epoch;
        feedback.latest_rtt_msec = 80 + 5 * (epoch - 20);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    ok(adaptive_test_output(cc).rtt_reduction_events != 0);
    quicly_flexicast_cc_free(cc);
}
