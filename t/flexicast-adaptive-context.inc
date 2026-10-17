/* Real transport samples carry immutable send context and independent RTT
 * identity. Exercise ineligible samples and timing boundaries, not throughput
 * expectations: those belong to the shaped-network and model harnesses. */
static quicly_flexicast_feedback_t adaptive_context_sample(uint64_t epoch, int64_t now, uint64_t physical_rate,
                                                          uint32_t fanout, uint64_t delivered_rate, uint32_t rtt)
{
    return (quicly_flexicast_feedback_t){
        .member_id = 1, .epoch = epoch, .acked_packets = 8, .acked_bytes = 9600,
        .delivery_rate_bytes_per_second = delivered_rate, .delivery_rate_sample_epoch = epoch,
        .delivery_sample_flags = QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID,
        .delivery_sample_fanout = fanout, .delivery_sample_bytes = 9600,
        .delivery_sample_pacing_rate_bytes_per_second = physical_rate,
        .delivery_sample_sent_at_start = now - 100, .delivery_sample_sent_at_end = now - 50,
        .delivery_sample_acked_at_start = now - 100, .delivery_sample_acked_at_end = now - 50,
        .minimum_rtt_msec = 20, .latest_rtt_msec = rtt,
        .rtt_sample_epoch = epoch, .rtt_sample_at = now, .raw_rtt_msec = rtt,
        .rtt_sample_flags = QUICLY_FLEXICAST_RTT_PRESENT | QUICLY_FLEXICAST_RTT_VALID, .now = now};
}

static void test_adaptive_context(void)
{
    /* Low application/host sending, missing context and mixed fanout cannot
     * become congestion or teach a radio loss baseline. CE is independent. */
    const uint32_t unusable[] = {QUICLY_FLEXICAST_SAMPLE_PRESENT,
        QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_APP_LIMITED,
        QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED,
        QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_MIXED};
    for (size_t i = 0; i != sizeof(unusable) / sizeof(unusable[0]); ++i) {
        quicly_flexicast_cc_t *cc = adaptive_test_new(100000, 2000, 1);
        ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
        quicly_flexicast_feedback_t feedback;
        for (uint64_t epoch = 1; epoch <= 6; ++epoch) {
            feedback = adaptive_context_sample(epoch, 250 * epoch, 100000, 1, 10000, 80);
            feedback.delivery_sample_flags = unusable[i];
            quicly_flexicast_cc_on_feedback(cc, &feedback);
        }
        quicly_flexicast_cc_trace_event_t event;
        ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
        ok(event.state_after.baseline_delivery_ratio_ppm == 0 && event.state_after.degraded_delivery_epochs == 0);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 100000);
        feedback.epoch = 7;
        feedback.now += 250;
        feedback.ecn_ce_count = 1;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 85000);
        quicly_flexicast_cc_free(cc);
    }

    /* Historical fanout overrides today's hint; changing context must not
     * blend a low per-receiver rate into a new one-copy delivery sample. */
    quicly_flexicast_cc_t *cc = adaptive_test_new(100000, 2000, 1);
    quicly_flexicast_cc_hints_t hints = {.delivery_rate_divisor = 1};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    quicly_flexicast_feedback_t feedback = adaptive_context_sample(1, 200, 100000, 4, 25000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback = adaptive_context_sample(2, 500, 100000, 1, 100000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 100000);
    quicly_flexicast_cc_free(cc);

    /* A new publication can still describe packets sent before a reduction.
     * It cannot cut again; an interval entirely at the new rate can. */
    cc = adaptive_test_new(100000, 2000, 1);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 20000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    feedback = adaptive_context_sample(2, 500, 100000, 1, 20000, 80);
    feedback.delivery_sample_sent_at_start = 100;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    feedback = adaptive_context_sample(3, 800, 50000, 1, 20000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 25000);
    quicly_flexicast_cc_free(cc);

    /* Clock-bucket boundaries do not admit two growths or correlated cuts
     * one millisecond apart. The default interval stays 250 ms. */
    for (size_t cut = 0; cut != 2; ++cut) {
        cc = adaptive_test_new(100000, 2000, 32);
        const int64_t times[] = {249, 250, 498, 499};
        uint64_t first = 0;
        for (size_t step = 0; step != 4; ++step) {
            for (uint64_t member = 1; member <= 32; ++member) {
                feedback = adaptive_context_sample(step + 1, times[step], 1000000, 1, 1000000, 20);
                feedback.member_id = member;
                feedback.ecn_ce_count = cut;
                quicly_flexicast_cc_on_feedback(cc, &feedback);
            }
            if (step == 0)
                first = adaptive_test_output(cc).rate_bytes_per_second;
            else if (step < 3)
                ok(adaptive_test_output(cc).rate_bytes_per_second == first);
        }
        quicly_flexicast_cc_output_t output = adaptive_test_output(cc);
        ok(cut ? output.ecn_reduction_events == 2 : output.rate_increase_events == 2);
        quicly_flexicast_cc_free(cc);
    }

    /* RTT trends use elapsed sample time as well, not wall bucket edges. */
    cc = adaptive_test_new(100000, 2000, 1);
    const int64_t trend_times[] = {249, 250, 499, 500, 749};
    for (size_t step = 0; step != 5; ++step) {
        feedback = adaptive_context_sample(step + 1, trend_times[step], 100000, 1, 100000, 40 + step * 10);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        if (step < 4)
            ok(adaptive_test_output(cc).rate_bytes_per_second == 100000);
    }
    ok(adaptive_test_output(cc).rate_bytes_per_second == 90000);
    quicly_flexicast_cc_free(cc);

    /* Repeated RTT provenance cannot extend an expired hold or create trends.
     * A fresh delivery sample can grow once that hold has elapsed. */
    cc = adaptive_test_new(100000, 2000, 1);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 100000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback = adaptive_context_sample(2, 800, 100000, 1, 100000, 80);
    feedback.rtt_sample_epoch = 1;
    feedback.rtt_sample_at = 200;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 112500);
    quicly_flexicast_cc_free(cc);

    /* New identities do not make impossible or stale RTT timestamps fresh.
     * Without fresh clean RTT, a low rate cannot be learned as radio loss. */
    for (size_t invalid_rtt = 0; invalid_rtt != 4; ++invalid_rtt) {
        cc = adaptive_test_new(100000, 2000, 1);
        ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
        for (uint64_t epoch = 1; epoch <= 6; ++epoch) {
            feedback = adaptive_context_sample(epoch, 2000 + epoch * 250, 100000, 1, 20000, 80);
            if (invalid_rtt == 0)
                feedback.rtt_sample_at = 0;
            else if (invalid_rtt == 1)
                feedback.rtt_sample_at = feedback.now + 1;
            else if (invalid_rtt == 2)
                feedback.rtt_sample_at = feedback.now - 1001;
            else
                feedback.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
            quicly_flexicast_cc_on_feedback(cc, &feedback);
        }
        quicly_flexicast_cc_trace_event_t event;
        ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
        ok(event.state_after.baseline_delivery_ratio_ppm == 1000000);
        ok(event.state_after.growth_blocked_until == 0 && event.state_after.previous_rtt == 0);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 100000);
        quicly_flexicast_cc_free(cc);
    }

    cc = adaptive_test_new(100000, 2000, 1);
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    for (uint64_t epoch = 1; epoch <= 4; ++epoch) {
        feedback = adaptive_context_sample(epoch, epoch * 250, 100000, 1, 20000, 20);
        if (epoch < 4)
            feedback.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_trace_event_t clean_event;
    ok(quicly_flexicast_cc_read_trace(cc, &clean_event, 1, NULL) == 1);
    ok(clean_event.state_after.baseline_delivery_ratio_ppm == 1000000);
    ok(clean_event.state_after.degraded_delivery_epochs == 1); /* three unusable RTTs did not teach */
    quicly_flexicast_cc_free(cc);

    /* One receiver's standing queue vetoes clean-baseline learning for the
     * whole sender until the hold expires, even on another receiver's ACKs. */
    cc = adaptive_test_new(100000, 2000, 2);
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    for (uint64_t epoch = 1; epoch <= 6; ++epoch) {
        feedback = adaptive_context_sample(epoch, epoch * 250, 100000, 1, 100000, 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        feedback.member_id = 2;
        feedback.latest_rtt_msec = feedback.raw_rtt_msec = 20;
        feedback.delivery_rate_bytes_per_second = 20000;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    quicly_flexicast_cc_trace_event_t event;
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    ok(event.state_after.baseline_delivery_ratio_ppm == 1000000);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 100000);
    quicly_flexicast_cc_free(cc);

    /* An RFC-valid unadjusted RTT can contain an inconsistent ACK delay.
     * Preserve telemetry, but it cannot freeze growth indefinitely. */
    cc = adaptive_test_new(100000, 2000, 1);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 100000, 26);
    feedback.minimum_rtt_msec = 2;
    feedback.rtt_ack_delay_msec = 25;
    feedback.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 112500);
    feedback.epoch = 2;
    feedback.now = 500;
    feedback.ecn_ce_count = 1;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 95625);
    quicly_flexicast_cc_free(cc);

    /* Before the first published delivery sample, fresh clean RTT permits
     * bounded startup. Duplicate frames cannot spend another probe. */
    cc = adaptive_test_new(100000, 2000, 1);
    feedback = adaptive_context_sample(1, 200, 0, 0, 0, 20);
    feedback.delivery_rate_sample_epoch = 0;
    feedback.delivery_sample_flags = QUICLY_FLEXICAST_SAMPLE_PRESENT;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback.epoch = 2;
    feedback.now = 500;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 112500);
    feedback.epoch = feedback.rtt_sample_epoch = 3;
    feedback.rtt_sample_at = 500;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 126562);
    quicly_flexicast_cc_on_epoch_reset(cc, 600);
    feedback = adaptive_context_sample(1, 900, 126562, 1, 126562, 20);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second > 126562);
    quicly_flexicast_cc_free(cc);
}
