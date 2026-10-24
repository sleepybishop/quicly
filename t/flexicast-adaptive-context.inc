/* adaptive controller send-context and RTT identity tests */
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

/* established native growth probe vs bootstrap and legacy gains */
static void test_adaptive_growth_probe(void)
{
    for (size_t mode = 0; mode != 3; ++mode) { /* native delivery, native startup, legacy delivery */
        for (uint32_t senders = 1; senders <= 4; senders *= 4) {
            quicly_flexicast_cc_t *cc = adaptive_test_new(100000, 2000, 1);
            quicly_flexicast_cc_hints_t hints = {.active_senders = senders};
            quicly_flexicast_cc_set_hints(cc, &hints, 100);
            uint64_t expected = 100000;
            const int64_t times[] = {249, 250, 498, 499};
            for (size_t step = 0; step != 4; ++step) {
                quicly_flexicast_feedback_t feedback = adaptive_context_sample(step + 1, times[step], expected, 1, expected, 20);
                if (mode == 1) {
                    feedback.delivery_rate_bytes_per_second = 0;
                    feedback.delivery_rate_sample_epoch = 0;
                    feedback.delivery_sample_flags = QUICLY_FLEXICAST_SAMPLE_PRESENT;
                } else if (mode == 2) {
                    feedback.delivery_sample_flags = 0;
                    feedback.rtt_sample_flags = 0;
                }
                quicly_flexicast_cc_on_feedback(cc, &feedback);
                if (step == 0 || step == 3) {
                    uint32_t divisor = (mode == 0 ? 16 : 8) * (senders == 1 ? 1 : 2);
                    expected += expected / divisor;
                }
                ok(adaptive_test_output(cc).rate_bytes_per_second == expected);
            }
            ok(adaptive_test_output(cc).rate_increase_events == 2);
            quicly_flexicast_cc_free(cc);
        }
    }

    /* datagram floor, median catch-up limit, and aggregate cap constrain growth probes */
    quicly_flexicast_cc_t *cc = adaptive_test_new(8000, 2000, 1);
    quicly_flexicast_feedback_t feedback = adaptive_context_sample(1, 200, 8000, 1, 8000, 20);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 9200);
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(100000, 2000, 1);
    quicly_flexicast_cc_hints_t hints = {.median_sender_rate_bytes_per_second = 103000};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 100000, 20);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 103000);
    quicly_flexicast_cc_free(cc);

    cc = adaptive_test_new(100000, 2000, 1);
    hints = (quicly_flexicast_cc_hints_t){.aggregate_rate_limit_bytes_per_second = 106000};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 100000, 20);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 106000);
    feedback = adaptive_context_sample(2, 450, 106000, 1, 106000, 20);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 106000);
    quicly_flexicast_cc_free(cc);
}

static void test_adaptive_absolute_ceiling(void);
static void test_adaptive_drain(void);
static void test_adaptive_cadence(void);

static void test_adaptive_context(void)
{
    test_adaptive_absolute_ceiling();
    test_adaptive_drain();
    test_adaptive_cadence();
    test_adaptive_growth_probe();
    /* limited, missing, or mixed context cannot trigger delivery cuts or radio baseline learning */
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

    /* historical fanout overrides current divisor hint */
    quicly_flexicast_cc_t *cc = adaptive_test_new(100000, 2000, 1);
    quicly_flexicast_cc_hints_t hints = {.delivery_rate_divisor = 1};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    quicly_flexicast_feedback_t feedback = adaptive_context_sample(1, 200, 100000, 4, 25000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback = adaptive_context_sample(2, 500, 100000, 1, 100000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 100000);
    quicly_flexicast_cc_free(cc);

    /* clock-bucket boundaries do not allow consecutive updates 1 ms apart */
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

    /* RTT trends use elapsed sample time rather than bucket edges */
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

    /* repeated RTT sample epoch does not extend an expired hold */
    cc = adaptive_test_new(100000, 2000, 1);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 100000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback = adaptive_context_sample(2, 800, 100000, 1, 100000, 80);
    feedback.rtt_sample_epoch = 1;
    feedback.rtt_sample_at = 200;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 106250);
    quicly_flexicast_cc_free(cc);

    /* invalid or stale RTT timestamps cannot trigger cuts or baseline learning */
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

    /* standing queue on one receiver blocks baseline learning for the whole sender */
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

    /* inconsistent ACK delay does not freeze growth indefinitely */
    cc = adaptive_test_new(100000, 2000, 1);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 100000, 26);
    feedback.minimum_rtt_msec = 2;
    feedback.rtt_ack_delay_msec = 25;
    feedback.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 106250);
    feedback.epoch = 2;
    feedback.now = 500;
    feedback.ecn_ce_count = 1;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 90312);
    quicly_flexicast_cc_free(cc);

    /* fresh clean RTT permits bounded startup before the first delivery sample */
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


/* helper for historical send-context ceiling tests */
static quicly_flexicast_feedback_t adaptive_ceiling_old_sample(uint64_t epoch, int64_t now, uint64_t physical_rate,
                                                             uint32_t fanout, uint64_t delivered_rate, uint32_t rtt)
{
    quicly_flexicast_feedback_t feedback = adaptive_context_sample(epoch, now, physical_rate, fanout, delivered_rate, rtt);
    feedback.delivery_sample_sent_at_start = 100;
    feedback.delivery_sample_sent_at_end = 150;
    return feedback;
}

static quicly_flexicast_cc_t *adaptive_ceiling_after_first_cut(void)
{
    quicly_flexicast_cc_t *cc = adaptive_test_new(100000, 2000, 1);
    quicly_flexicast_feedback_t feedback = adaptive_ceiling_old_sample(1, 200, 100000, 1, 20000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    return cc;
}

static void test_adaptive_absolute_ceiling(void)
{
    /* bounded steps toward a fixed drain target without compounding below the ceiling */
    quicly_flexicast_cc_t *cc = adaptive_test_new(100000, 2000, 1);
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    const int64_t times[] = {200, 449, 450, 699, 700, 950, 1200};
    const uint64_t expected[] = {50000, 50000, 25000, 25000, 16000, 16000, 16000};
    for (size_t i = 0; i != sizeof(times) / sizeof(times[0]); ++i) {
        quicly_flexicast_feedback_t feedback = adaptive_ceiling_old_sample(i + 1, times[i], 100000, 1, 20000, 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == expected[i]);
    }
    quicly_flexicast_cc_trace_event_t event;
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    ok(event.state_after.baseline_delivery_ratio_ppm == 1000000);
    ok(event.state_after.delivery_ceiling_bytes_per_second == 20000);
    ok(event.state_after.delivery_ceiling_eligible && !event.state_after.delivery_sample_post_cut);
    ok(adaptive_test_output(cc).rate_reduction_events == 3);
    ok(event.state_after.last_reduction_at == 700); /* no-op ceilings consume no cut clock */
    quicly_flexicast_cc_free(cc);

    /* historical fanout scales per-receiver delivery into the aggregate ceiling */
    const uint32_t fanouts[] = {1, 2, 4};
    for (size_t i = 0; i != sizeof(fanouts) / sizeof(fanouts[0]); ++i) {
        cc = adaptive_test_new(100000, 2000, 1);
        quicly_flexicast_cc_hints_t hints = {.delivery_rate_divisor = 32};
        quicly_flexicast_cc_set_hints(cc, &hints, 100);
        for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
            quicly_flexicast_feedback_t feedback = adaptive_ceiling_old_sample(epoch, 200 + (epoch - 1) * 250,
                                                                              100000, fanouts[i], 40000 / fanouts[i], 80);
            quicly_flexicast_cc_on_feedback(cc, &feedback);
            ok(adaptive_test_output(cc).rate_bytes_per_second == (epoch == 1 ? 50000 : 32000));
        }
        quicly_flexicast_cc_free(cc);
    }

    /* duplicate epochs and unusable RTT provenance do not trigger another cut */
    for (size_t mode = 0; mode != 6; ++mode) {
        cc = adaptive_ceiling_after_first_cut();
        quicly_flexicast_feedback_t feedback = adaptive_ceiling_old_sample(2, 500, 100000, 1, 10000, 80);
        if (mode == 0)
            feedback.epoch = 1;
        else if (mode == 1)
            feedback.delivery_rate_sample_epoch = 1;
        else if (mode == 2) {
            feedback.rtt_sample_epoch = 1;
            feedback.rtt_sample_at = 200;
        } else if (mode == 3) {
            feedback.rtt_sample_at = 0;
        } else if (mode == 4) {
            feedback.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT;
        } else {
            feedback.now = 2000;
            feedback.rtt_sample_at = 999;
            feedback.delivery_sample_acked_at_start = 1900;
            feedback.delivery_sample_acked_at_end = 1950;
        }
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
        quicly_flexicast_cc_free(cc);
    }

    /* unusable delivery context cannot bypass provenance checks */
    const uint32_t invalid_flags[] = {QUICLY_FLEXICAST_SAMPLE_PRESENT,
        QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_APP_LIMITED,
        QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED,
        QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID | QUICLY_FLEXICAST_SAMPLE_MIXED};
    for (size_t i = 0; i != sizeof(invalid_flags) / sizeof(invalid_flags[0]); ++i) {
        cc = adaptive_ceiling_after_first_cut();
        quicly_flexicast_feedback_t feedback = adaptive_ceiling_old_sample(2, 500, 100000, 1, 10000, 80);
        feedback.delivery_sample_flags = invalid_flags[i];
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
        quicly_flexicast_cc_free(cc);
    }
    for (size_t invalid = 0; invalid != 10; ++invalid) {
        cc = adaptive_ceiling_after_first_cut();
        quicly_flexicast_feedback_t feedback = adaptive_ceiling_old_sample(2, 1500, 100000, 1, 10000, 80);
        switch (invalid) {
        case 0: feedback.delivery_sample_pacing_rate_bytes_per_second = 0; break;
        case 1: feedback.delivery_sample_fanout = 0; break;
        case 2: feedback.delivery_sample_bytes = 0; break;
        case 3: feedback.delivery_sample_sent_at_start = -1; break;
        case 4: feedback.delivery_sample_sent_at_end = 99; break;
        case 5: feedback.delivery_sample_acked_at_end = feedback.delivery_sample_acked_at_start; break;
        case 6: feedback.delivery_sample_sent_at_end = feedback.delivery_sample_acked_at_end + 1; break;
        case 7: feedback.delivery_sample_acked_at_end = feedback.now + 1; break;
        case 8:
            feedback.delivery_sample_acked_at_start = 400;
            feedback.delivery_sample_acked_at_end = 499; /* one millisecond beyond timeout */
            break;
        case 9: feedback.delivery_rate_bytes_per_second = 0; break;
        }
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
        quicly_flexicast_cc_free(cc);
    }

    /* freshness boundary is inclusive at one feedback timeout */
    cc = adaptive_ceiling_after_first_cut();
    quicly_flexicast_feedback_t feedback = adaptive_ceiling_old_sample(2, 1500, 100000, 1, 10000, 80);
    feedback.delivery_sample_acked_at_start = 400;
    feedback.delivery_sample_acked_at_end = 500;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 25000);
    quicly_flexicast_cc_free(cc);

    /* pre-cut sending cannot teach a radio baseline or authorize growth */
    for (size_t healthy = 0; healthy != 2; ++healthy) {
        cc = adaptive_ceiling_after_first_cut();
        ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
        for (uint64_t epoch = 2; epoch <= 7; ++epoch) {
            feedback = adaptive_ceiling_old_sample(epoch, 1000 + epoch * 250, 100000, 1, healthy ? 100000 : 10000, 20);
            quicly_flexicast_cc_on_feedback(cc, &feedback);
        }
        ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
        ok(event.state_after.baseline_delivery_ratio_ppm == 1000000);
        ok(event.state_after.degraded_delivery_epochs == 0);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
        quicly_flexicast_cc_free(cc);
    }

    /* learned 50% radio delivery baseline scales the ceiling */
    cc = adaptive_test_new(100000, 2000, 1);
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    for (uint64_t epoch = 1; epoch <= 4; ++epoch) {
        feedback = adaptive_context_sample(epoch, epoch * 250, 100000, 1, 50000, 20);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    }
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    ok(event.state_after.baseline_delivery_ratio_ppm == 500000);
    for (uint64_t epoch = 5; epoch <= 8; ++epoch) {
        feedback = adaptive_ceiling_old_sample(epoch, epoch * 250, 100000, 1, 10000, 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        const uint64_t learned_expected[] = {50000, 25000, 16000, 16000};
        ok(adaptive_test_output(cc).rate_bytes_per_second == learned_expected[epoch - 5]);
    }
    quicly_flexicast_cc_free(cc);

    /* independent ECN and loss responses remain active below the delivery ceiling */
    for (size_t ce = 0; ce != 2; ++ce) {
        cc = adaptive_ceiling_after_first_cut();
        feedback = adaptive_ceiling_old_sample(2, 500, 100000, 1, 80000, 80);
        feedback.ecn_ce_count = ce;
        feedback.lost_packets = ce ? 0 : 8;
        if (ce) {
            feedback.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
            feedback.rtt_sample_epoch = 1; /* ECN does not require a fresh RTT */
        }
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (ce ? 42500 : 45000));
        quicly_flexicast_cc_free(cc);
    }

    /* random loss with flat, clean RTT does not cut rate */
    cc = adaptive_ceiling_after_first_cut();
    for (uint64_t epoch = 2; epoch <= 7; ++epoch) {
        feedback = adaptive_ceiling_old_sample(epoch, epoch * 250, 100000, 1, 10000, 20);
        feedback.lost_packets = epoch % 2 ? 3 : 1;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    }
    quicly_flexicast_cc_free(cc);

    /* large rates avoid intermediate overflow */
    const uint64_t large = UINT64_C(1) << 62;
    quicly_flexicast_cc_config_t config = {.maximum_members = 1,
        .startup_rate_bytes_per_second = large, .minimum_rate_bytes_per_second = 2000,
        .maximum_rate_bytes_per_second = UINT64_MAX, .maximum_datagram_size = 1200,
        .feedback_timeout_msec = 1000};
    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    quicly_flexicast_cc_on_member_added(cc, 1, 100);
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        feedback = adaptive_ceiling_old_sample(epoch, 200 + (epoch - 1) * 250, large, 4, large / 16, 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        uint64_t expected =
            epoch == 1 ? large / 2 : epoch == 2 ? large / 4 : (large / 4) / 5 * 4 + (large / 4) % 5 * 4 / 5;
        ok(adaptive_test_output(cc).rate_bytes_per_second == expected);
    }
    quicly_flexicast_cc_free(cc);

    /* products exceeding UINT64_MAX saturate at the historical offered rate */
    cc = adaptive_ceiling_after_first_cut();
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    feedback = adaptive_ceiling_old_sample(2, 500, UINT64_MAX, UINT32_MAX, UINT64_MAX, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    ok(event.state_after.delivery_ceiling_bytes_per_second == UINT64_MAX);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    quicly_flexicast_cc_free(cc);

    /* legacy callers without native provenance retain the ratio policy */
    cc = adaptive_test_new(100000, 2000, 1);
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 20000, 80);
    feedback.delivery_sample_flags = feedback.rtt_sample_flags = 0;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    ok(!event.state_after.delivery_ceiling_eligible && event.state_after.delivery_ceiling_bytes_per_second == 0);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    quicly_flexicast_cc_free(cc);

    /* configured minimum remains a floor and epoch reset allows fresh publication epochs */
    cc = adaptive_test_new(4000, 2000, 1);
    feedback = adaptive_ceiling_old_sample(1, 200, 4000, 1, 1, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 2000);
    quicly_flexicast_cc_on_epoch_reset(cc, 500);
    feedback = adaptive_context_sample(1, 800, 2000, 1, 2000, 20);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second > 2000);
    quicly_flexicast_cc_free(cc);
}

#include "flexicast-adaptive-drain.inc"
#include "flexicast-adaptive-cadence.inc"
