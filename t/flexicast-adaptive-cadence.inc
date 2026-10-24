/* conditional faster cut policy tests */
static void test_adaptive_cadence(void)
{
    quicly_flexicast_cc_t *cc = adaptive_ceiling_after_first_cut();
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    const int64_t times[] = {324, 325, 449, 450, 575, 700};
    const uint64_t rates[] = {50000, 25000, 25000, 12500, 10000, 10000};
    for (size_t i = 0; i != sizeof(times) / sizeof(times[0]); ++i) {
        quicly_flexicast_feedback_t feedback = adaptive_context_sample(i + 2, times[i], 50000, 1, 10000, 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == rates[i]);
    }
    quicly_flexicast_cc_trace_event_t event;
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    ok(event.state_after.control_interval_msec == 250); /* normal clock is unchanged */
    ok(event.state_after.last_reduction_at == 575); /* no compounding below the fixed absolute ceiling */
    ok(adaptive_test_output(cc).rate_reduction_events == 4);
    quicly_flexicast_cc_free(cc);

    /* ceiling just below current rate still applies the minimum 10% decrease */
    cc = adaptive_ceiling_after_first_cut();
    quicly_flexicast_feedback_t near_ceiling = adaptive_context_sample(2, 325, 100000, 1, 48000, 80);
    quicly_flexicast_cc_on_feedback(cc, &near_ceiling);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 45000);
    quicly_flexicast_cc_free(cc);

    /* samples spanning pre-cut sending retain the normal 250 ms path */
    for (size_t post_cut = 0; post_cut != 2; ++post_cut) {
        cc = adaptive_ceiling_after_first_cut();
        quicly_flexicast_feedback_t feedback = adaptive_context_sample(2, 325, 50000, 1, 10000, 80);
        feedback.delivery_sample_sent_at_start = post_cut ? 200 : 199;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (post_cut ? 25000 : 50000));
        if (!post_cut) {
            feedback = adaptive_ceiling_old_sample(3, 449, 100000, 1, 10000, 80);
            quicly_flexicast_cc_on_feedback(cc, &feedback);
            ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
            feedback = adaptive_ceiling_old_sample(4, 450, 100000, 1, 10000, 80);
            quicly_flexicast_cc_on_feedback(cc, &feedback);
            ok(adaptive_test_output(cc).rate_bytes_per_second == 25000);
        }
        quicly_flexicast_cc_free(cc);
    }

    /* RTT receipt is an independent watermark */
    for (size_t at_cut = 0; at_cut != 2; ++at_cut) {
        cc = adaptive_ceiling_after_first_cut();
        quicly_flexicast_feedback_t feedback = adaptive_context_sample(2, 325, 50000, 1, 10000, 80);
        feedback.rtt_sample_at = at_cut ? 200 : 199;
        feedback.raw_rtt_msec = 80; /* inferred send is 120 or 119, before cut200 */
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (at_cut ? 25000 : 50000));
        quicly_flexicast_cc_free(cc);
    }

    /* duplicates or invalid provenance cannot enter the faster path */
    for (size_t invalid = 0; invalid != 20; ++invalid) {
        cc = adaptive_ceiling_after_first_cut();
        quicly_flexicast_feedback_t feedback = adaptive_context_sample(2, 325, 50000, 1, 10000, 80);
        switch (invalid) {
        case 0: feedback.epoch = 1; break;
        case 1: feedback.delivery_rate_sample_epoch = 1; break;
        case 2: feedback.delivery_rate_sample_epoch = 0; break;
        case 3: feedback.rtt_sample_epoch = 1; break;
        case 4: feedback.rtt_sample_flags = 0; break; /* legacy RTT fallback is not explicit evidence */
        case 5: feedback.rtt_sample_flags = QUICLY_FLEXICAST_RTT_PRESENT; break;
        case 6: feedback.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT; break;
        case 7: feedback.rtt_sample_at = feedback.now + 1; break;
        case 8: feedback.delivery_sample_flags = QUICLY_FLEXICAST_SAMPLE_PRESENT; break;
        case 9: feedback.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_APP_LIMITED; break;
        case 10: feedback.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED; break;
        case 11: feedback.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED; break;
        case 12: feedback.delivery_sample_fanout = 0; break;
        case 13: feedback.delivery_sample_pacing_rate_bytes_per_second = 0; break;
        case 14: feedback.delivery_sample_bytes = 0; break;
        case 15: feedback.delivery_sample_sent_at_end = feedback.delivery_sample_sent_at_start - 1; break;
        case 16: feedback.delivery_sample_acked_at_end = feedback.now + 1; break;
        case 17: feedback.delivery_sample_acked_at_end = feedback.delivery_sample_acked_at_start; break;
        case 18: feedback.delivery_rate_bytes_per_second = 0; break;
        case 19: feedback.latest_rtt_msec = 25; break; /* minimum20 + margin5 is not queue growth */
        }
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
        quicly_flexicast_cc_free(cc);
    }

    /* rejected publication epoch is consumed and cannot be reused */
    cc = adaptive_ceiling_after_first_cut();
    quicly_flexicast_feedback_t feedback = adaptive_context_sample(2, 325, 50000, 1, 10000, 80);
    feedback.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    feedback = adaptive_context_sample(3, 326, 50000, 1, 10000, 80);
    feedback.delivery_rate_sample_epoch = 2;
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    feedback = adaptive_context_sample(4, 327, 50000, 1, 10000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 25000);
    quicly_flexicast_cc_free(cc);

    /* historical fanout controls the physical ceiling */
    const uint32_t fanouts[] = {1, 2, 4};
    for (size_t i = 0; i != sizeof(fanouts) / sizeof(fanouts[0]); ++i) {
        cc = adaptive_ceiling_after_first_cut();
        quicly_flexicast_cc_hints_t hints = {.delivery_rate_divisor = 32};
        quicly_flexicast_cc_set_hints(cc, &hints, 250);
        feedback = adaptive_context_sample(2, 325, 50000, fanouts[i], 30000 / fanouts[i], 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 30000);
        quicly_flexicast_cc_free(cc);
    }
    cc = adaptive_ceiling_after_first_cut();
    for (uint64_t epoch = 2; epoch <= 5; ++epoch) {
        feedback = adaptive_context_sample(epoch, 200 + (epoch - 1) * 125, 50000, 1, 10000, 20);
        feedback.lost_packets = epoch % 2 ? 3 : 1;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    }
    quicly_flexicast_cc_free(cc);

    /* all members share the reduction clock */
    cc = adaptive_test_new(100000, 2000, 32);
    feedback = adaptive_context_sample(1, 200, 100000, 1, 10000, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    const int64_t group_times[] = {325, 449, 450};
    const uint64_t group_rates[] = {25000, 25000, 12500};
    for (size_t step = 0; step != 3; ++step) {
        for (uint64_t member = 1; member <= 32; ++member) {
            feedback = adaptive_context_sample(step + 2, group_times[step], 50000, 1, 1000, 80);
            feedback.member_id = member;
            /* allow same-millisecond send boundary for later members */
            feedback.delivery_sample_sent_at_start = group_times[step];
            feedback.delivery_sample_sent_at_end = group_times[step];
            feedback.delivery_sample_acked_at_start = group_times[step] - 1;
            feedback.delivery_sample_acked_at_end = group_times[step];
            quicly_flexicast_cc_on_feedback(cc, &feedback);
        }
        ok(adaptive_test_output(cc).rate_bytes_per_second == group_rates[step]);
    }
    ok(adaptive_test_output(cc).rate_reduction_events == 3);
    quicly_flexicast_cc_free(cc);

    /* CE never takes the faster path */
    for (size_t first_early = 0; first_early != 2; ++first_early) {
        cc = adaptive_ceiling_after_first_cut();
        feedback = adaptive_context_sample(2, 325, 50000, 1, 10000, 80);
        feedback.ecn_ce_count = first_early ? 0 : 1;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (first_early ? 25000 : 50000));
        feedback = adaptive_context_sample(3, 449, 50000, 1, 10000, 80);
        feedback.ecn_ce_count = 1;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (first_early ? 25000 : 50000));
        feedback = adaptive_context_sample(4, first_early ? 575 : 450, 50000, 1, 10000, 80);
        feedback.ecn_ce_count = 1;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (first_early ? 21250 : 42500));
        quicly_flexicast_cc_free(cc);
    }

    /* fresh queued RTT plus loss stays on the 250 ms path */
    cc = adaptive_ceiling_after_first_cut();
    for (size_t step = 0; step != 2; ++step) {
        feedback = adaptive_context_sample(step + 2, step ? 450 : 325, 50000, 1, 50000, 80);
        feedback.lost_packets = 2;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (step ? 40000 : 50000));
    }
    quicly_flexicast_cc_free(cc);
    cc = adaptive_test_new(100000, 2000, 1);
    const int64_t trend_times[] = {200, 450, 700, 825, 950};
    const uint32_t trend_rtt[] = {40, 50, 60, 60, 70};
    const uint64_t trend_rates[] = {100000, 100000, 90000, 90000, 81000};
    for (size_t step = 0; step != 5; ++step) {
        feedback = adaptive_context_sample(step + 1, trend_times[step], 100000, 1, 100000, trend_rtt[step]);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == trend_rates[step]);
    }
    quicly_flexicast_cc_free(cc);

    /* legacy callers without sample flags retain the 250 ms interval */
    cc = adaptive_test_new(100000, 2000, 1);
    for (size_t step = 0; step != 3; ++step) {
        feedback = adaptive_context_sample(step + 1, step == 0 ? 200 : step == 1 ? 325 : 450,
                                           100000, 1, 10000, 80);
        feedback.delivery_sample_flags = 0;
        feedback.rtt_sample_flags = 0;
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (step == 2 ? 25000 : 50000));
    }
    quicly_flexicast_cc_free(cc);

    /* growth stays on its 250 ms clock */
    cc = adaptive_test_new(100000, 2000, 1);
    const int64_t growth_times[] = {200, 325, 450};
    const uint64_t growth_rates[] = {106250, 106250, 112890};
    for (size_t step = 0; step != 3; ++step) {
        uint64_t current = adaptive_test_output(cc).rate_bytes_per_second;
        feedback = adaptive_context_sample(step + 1, growth_times[step], current, 1, current, 20);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == growth_rates[step]);
    }
    quicly_flexicast_cc_free(cc);

    /* floor and aggregate-cap no-ops retain established semantics */
    cc = adaptive_test_new(100000, 30000, 1);
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        feedback = adaptive_context_sample(epoch, 200 + (epoch - 1) * 125, 100000, 1, 10000, 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (epoch == 1 ? 50000 : 30000));
    }
    ok(adaptive_test_output(cc).rate_reduction_events == 2);
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    ok(event.state_after.last_reduction_at == 450); /* existing floor no-op advances clock */
    quicly_flexicast_cc_free(cc);
    cc = adaptive_ceiling_after_first_cut();
    quicly_flexicast_cc_hints_t cap = {.aggregate_rate_limit_bytes_per_second = 1000};
    quicly_flexicast_cc_set_hints(cc, &cap, 250);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 1000);
    feedback = adaptive_context_sample(2, 325, 50000, 1, 100, 80);
    quicly_flexicast_cc_on_feedback(cc, &feedback);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 1000);
    quicly_flexicast_cc_free(cc);

    /* configured ordinary interval shorter than 125 ms remains available */
    quicly_flexicast_cc_config_t config = {.maximum_members = 1,
        .startup_rate_bytes_per_second = 100000, .minimum_rate_bytes_per_second = 2000,
        .maximum_rate_bytes_per_second = 1000000, .maximum_datagram_size = 1200,
        .feedback_timeout_msec = 100};
    cc = NULL;
    ok(quicly_flexicast_cc_create(&cc, &quicly_flexicast_cc_type_adaptive, &config, 100) == 0);
    const int64_t short_times[] = {200, 224, 225};
    for (size_t step = 0; step != 3; ++step) {
        feedback = adaptive_ceiling_old_sample(step + 1, short_times[step], 100000, 1, 10000, 80);
        quicly_flexicast_cc_on_feedback(cc, &feedback);
        ok(adaptive_test_output(cc).rate_bytes_per_second == (step == 2 ? 25000 : 50000));
    }
    quicly_flexicast_cc_free(cc);
}
