/* Delayed bounded drain is an episode, not another per-ACK multiplicative
 * decrease. These tests assert clocks, provenance and fixed-target behavior;
 * network throughput and latency remain measurement-harness concerns. */
static quicly_flexicast_cc_trace_event_t adaptive_drain_trace(quicly_flexicast_cc_t *cc)
{
    quicly_flexicast_cc_trace_event_t event;
    memset(&event, 0, sizeof(event));
    ok(quicly_flexicast_cc_read_trace(cc, &event, 1, NULL) == 1);
    return event;
}

static quicly_flexicast_cc_t *adaptive_drain_new(uint64_t startup, uint64_t minimum, size_t members)
{
    quicly_flexicast_cc_t *cc = adaptive_test_new(startup, minimum, members);
    ok(quicly_flexicast_cc_enable_trace(cc, 1) == 0);
    return cc;
}

static quicly_flexicast_feedback_t adaptive_drain_sample(uint64_t epoch, int64_t now, uint64_t member,
                                                       uint64_t historical_rate, uint64_t delivered_rate, uint32_t rtt)
{
    quicly_flexicast_feedback_t f = adaptive_context_sample(epoch, now, historical_rate, 1, delivered_rate, rtt);
    f.member_id = member;
    /* Ordinary pre-cut sending remains usable for a ceiling. Keep it separate
     * from fresh post-cut sending that could support growth or baseline learning. */
    f.delivery_sample_sent_at_start = 100;
    f.delivery_sample_sent_at_end = 150;
    return f;
}

static quicly_flexicast_cc_trace_event_t adaptive_drain_deliver(quicly_flexicast_cc_t *cc,
                                                               quicly_flexicast_feedback_t f)
{
    quicly_flexicast_cc_on_feedback(cc, &f);
    return adaptive_drain_trace(cc);
}

static quicly_flexicast_cc_t *adaptive_drain_active(size_t members, uint64_t activation_member)
{
    quicly_flexicast_cc_t *cc = adaptive_drain_new(100000, 2000, members);
    quicly_flexicast_cc_trace_event_t e = adaptive_drain_deliver(cc, adaptive_drain_sample(1, 200, 1, 100000, 40000, 80));
    ok(e.state_after.drain_phase == 1 && adaptive_test_output(cc).rate_bytes_per_second == 50000);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(2, 450, activation_member, 100000, 40000, 80));
    ok(e.state_after.drain_phase == 2 && e.state_after.drain_member_id == activation_member);
    ok(e.state_after.drain_target_bytes_per_second == 32000 && e.state_after.drain_deadline == 1450);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 32000);
    return cc;
}

static void test_adaptive_drain(void)
{
    /* Observation does not apply headroom immediately, and a lower sample
     * during observation must not become a minimum-filtered drain target. */
    quicly_flexicast_cc_t *cc = adaptive_drain_new(100000, 2000, 1);
    quicly_flexicast_cc_trace_event_t e = adaptive_drain_deliver(cc, adaptive_drain_sample(1, 200, 1, 100000, 40000, 80));
    ok(e.state_after.drain_phase == 1 && e.state_after.drain_started_at == 200);
    ok(e.state_after.drain_deadline == 700 && adaptive_test_output(cc).rate_bytes_per_second == 50000);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(2, 449, 1, 100000, 10000, 80));
    ok(e.state_after.drain_phase == 1 && adaptive_test_output(cc).rate_bytes_per_second == 50000);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(3, 450, 1, 100000, 40000, 80));
    ok(e.state_after.drain_phase == 2 && e.state_after.drain_started_at == 450);
    ok(e.state_after.drain_ceiling_bytes_per_second == 40000 && e.state_after.drain_target_bytes_per_second == 32000);
    ok(e.state_after.drain_deadline == 1450 && adaptive_test_output(cc).rate_bytes_per_second == 32000);
    /* A duplicate frame and a new ACK carrying a repeated delivery publication
     * neither renew the deadline nor apply a second headroom multiplier. */
    quicly_flexicast_feedback_t f = adaptive_drain_sample(3, 700, 1, 32000, 32000, 80);
    e = adaptive_drain_deliver(cc, f);
    ok(e.state_after.drain_deadline == 1450 && adaptive_test_output(cc).rate_bytes_per_second == 32000);
    f.epoch = f.rtt_sample_epoch = 4;
    e = adaptive_drain_deliver(cc, f);
    ok(e.state_after.drain_target_bytes_per_second == 32000 && adaptive_test_output(cc).rate_bytes_per_second == 32000);
    for (uint64_t epoch = 5; epoch <= 7; ++epoch) {
        e = adaptive_drain_deliver(cc, adaptive_drain_sample(epoch, 700 + (epoch - 5) * 250, 1, 32000, 32000, 80));
        ok(e.state_after.drain_phase == 2 && e.state_after.drain_deadline == 1450);
        ok(e.state_after.drain_ceiling_bytes_per_second == 40000 && adaptive_test_output(cc).rate_bytes_per_second == 32000);
    }
    uint64_t reductions = adaptive_test_output(cc).rate_reduction_events;
    quicly_flexicast_cc_on_timeout(cc, 1450);
    e = adaptive_drain_trace(cc);
    ok(e.state_after.drain_phase == 0 && e.state_after.drain_ended_at == 1450);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 32000 && adaptive_test_output(cc).rate_reduction_events == reductions);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(8, 1700, 1, 100000, 10000, 80));
    ok(e.state_after.drain_phase == 0); /* no rearm from queued ACKs alone */
    quicly_flexicast_cc_free(cc);

    /* A far-away fixed target still obeys maximum50% steps and the elapsed
     *250ms clock; self-limited delivery at the target cannot compound80%. */
    cc = adaptive_drain_new(100000, 2000, 1);
    const int64_t times[] = {200, 449, 450, 699, 700, 949, 950};
    const uint64_t rates[] = {50000, 50000, 25000, 25000, 12500, 12500, 8000};
    for (size_t i = 0; i != sizeof(times) / sizeof(times[0]); ++i) {
        e = adaptive_drain_deliver(cc, adaptive_drain_sample(i + 1, times[i], 1, 100000, 10000, 80));
        ok(adaptive_test_output(cc).rate_bytes_per_second == rates[i]);
        if (times[i] >= 450)
            ok(e.state_after.drain_target_bytes_per_second == 8000 && e.state_after.drain_deadline == 1450);
        if (i == 2) {
            /* External load prevents new episodes, but does not erase an
             * active target backed by fresh, unlimited queued-path evidence. */
            quicly_flexicast_cc_hints_t external = {.external_load_epoch = 1, .external_load_queued_bytes = 4800};
            quicly_flexicast_cc_set_hints(cc, &external, 500);
        }
    }
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(8, 1200, 1, 8000, 8000, 80));
    ok(adaptive_test_output(cc).rate_bytes_per_second == 8000 && e.state_after.last_reduction_at == 950);
    quicly_flexicast_cc_free(cc);

    /* Independent congestion can cut below the fixed target; the episode
     * must not hold the rate up or restore it when it ends. CE retains15%. */
    cc = adaptive_drain_active(1, 1);
    f = adaptive_drain_sample(3, 700, 1, 100000, 1000, 80);
    f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_APP_LIMITED;
    f.ecn_ce_count = 1;
    e = adaptive_drain_deliver(cc, f);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 27200);
    ok(e.state_after.drain_target_bytes_per_second == 32000 && e.state_after.drain_deadline == 1450);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(4, 950, 1, 100000, 10000, 80));
    ok(adaptive_test_output(cc).rate_bytes_per_second == 13600);
    quicly_flexicast_cc_on_timeout(cc, 1450);
    e = adaptive_drain_trace(cc);
    ok(e.state_after.drain_phase == 0 && adaptive_test_output(cc).rate_bytes_per_second == 13600);
    quicly_flexicast_cc_free(cc);

    /* The clock is shared, so a different receiver may activate. Only that
     * activating owner can clear with fresh post-entry clean RTT, after the
     * existing group hold; other clean members cannot erase its queue. */
    cc = adaptive_drain_active(2, 2);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(3, 700, 2, 32000, 32000, 20));
    ok(e.state_after.drain_phase == 2); /* group hold from450 lasts until950 */
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(4, 950, 1, 32000, 32000, 20));
    ok(e.state_after.drain_phase == 2 && adaptive_test_output(cc).rate_bytes_per_second == 32000);
    f = adaptive_drain_sample(4, 951, 2, 32000, 32000, 20);
    f.rtt_sample_at = 449;
    e = adaptive_drain_deliver(cc, f);
    ok(e.state_after.drain_phase == 2);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(5, 952, 2, 32000, 32000, 20));
    ok(e.state_after.drain_phase == 0 && e.state_after.drain_ended_at == 952);
    quicly_flexicast_cc_free(cc);

    /* Exactly500ms expires observation before activation; no immediate retry
     * after expiry. A clean owner cancels earlier, but another member cannot. */
    for (size_t clean_cancel = 0; clean_cancel != 2; ++clean_cancel) {
        cc = adaptive_drain_new(100000, 2000, 2);
        e = adaptive_drain_deliver(cc, adaptive_drain_sample(1, 200, 1, 100000, 40000, 80));
        if (clean_cancel) {
            e = adaptive_drain_deliver(cc, adaptive_drain_sample(2, 300, 2, 100000, 100000, 20));
            ok(e.state_after.drain_phase == 1);
            e = adaptive_drain_deliver(cc, adaptive_drain_sample(2, 350, 1, 100000, 100000, 20));
            ok(e.state_after.drain_phase == 0 && e.state_after.drain_ended_at == 350);
        } else {
            e = adaptive_drain_deliver(cc, adaptive_drain_sample(2, 700, 1, 100000, 40000, 80));
            ok(e.state_after.drain_phase == 0 && e.state_after.drain_ended_at == 700);
        }
        e = adaptive_drain_deliver(cc, adaptive_drain_sample(3, 750, 1, 100000, 10000, 80));
        ok(e.state_after.drain_phase == 0);
        quicly_flexicast_cc_free(cc);
    }

    /* An actual ordinary growth rearms, but old send/RTT history cannot start
     * the new episode. Test delivery and RTT provenance independently. */
    for (size_t stale_field = 0; stale_field != 2; ++stale_field) {
        cc = adaptive_drain_active(2, 1);
        quicly_flexicast_cc_on_timeout(cc, 1450);
        (void)adaptive_drain_trace(cc);
        uint64_t epoch = 3;
        int64_t growth_at = 0;
        for (int64_t now = 1800; now <= 3300 && growth_at == 0; now += 250) {
            uint64_t rate = adaptive_test_output(cc).rate_bytes_per_second;
            f = adaptive_context_sample(epoch++, now, rate, 1, rate, 20);
            e = adaptive_drain_deliver(cc, f);
            if (adaptive_test_output(cc).rate_bytes_per_second > rate)
                growth_at = now;
        }
        ok(growth_at != 0);
        f = adaptive_context_sample(epoch++, growth_at + 250, 100000, 1, 10000, 80);
        if (stale_field == 0) {
            f.delivery_sample_sent_at_start = growth_at - 1;
            f.delivery_sample_sent_at_end = growth_at;
        } else {
            f.rtt_sample_at = growth_at - 1;
        }
        e = adaptive_drain_deliver(cc, f);
        ok(e.state_after.drain_phase == 0);
        f = adaptive_context_sample(epoch++, growth_at + 500, 100000, 1, 1000, 80);
        e = adaptive_drain_deliver(cc, f);
        ok(e.state_after.drain_phase == 1);
        /* Activation by another member needs the same post-growth history
         * boundary; a fresh identity cannot revive its older send/RTT sample. */
        f = adaptive_context_sample(1, growth_at + 750, 100000, 1, 1000, 80);
        f.member_id = 2;
        if (stale_field == 0) {
            f.delivery_sample_sent_at_start = growth_at - 1;
            f.delivery_sample_sent_at_end = growth_at;
        } else {
            f.rtt_sample_at = growth_at - 1;
        }
        e = adaptive_drain_deliver(cc, f);
        ok(e.state_after.drain_phase == 1 && e.state_after.drain_target_bytes_per_second == 0);
        quicly_flexicast_cc_free(cc);
    }

    /* Missing/limited/malformed native context and legacy callers retain their
     * normal controller behavior but cannot start this native-only episode. */
    for (size_t invalid = 0; invalid != 13; ++invalid) {
        cc = adaptive_drain_new(100000, 2000, 1);
        for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
            f = adaptive_drain_sample(epoch, 200 + (epoch - 1) * 250, 1, 100000, 10000, 80);
            switch (invalid) {
            case 0: f.delivery_sample_flags = QUICLY_FLEXICAST_SAMPLE_PRESENT; break;
            case 1: f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_APP_LIMITED; break;
            case 2: f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED; break;
            case 3: f.delivery_sample_flags |= QUICLY_FLEXICAST_SAMPLE_MIXED; break;
            case 4: f.delivery_sample_fanout = 0; break;
            case 5: f.delivery_sample_sent_at_end = 99; break;
            case 6: f.delivery_sample_acked_at_end = f.now + 1; break;
            case 7: f.delivery_sample_pacing_rate_bytes_per_second = 0; break;
            case 8: f.rtt_sample_flags = QUICLY_FLEXICAST_RTT_PRESENT; break;
            case 9: f.rtt_sample_flags |= QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT; break;
            case 10: f.rtt_sample_at = f.now + 1; break;
            case 11: f.rtt_sample_flags = 0; break;
            case 12: f.delivery_sample_flags = 0; f.rtt_sample_flags = 0; break;
            }
            e = adaptive_drain_deliver(cc, f);
            ok(e.state_after.drain_phase == 0);
        }
        quicly_flexicast_cc_free(cc);
    }
    /* CE-only and clean flat random-loss evidence must not arm drain. */
    for (size_t ce = 0; ce != 2; ++ce) {
        cc = adaptive_drain_new(100000, 2000, 1);
        for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
            f = adaptive_drain_sample(epoch, 200 + (epoch - 1) * 250, 1, 100000, 10000, ce ? 80 : 20);
            f.ecn_ce_count = ce;
            f.lost_packets = ce ? 0 : 2;
            e = adaptive_drain_deliver(cc, f);
            ok(e.state_after.drain_phase == 0);
        }
        if (!ce)
            ok(adaptive_test_output(cc).rate_reduction_events == 0);
        quicly_flexicast_cc_free(cc);
    }
    cc = adaptive_drain_new(100000, 2000, 1);
    quicly_flexicast_cc_hints_t hints = {.external_load_epoch = 1, .external_load_queued_bytes = 4800};
    quicly_flexicast_cc_set_hints(cc, &hints, 100);
    for (uint64_t epoch = 1; epoch <= 3; ++epoch) {
        e = adaptive_drain_deliver(cc, adaptive_drain_sample(epoch, 200 + (epoch - 1) * 250, 1, 100000, 10000, 80));
        ok(e.state_after.drain_phase == 0);
    }
    quicly_flexicast_cc_free(cc);

    /* The historical physical fanout, not current scheduler hints, sets the
     * fixed target for native multicast and two/four replicated copies. */
    const uint32_t fanouts[] = {1, 2, 4};
    for (size_t i = 0; i != sizeof(fanouts) / sizeof(fanouts[0]); ++i) {
        cc = adaptive_drain_new(100000, 2000, 1);
        hints = (quicly_flexicast_cc_hints_t){.delivery_rate_divisor = 32};
        quicly_flexicast_cc_set_hints(cc, &hints, 100);
        for (uint64_t epoch = 1; epoch <= 2; ++epoch) {
            f = adaptive_drain_sample(epoch, 200 + (epoch - 1) * 250, 1, 100000, 40000 / fanouts[i], 80);
            f.delivery_sample_fanout = fanouts[i];
            e = adaptive_drain_deliver(cc, f);
        }
        ok(e.state_after.drain_phase == 2 && e.state_after.drain_ceiling_bytes_per_second == 40000);
        ok(e.state_after.drain_target_bytes_per_second == 32000 && adaptive_test_output(cc).rate_bytes_per_second == 32000);
        quicly_flexicast_cc_free(cc);
    }

    /* A growth attempt erased by an aggregate cap is not an actual growth and
     * cannot rearm an already cancelled observation episode. */
    cc = adaptive_drain_new(100000, 2000, 1);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(1, 200, 1, 100000, 40000, 80));
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(2, 350, 1, 100000, 100000, 20));
    ok(e.state_after.drain_phase == 0);
    hints = (quicly_flexicast_cc_hints_t){.aggregate_rate_limit_bytes_per_second = 50000};
    quicly_flexicast_cc_set_hints(cc, &hints, 500);
    f = adaptive_context_sample(3, 800, 50000, 1, 50000, 20);
    e = adaptive_drain_deliver(cc, f);
    ok(adaptive_test_output(cc).rate_bytes_per_second == 50000);
    ok(e.state_after.last_growth_at == 800); /* retain ordinary capped-attempt clock semantics */
    f = adaptive_context_sample(4, 1050, 100000, 1, 10000, 80);
    e = adaptive_drain_deliver(cc, f);
    ok(e.state_after.drain_phase == 0);
    quicly_flexicast_cc_free(cc);

    /* A floor-clamped ordinary attempt cannot activate drain or report another
     * effective reduction. Its existing ordinary cut-clock behavior is retained. */
    cc = adaptive_drain_new(10000, 9000, 1);
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(1, 200, 1, 10000, 1000, 80));
    uint64_t reduced_at_floor = adaptive_test_output(cc).rate_reduction_events;
    e = adaptive_drain_deliver(cc, adaptive_drain_sample(2, 450, 1, 10000, 1000, 80));
    ok(e.state_after.drain_phase != 2 && adaptive_test_output(cc).rate_bytes_per_second == 9000);
    ok(adaptive_test_output(cc).rate_reduction_events == reduced_at_floor && e.state_after.last_reduction_at == 450);
    quicly_flexicast_cc_free(cc);

    /* Removing an unrelated member does not erase an episode; owner removal
     * and rekey do. Rekey starts a fresh provenance epoch without restoring rate. */
    for (size_t reset = 0; reset != 2; ++reset) {
        cc = adaptive_drain_active(2, 2);
        uint64_t before = adaptive_test_output(cc).rate_bytes_per_second;
        if (reset) {
            quicly_flexicast_cc_on_epoch_reset(cc, 600);
        } else {
            quicly_flexicast_cc_on_member_removed(cc, 1, 550);
            e = adaptive_drain_trace(cc);
            ok(e.state_after.drain_phase == 2);
            quicly_flexicast_cc_on_member_removed(cc, 2, 600);
        }
        e = adaptive_drain_trace(cc);
        ok(e.state_after.drain_phase == 0 && adaptive_test_output(cc).rate_bytes_per_second == before);
        if (reset) {
            f = adaptive_context_sample(1, 900, 100000, 1, 10000, 80);
            e = adaptive_drain_deliver(cc, f);
            ok(e.state_after.drain_phase == 1);
        }
        quicly_flexicast_cc_free(cc);
    }
}
