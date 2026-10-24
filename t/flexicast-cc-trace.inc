/* trace state is observational and must not change controller output */
static void trace_test_event(quicly_flexicast_cc_t *cc, size_t step)
{
    int64_t now = 100 + (int64_t)step * 1000;
    switch (step % 6) {
    case 0:
        quicly_flexicast_cc_on_member_added(cc, 1, now);
        break;
    case 1: {
        quicly_flexicast_cc_hints_t hints = {.active_senders = 2,
            .median_sender_rate_bytes_per_second = 200000,
            .aggregate_rate_limit_bytes_per_second = 80000,
            .external_load_epoch = step + 1,
            .external_load_queued_bytes = step % 12 == 1 ? 4800 : 0};
        quicly_flexicast_cc_set_hints(cc, &hints, now);
    } break;
    case 2: {
        quicly_flexicast_feedback_t feedback = {.member_id = 1, .epoch = step + 1,
            .acked_packets = 8, .acked_bytes = 9600,
            .delivery_rate_bytes_per_second = 20000,
            .delivery_rate_sample_epoch = step + 1,
            .minimum_rtt_msec = 20, .latest_rtt_msec = 80, .now = now};
        quicly_flexicast_cc_on_feedback(cc, &feedback);
    } break;
    case 3:
        quicly_flexicast_cc_on_timeout(cc, now);
        break;
    case 4:
        quicly_flexicast_cc_on_epoch_reset(cc, now);
        break;
    case 5:
        quicly_flexicast_cc_on_member_removed(cc, 1, now);
        break;
    }
}

static void test_cc_trace(void)
{
    quicly_flexicast_cc_config_t config = {.maximum_members = 2,
        .startup_rate_bytes_per_second = 100000, .minimum_rate_bytes_per_second = 2000,
        .maximum_rate_bytes_per_second = 1000000, .maximum_datagram_size = 1200,
        .feedback_timeout_msec = 1000};
    quicly_flexicast_cc_type_t *types[] = {&quicly_flexicast_cc_type_adaptive, &quicly_flexicast_cc_type_multicast};
    for (size_t type = 0; type != sizeof(types) / sizeof(types[0]); ++type) {
        quicly_flexicast_cc_t *plain = NULL, *traced = NULL;
        quicly_flexicast_cc_output_t plain_output, traced_output;
        quicly_flexicast_cc_trace_event_t events[7];
        uint64_t overwritten = 999;
        ok(quicly_flexicast_cc_create(&plain, types[type], &config, 100) == 0);
        ok(quicly_flexicast_cc_create(&traced, types[type], &config, 100) == 0);
        ok(quicly_flexicast_cc_read_trace(traced, events, 7, &overwritten) == 0 && overwritten == 0);
        ok(quicly_flexicast_cc_enable_trace(traced, 7) == 0);
        for (size_t step = 0; step != 48; ++step) {
            trace_test_event(plain, step);
            trace_test_event(traced, step);
            quicly_flexicast_cc_get_output(plain, &plain_output);
            quicly_flexicast_cc_get_output(traced, &traced_output);
            ok(memcmp(&plain_output, &traced_output, sizeof(plain_output)) == 0);
        }
        ok(quicly_flexicast_cc_read_trace(traced, NULL, 0, &overwritten) == 0 && overwritten == 41);
        ok(quicly_flexicast_cc_enable_trace(traced, 0) != 0);
        ok(quicly_flexicast_cc_enable_trace(traced, QUICLY_FLEXICAST_CC_TRACE_MAX_CAPACITY + 1U) != 0);
        ok(quicly_flexicast_cc_read_trace(traced, events, 3, &overwritten) == 3 && overwritten == 41);
        for (size_t i = 0; i != 3; ++i) {
            ok(events[i].sequence == 42 + i);
            ok(events[i].now == 100 + (int64_t)(41 + i) * 1000);
            ok(events[i].state_before.available == (type == 0));
        }
        ok(events[0].type == QUICLY_FLEXICAST_CC_TRACE_MEMBER_REMOVED);
        ok(events[1].type == QUICLY_FLEXICAST_CC_TRACE_MEMBER_ADDED);
        ok(events[2].type == QUICLY_FLEXICAST_CC_TRACE_HINTS);
        ok(events[2].hints.external_load_epoch == 44);
        ok(quicly_flexicast_cc_read_trace(traced, events, 7, &overwritten) == 4 && overwritten == 41);
        for (size_t i = 0; i != 4; ++i)
            ok(events[i].sequence == 45 + i);
        ok(events[0].type == QUICLY_FLEXICAST_CC_TRACE_FEEDBACK && events[0].feedback.epoch == 45);
        ok(events[1].type == QUICLY_FLEXICAST_CC_TRACE_TIMEOUT);
        ok(events[2].type == QUICLY_FLEXICAST_CC_TRACE_EPOCH_RESET);
        if (type == 0) {
            ok(events[0].state_after.growth_blocked_until > events[0].now);
            ok(events[0].rate_before == events[0].rate_after && events[0].reason == QUICLY_FLEXICAST_CC_REASON_RTT);
            ok(events[0].state_after.last_delivery_sample_epoch == 45);
            ok(events[2].state_before.last_delivery_sample_epoch == 0); /* reset has no selected member */
        }
        ok(quicly_flexicast_cc_read_trace(traced, events, 7, &overwritten) == 0 && overwritten == 41);
        quicly_flexicast_cc_disable_trace(traced);
        trace_test_event(plain, 48);
        trace_test_event(traced, 48);
        quicly_flexicast_cc_get_output(plain, &plain_output);
        quicly_flexicast_cc_get_output(traced, &traced_output);
        ok(memcmp(&plain_output, &traced_output, sizeof(plain_output)) == 0);
        ok(quicly_flexicast_cc_read_trace(traced, events, 7, &overwritten) == 0 && overwritten == 0);
        ok(quicly_flexicast_cc_enable_trace(traced, 1) == 0);
        quicly_flexicast_cc_on_epoch_reset(traced, 50000);
        ok(quicly_flexicast_cc_read_trace(traced, events, 7, &overwritten) == 1 && overwritten == 0);
        ok(events[0].sequence == 1 && events[0].type == QUICLY_FLEXICAST_CC_TRACE_EPOCH_RESET);
        quicly_flexicast_cc_free(traced);
        quicly_flexicast_cc_free(plain);
    }
    ok(quicly_flexicast_cc_enable_trace(NULL, 1) != 0);
    quicly_flexicast_cc_disable_trace(NULL);
    uint64_t overwritten = 1;
    ok(quicly_flexicast_cc_read_trace(NULL, NULL, 0, &overwritten) == 0 && overwritten == 0);
}
