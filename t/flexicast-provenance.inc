/* Native measurement provenance: these tests use actual packet construction,
 * socket-submission accounting, ACK ranges, and the controller callback. */
static quicly_flexicast_send_context_t provenance_context(uint64_t rate, uint32_t fanout, uint32_t flags)
{
    return (quicly_flexicast_send_context_t){.pacing_rate_bytes_per_second = rate, .physical_fanout = fanout,
                                            .flags = QUICLY_FLEXICAST_SAMPLE_VALID | flags};
}

static uint64_t provenance_send(quicly_flexicast_flow_t *flow, int64_t now,
                                const quicly_flexicast_send_context_t *context, size_t *size)
{
    uint8_t packet[1300];
    uint64_t pn;
    regression_send(flow, packet, sizeof(packet), size, &pn, now - 1);
    ok(quicly_flexicast_mark_submitted_with_context(flow, 0, pn, now, context) == 0);
    return pn;
}

static void test_feedback_provenance(void)
{
    uint8_t secret[32] = {17};
    size_t size;
    uint64_t rates[2];
    quicly_flexicast_send_context_t context = provenance_context(1000000, 2, 0);
    for (int split = 0; split != 2; ++split) {
        quicly_flexicast_flow_t *flow = create_cc_flow(1000, secret);
        ok(quicly_flexicast_attach_at(flow, 1, 100) == 0);
        provenance_send(flow, 100, &context, &size);
        regression_ack(flow, 1, 0, 0, 0, 200);
        quicly_flexicast_send_context_t app = provenance_context(1000000, 2, QUICLY_FLEXICAST_SAMPLE_APP_LIMITED);
        quicly_flexicast_send_context_t host = provenance_context(1000000, 2, QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED);
        provenance_send(flow, 201, &app, &size);
        provenance_send(flow, 211, &host, &size);
        if (split) {
            regression_ack(flow, 1, 1, 1, 0, 220);
            regression_ack(flow, 1, 2, 2, 0, 220);
        } else {
            regression_ack(flow, 1, 1, 2, 0, 220);
        }
        ok(test_last_feedback.delivery_rate_sample_epoch == 0);
        provenance_send(flow, 221, &context, &size);
        regression_ack(flow, 1, 3, 3, 0, 230);
        rates[split] = test_last_feedback.delivery_rate_bytes_per_second;
        ok(rates[split] == size * 2 * 1000 / 111);
        ok(test_last_feedback.delivery_sample_bytes == size * 2);
        ok(test_last_feedback.delivery_sample_flags == (QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID |
                                                        QUICLY_FLEXICAST_SAMPLE_APP_LIMITED | QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED));
        ok(test_last_feedback.delivery_sample_pacing_rate_bytes_per_second == 1000000);
        ok(test_last_feedback.delivery_sample_fanout == 2);
        ok(test_last_feedback.delivery_sample_sent_at_start == 100 && test_last_feedback.delivery_sample_sent_at_end == 211);
        ok(test_last_feedback.delivery_sample_acked_at_start == 200 && test_last_feedback.delivery_sample_acked_at_end == 220);
        ok(test_last_feedback.delivery_rate_sample_epoch == 1);
        uint64_t rtt_epoch = test_last_feedback.rtt_sample_epoch;
        quicly_ack_frame_t ce = {.largest_acknowledged = 3, .smallest_acknowledged = 3, .ack_block_lengths = {1},
                                .ecn_counts = {0, 0, 1}, .ack_delay = 25};
        size_t acked, lost, complete;
        ok(quicly_flexicast_ack_frame_at(flow, 1, &ce, &acked, &lost, &complete, 500) == 0);
        ok(acked == 0 && test_last_feedback.ecn_ce_count == 1);
        ok(test_last_feedback.delivery_rate_sample_epoch == 1 && test_last_feedback.delivery_rate_bytes_per_second == rates[split]);
        ok(test_last_feedback.delivery_sample_sent_at_end == 211 && test_last_feedback.delivery_sample_acked_at_end == 220);
        ok(test_last_feedback.rtt_sample_epoch == rtt_epoch && test_last_feedback.rtt_sample_at == 230);
        ok(test_last_feedback.rtt_ack_delay_msec == 0 && test_last_feedback.ack_delay_msec == 25);

        /* Rekey clears publication identity/context, independently of retained
         * statistics, then publishes the new rate/fanout without old flags. */
        secret[0]++;
        ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secret, sizeof(secret)), 100, 600) == 0);
        ok(quicly_flexicast_attach_at(flow, 1, 600) == 0);
        quicly_flexicast_send_context_t next = provenance_context(25000, 1, 0);
        for (int i = 0; i != 3; ++i) {
            uint64_t pn = provenance_send(flow, 700 + i * 10, &next, &size);
            regression_ack(flow, 1, pn, pn, 0, 702 + i * 10);
            ok(test_last_feedback.delivery_rate_sample_epoch == (i == 2 ? 1 : 0));
            if (i != 2) {
                ok(test_last_feedback.delivery_rate_bytes_per_second == 0);
                ok(test_last_feedback.delivery_sample_flags == QUICLY_FLEXICAST_SAMPLE_PRESENT);
            }
        }
        ok(test_last_feedback.delivery_sample_flags == (QUICLY_FLEXICAST_SAMPLE_PRESENT | QUICLY_FLEXICAST_SAMPLE_VALID));
        ok(test_last_feedback.delivery_sample_pacing_rate_bytes_per_second == 25000 && test_last_feedback.delivery_sample_fanout == 1);
        ok(test_last_feedback.delivery_rate_bytes_per_second == size * 1000 / 10);
        ok(test_last_feedback.rtt_sample_epoch == 3);
        quicly_flexicast_flow_free(flow);
    }
    ok(rates[0] == rates[1]);

    /* Mixing either rate or fanout within a bucket cannot be interpreted as
     * one coherent capacity measurement. Missing context stays explicitly
     * native/unknown, never a legacy-controller fallback. */
    for (int kind = 0; kind != 3; ++kind) {
        quicly_flexicast_flow_t *flow = create_cc_flow(1000, secret);
        ok(quicly_flexicast_attach_at(flow, 1, 100) == 0);
        provenance_send(flow, 100, &context, &size);
        regression_ack(flow, 1, 0, 0, 0, 102);
        provenance_send(flow, 110, &context, &size);
        quicly_flexicast_send_context_t other = context;
        if (kind == 0)
            other.pacing_rate_bytes_per_second /= 2;
        else
            other.physical_fanout = 1;
        provenance_send(flow, 111, kind == 2 ? NULL : &other, &size);
        regression_ack(flow, 1, 1, 2, 0, 120);
        provenance_send(flow, 121, &context, &size);
        regression_ack(flow, 1, 3, 3, 0, 130);
        ok(test_last_feedback.delivery_rate_sample_epoch == 1);
        ok(test_last_feedback.delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_PRESENT);
        ok(!(test_last_feedback.delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_VALID));
        ok(test_last_feedback.delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_MIXED);
        quicly_flexicast_flow_free(flow);
    }

    quicly_flexicast_flow_t *flow = create_cc_flow(1000, secret);
    ok(quicly_flexicast_attach_at(flow, 1, 100) == 0);
    provenance_send(flow, 100, &context, &size);
    provenance_send(flow, 110, &context, &size);
    regression_ack(flow, 1, 1, 1, 0, 120);
    ok(test_last_feedback.rtt_sample_epoch == 1 && test_last_feedback.latest_rtt_msec == 10);
    regression_ack(flow, 1, 0, 1, 25, 200); /* largest duplicate, older packet newly ACKed */
    ok(test_last_feedback.acked_packets == 1);
    ok(test_last_feedback.rtt_sample_epoch == 1 && test_last_feedback.rtt_sample_at == 120);
    ok(test_last_feedback.latest_rtt_msec == 10 && test_last_feedback.rtt_ack_delay_msec == 0);
    uint64_t pn = provenance_send(flow, 210, &context, &size);
    ok(quicly_flexicast_mark_submitted(flow, 0, pn, 0) == 0);
    regression_ack(flow, 1, pn, pn, 0, 220);
    ok(test_last_feedback.rtt_sample_epoch == 1); /* unknown actual send time */
    ok(test_last_feedback.delivery_sample_sent_at_start == 100); /* reordered older packet is in this interval */
    quicly_flexicast_flow_free(flow);

    flow = create_cc_flow(1000, secret);
    ok(quicly_flexicast_attach_at(flow, 1, 100) == 0);
    provenance_send(flow, 100, &context, &size);
    regression_ack(flow, 1, 0, 0, 0, 102);
    pn = provenance_send(flow, 110, &context, &size);
    ok(quicly_flexicast_mark_submitted(flow, 0, pn, 0) == 0);
    regression_ack(flow, 1, pn, pn, 0, 112);
    for (int i = 0; i != 3; ++i) {
        pn = provenance_send(flow, 120 + i * 10, &context, &size);
        regression_ack(flow, 1, pn, pn, 0, 122 + i * 10);
        ok(!!(test_last_feedback.delivery_sample_flags & QUICLY_FLEXICAST_SAMPLE_VALID) == (i == 2));
    }
    ok(test_last_feedback.delivery_sample_sent_at_start == 120 && test_last_feedback.delivery_sample_sent_at_end == 130);
    ok(test_last_feedback.delivery_rate_bytes_per_second == size * 1000 / 10);
    quicly_flexicast_flow_free(flow);

    flow = create_cc_flow(1000, secret);
    ok(quicly_flexicast_attach_at(flow, 1, 100) == 0);
    provenance_send(flow, 100, &context, &size);
    regression_ack(flow, 1, 0, 0, 0, 102);
    provenance_send(flow, 200, &context, &size);
    regression_ack(flow, 1, 1, 1, 25, 226);
    ok(test_last_feedback.rtt_sample_epoch == 2 && test_last_feedback.raw_rtt_msec == 26);
    ok(test_last_feedback.latest_rtt_msec == 26 && test_last_feedback.applied_ack_delay_msec == 0);
    ok(test_last_feedback.rtt_sample_flags & QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT);
    provenance_send(flow, 300, &context, &size);
    regression_ack(flow, 1, 2, 2, 25, 327);
    ok(test_last_feedback.rtt_sample_epoch == 3 && test_last_feedback.raw_rtt_msec == 27);
    ok(test_last_feedback.latest_rtt_msec == 2 && test_last_feedback.applied_ack_delay_msec == 25);
    ok(!(test_last_feedback.rtt_sample_flags & QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT));
    quicly_flexicast_flow_free(flow);

    /* The only explicitly limited packet is lost. Its evidence still marks
     * the later ACK interval spanning the gap, then expires at a new boundary. */
    for (int cause = 0; cause != 2; ++cause) {
        uint32_t flag = cause == 0 ? QUICLY_FLEXICAST_SAMPLE_APP_LIMITED : QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED;
        quicly_flexicast_send_context_t limited = provenance_context(1000000, 2, flag);
        flow = create_cc_flow(1000, secret);
        ok(quicly_flexicast_attach_at(flow, 1, 100) == 0);
        provenance_send(flow, 100, &context, &size);
        regression_ack(flow, 1, 0, 0, 0, 110);
        provenance_send(flow, 120, &limited, &size); /* PN 1 is never ACKed */
        provenance_send(flow, 140, &context, &size);
        regression_ack(flow, 1, 2, 2, 0, 150);
        provenance_send(flow, 160, &context, &size);
        regression_ack(flow, 1, 3, 3, 0, 170);
        ok(test_last_feedback.delivery_rate_sample_epoch == 1);
        ok(test_last_feedback.delivery_sample_sent_at_start == 100);
        ok(test_last_feedback.delivery_sample_flags & flag);
        provenance_send(flow, 180, &context, &size);
        regression_ack(flow, 1, 4, 4, 0, 190);
        ok(test_last_feedback.lost_packets == 1);
        ok(test_last_feedback.delivery_sample_sent_at_start == 140);
        ok(!(test_last_feedback.delivery_sample_flags & flag));

        provenance_send(flow, 900, &limited, &size);
        secret[0]++;
        ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secret, sizeof(secret)), 100, 1000) == 0);
        ok(quicly_flexicast_attach_at(flow, 1, 1000) == 0);
        /* Restart this synthetic clock to prove that the old watermark was
         * cleared, rather than merely overtaken by a later timestamp. */
        for (int i = 0; i != 3; ++i) {
            pn = provenance_send(flow, 100 + i * 20, &context, &size);
            regression_ack(flow, 1, pn, pn, 0, 110 + i * 20);
        }
        ok(test_last_feedback.delivery_rate_sample_epoch == 1);
        ok(!(test_last_feedback.delivery_sample_flags & flag));
        quicly_flexicast_flow_free(flow);
    }

    /* More than 4096 successful member submissions sharing one actual time
     * and context must not fill the sparse exception table. */
    flow = create_cc_flow(1000, secret);
    for (uint64_t member = 1; member <= 4; ++member)
        ok(quicly_flexicast_attach_at(flow, member, 100) == 0);
    uint8_t packet[1300];
    for (size_t i = 0; i != QUICLY_FLEXICAST_SENT_WINDOW; ++i) {
        regression_send(flow, packet, sizeof(packet), &size, &pn, 100);
        for (uint64_t member = 1; member <= 4; ++member)
            ok(quicly_flexicast_mark_submitted_with_context(flow, member, pn, 110, &context) == 0);
    }
    for (uint64_t member = 1; member <= 4; ++member) {
        regression_ack(flow, member, pn, pn, 0, 120);
        ok(test_last_feedback.rtt_sample_epoch == 1 && test_last_feedback.latest_rtt_msec == 10);
    }
    quicly_flexicast_flow_free(flow);
}
