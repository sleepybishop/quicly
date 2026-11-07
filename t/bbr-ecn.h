/* classic ECN must remain an independent congestion signal when loss is also reported or later disproved */
static void init_bbr_ecn_test(quicly_cc_t *cc, quicly_loss_t *loss)
{
    static const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    static const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    static const uint16_t max_ack_delay = 25;
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, cc, &conf, 1200, 0);
    quicly_bbr_configure(cc, 1200, 100, 1, 0);
    *loss = (quicly_loss_t){.conf = &loss_conf,
                            .max_ack_delay = &max_ack_delay,
                            .rtt = {.latest = 100, .minimum = 100, .smoothed = 100, .variance = 5}};
}

static void lose_bbr_ecn_test_packet(quicly_cc_t *cc, quicly_loss_t *loss, quicly_bbr_packet_t *packet, uint64_t pn,
                                     uint64_t next_pn, double sent_at, double now)
{
    quicly_bbr_packet_lost(cc, &packet->meta, pn, sent_at, (uint32_t)loss->sentmap.bytes_in_flight, now);
    cc->type->cc_on_lost(cc, loss, packet->meta.bytes, pn, next_pn, now, 1200);
    loss->sentmap.bytes_in_flight -= packet->meta.bytes;
}

static void test_bbr_ecn_mixed_loss(void)
{
    for (int with_loss = 0; with_loss != 2; ++with_loss) {
        quicly_cc_t cc;
        quicly_loss_t loss;
        init_bbr_ecn_test(&cc, &loss);
        quicly_cc_bbr_t *b = &cc.state.bbr;
        quicly_bbr_packet_t packets[100];
        for (size_t i = 0; i != PTLS_ELEMENTSOF(packets); ++i)
            ok(quicly_bbr_packet_sent(&cc, packets + i, 1200, (i + 1) * 1200, i, 1));
        loss.sentmap.bytes_in_flight = 120000;

        /* native ACK processing supplies packet losses before its final CE notification */
        quicly_bbr_begin_ack(&cc, 101);
        quicly_bbr_packet_acked(&cc, packets + 3, 3, 1, 101);
        loss.sentmap.bytes_in_flight -= 1200;
        if (with_loss)
            lose_bbr_ecn_test_packet(&cc, &loss, packets, 0, 100, 1, 101);
        quicly_cc_ecn_counts_t ecn = {.total = 1, .ce = 1};
        cc.type->cc_on_acked(&cc, &loss, 1200, 3, (uint32_t)loss.sentmap.bytes_in_flight, 1, 100, 101, 1200, &ecn);
        uint32_t before_cwnd = cc.cwnd;
        uint64_t before_bw = b->engine.bw;
        ok(before_bw != 0 && !b->engine.full_bw_reached);
        cc.type->cc_on_lost(&cc, &loss, 0, 3, 100, 101, 1200);
        ok(cc.cwnd == before_cwnd * 7 / 10);
        ok(b->engine.ecn_cwnd == cc.cwnd);
        ok(b->engine.ecn_bw == before_bw * 7 / 10);
        ok(b->engine.full_bw_reached && b->engine.state == QUICLY_BBR_BBR_STATE_DRAIN);
        ok(cc.num_ecn_loss_episodes == (with_loss ? 0 : 1));

        /* startup interval is much faster than this first bandwidth sample; CE must immediately apply DRAIN pacing */
        uint64_t rate = (QUICLY_BBR_SECONDS << 10) / b->stats.pacing_interval_m;
        ok(b->engine.pacing_gain_h == 50 && rate <= b->engine.ecn_bw / 2);
        ok(rate != 0);

        uint32_t capped_cwnd = cc.cwnd;
        uint64_t capped_bw = b->engine.ecn_bw, capped_interval = b->stats.pacing_interval_m;
        cc.type->cc_on_lost(&cc, &loss, 0, 4, 100, 102, 1200);
        ok(cc.cwnd == capped_cwnd && b->engine.ecn_bw == capped_bw);
        ok(b->stats.pacing_interval_m == capped_interval && cc.num_ecn_loss_episodes == (with_loss ? 0 : 1));

        /* a later flight is eligible for another CE response, including when packet loss started the first episode */
        quicly_bbr_packet_t next;
        ok(quicly_bbr_packet_sent(&cc, &next, 1200, (uint32_t)loss.sentmap.bytes_in_flight + 1200, 100, 103));
        loss.sentmap.bytes_in_flight += 1200;
        cc.type->cc_on_lost(&cc, &loss, 0, 100, 101, 203, 1200);
        ok(cc.cwnd == capped_cwnd * 7 / 10);
        ok(b->engine.ecn_bw == capped_bw * 7 / 10);
        ok(cc.num_ecn_loss_episodes == (with_loss ? 1 : 2));
    }
}

static void test_bbr_ecn_probe_pacing(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss;
    init_bbr_ecn_test(&cc, &loss);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    b->engine.full_bw_reached = 1;
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_UP;
    b->engine.bw = b->engine.max_bw = 1000000;
    b->stats.pacing_interval_m = 1; /* stale fast pacing must not survive the phase transition */
    quicly_bbr_packet_t packet;
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 1200, 0, 1));
    loss.sentmap.bytes_in_flight = 1200;
    cc.type->cc_on_lost(&cc, &loss, 0, 0, 1, 100, 1200);
    uint64_t rate = (QUICLY_BBR_SECONDS << 10) / b->stats.pacing_interval_m;
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_DOWN);
    ok(b->engine.ecn_bw == 700000);
    ok(b->engine.pacing_gain_h == 90 && rate <= b->engine.ecn_bw * 9 / 10);
    ok(rate != 0);
    ok(cc.num_ecn_loss_episodes == 1);

    /* public ECN counter counts ECN-only episodes; later packet loss reclassifies this same episode */
    lose_bbr_ecn_test_packet(&cc, &loss, &packet, 0, 1, 1, 101);
    ok(cc.num_loss_episodes == 1 && cc.num_ecn_loss_episodes == 0);
}

static void test_bbr_ecn_before_bandwidth_sample(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss;
    init_bbr_ecn_test(&cc, &loss);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    ok(b->engine.bw == 0 && b->stats.pacing_interval_m != 0);
    uint64_t initial_rate = (QUICLY_BBR_SECONDS << 10) / b->stats.pacing_interval_m;
    cc.type->cc_on_lost(&cc, &loss, 0, 0, 1, 100, 1200);
    ok(b->engine.ecn_bw == initial_rate * 7 / 10);
    ok(b->engine.ecn_bw != 0 && b->engine.ecn_bw != UINT64_MAX);
    ok(b->engine.full_bw_reached && b->engine.state == QUICLY_BBR_BBR_STATE_DRAIN);
    ok(b->stats.pacing_interval_m != 0);
    uint64_t rate = (QUICLY_BBR_SECONDS << 10) / b->stats.pacing_interval_m;
    ok(rate != 0 && rate <= b->engine.ecn_bw / 2);
}

static void test_bbr_ecn_survives_old_loss_undo(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss;
    init_bbr_ecn_test(&cc, &loss);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_bbr_packet_t packets[5];
    ok(quicly_bbr_packet_sent(&cc, packets, 1000, 1000, 0, 0));
    ok(quicly_bbr_packet_sent(&cc, packets + 1, 1000, 2000, 1, 1));
    loss.sentmap.bytes_in_flight = 2000;
    quicly_bbr_begin_ack(&cc, 101);
    quicly_bbr_packet_acked(&cc, packets + 1, 1, 1, 101);
    loss.sentmap.bytes_in_flight = 1000;
    cc.type->cc_on_acked(&cc, &loss, 1000, 1, 1000, 0, 2, 101, 1200, NULL);
    lose_bbr_ecn_test_packet(&cc, &loss, packets, 0, 2, 0, 200);
    ok(b->undo_pending == 1);

    ok(quicly_bbr_packet_sent(&cc, packets + 2, 1000, 1000, 2, 201));
    loss.sentmap.bytes_in_flight = 1000;
    quicly_bbr_begin_ack(&cc, 301);
    quicly_bbr_packet_acked(&cc, packets + 2, 2, 201, 301);
    loss.sentmap.bytes_in_flight = 0;
    quicly_cc_ecn_counts_t ecn = {.total = 1, .ce = 1};
    cc.type->cc_on_acked(&cc, &loss, 1000, 2, 0, 0, 3, 301, 1200, &ecn);
    cc.type->cc_on_lost(&cc, &loss, 0, 2, 3, 301, 1200);
    uint64_t cap = b->engine.ecn_cwnd, bandwidth_cap = b->engine.ecn_bw;
    ok(cap != UINT64_MAX && bandwidth_cap != UINT64_MAX);
    ok(b->engine.full_bw_reached && b->engine.state == QUICLY_BBR_BBR_STATE_DRAIN);

    /* old packet proves its loss was spurious, but says nothing about the later CE mark */
    quicly_bbr_begin_ack(&cc, 302);
    quicly_bbr_packet_acked(&cc, packets, 0, 0, 302);
    cc.type->cc_on_acked(&cc, &loss, 0, 0, 0, 0, 3, 302, 1200, NULL);
    ok(cc.num_loss_episodes_undone == 0);
    ok(b->engine.full_bw_reached && b->engine.state != QUICLY_BBR_BBR_STATE_STARTUP);
    ok(b->engine.ecn_cwnd == cap && b->engine.ecn_bw == bandwidth_cap);
    ok(cc.cwnd <= cap && quicly_bbr_pacing_rate(&cc) <= bandwidth_cap / 1000);

    /* clean ACK of a post-CE packet releases temporary bounds without undoing the genuine startup exit */
    ok(quicly_bbr_packet_sent(&cc, packets + 3, 1000, 1000, 3, 303));
    loss.sentmap.bytes_in_flight = 1000;
    quicly_bbr_begin_ack(&cc, 403);
    quicly_bbr_packet_acked(&cc, packets + 3, 3, 303, 403);
    loss.sentmap.bytes_in_flight = 0;
    cc.type->cc_on_acked(&cc, &loss, 1000, 3, 0, 0, 4, 403, 1200, NULL);
    ok(b->engine.ecn_cwnd == UINT64_MAX && b->engine.ecn_bw == UINT64_MAX);
    ok(b->engine.full_bw_reached && b->engine.state != QUICLY_BBR_BBR_STATE_STARTUP);

    /* invalidation applies to the old snapshot only: a future loss-only episode remains undoable */
    ok(quicly_bbr_packet_sent(&cc, packets + 4, 1000, 1000, 4, 404));
    loss.sentmap.bytes_in_flight = 1000;
    lose_bbr_ecn_test_packet(&cc, &loss, packets + 4, 4, 5, 404, 504);
    ok(b->undo_pending == 1);
    quicly_bbr_begin_ack(&cc, 604);
    quicly_bbr_packet_acked(&cc, packets + 4, 4, 404, 604);
    cc.type->cc_on_acked(&cc, &loss, 0, 4, 0, 0, 5, 604, 1200, NULL);
    ok(cc.num_loss_episodes_undone == 1 && b->undo_pending == 0);
    ok(b->engine.full_bw_reached && b->engine.state != QUICLY_BBR_BBR_STATE_STARTUP);
}

static void test_bbr_ecn_regressions(void)
{
    subtest("mixed-loss-and-ecn", test_bbr_ecn_mixed_loss);
    subtest("ecn-probe-pacing", test_bbr_ecn_probe_pacing);
    subtest("ecn-before-bandwidth-sample", test_bbr_ecn_before_bandwidth_sample);
    subtest("ecn-survives-old-loss-undo", test_bbr_ecn_survives_old_loss_undo);
}
