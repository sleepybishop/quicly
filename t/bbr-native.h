/* Native per-path accounting and controller transition regressions. */
static void test_bbr_native(void)
{
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_bbr_init;
    quic_ctx.egress[0].cc.initcwnd_packets = 100;
    quic_ctx.egress[0].pacing = 1;
    quicly_conn_t *client, *server;
    health_setup(&client, &server);
    quicly_path_space_t *primary = client->path_spaces[0], *alternative = client->path_spaces[1];
    ok(primary->cc.type == &quicly_cc_type_bbr && alternative->cc.type == &quicly_cc_type_bbr);
    ok(primary->cc.state.bbr.engine.rst == &primary->cc.state.bbr.sampler.rst);
    ok(alternative->cc.state.bbr.engine.rst == &alternative->cc.state.bbr.sampler.rst);
    ok(primary->cc.state.bbr.engine.rst != alternative->cc.state.bbr.engine.rst);
    uint64_t alternate_delivered = alternative->cc.state.bbr.sampler.rst.delivered;
    uint64_t primary_delivered = primary->cc.state.bbr.sampler.rst.delivered;
    uint8_t payload[200000];
    memset(payload, 0x6a, sizeof(payload));
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(quicly_set_stream_path_affinity(stream, 0) == 0);
    ok(quicly_streambuf_egress_write(stream, payload, sizeof(payload)) == 0);
    quicly_stream_t *received = NULL;
    for (size_t i = 0; i < 5000; ++i) {
        ++quic_now;
        transmit_multipath(client, server);
        transmit_multipath(server, client);
        received = quicly_get_stream(server, stream->stream_id);
        if (received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(payload) &&
            primary->loss.sentmap.bytes_in_flight == 0)
            break;
    }
    ok(received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(payload));
    if (received != NULL && quicly_streambuf_ingress_get(received).len == sizeof(payload))
        ok(memcmp(quicly_streambuf_ingress_get(received).base, payload, sizeof(payload)) == 0);
    ok(primary->cc.state.bbr.sampler.rst.delivered > primary_delivered + sizeof(payload));
    ok(alternative->cc.state.bbr.sampler.rst.delivered < alternate_delivered + 4096);
    ok(primary->cc.state.bbr.engine.max_bw != 0);
    ok(primary->cc.state.bbr.sampler.rst.delivered == primary->bytes_acked);
    ok(primary->cc.state.bbr.stats.pacing_interval_m != 0);

    /* Classic ECN must reduce the model once per recovery flight. */
    primary->cc.cwnd = primary->cc.state.bbr.stats.cwnd = 20000;
    uint64_t next = primary->packet_number + 1;
    primary->cc.type->cc_on_lost(&primary->cc, &primary->loss, 0, next - 1, next, quic_now, primary->max_udp_payload_size);
    ok(primary->cc.cwnd == 14000);
    primary->cc.type->cc_on_lost(&primary->cc, &primary->loss, 0, next - 1, next, quic_now, primary->max_udp_payload_size);
    ok(primary->cc.cwnd == 14000);
    ok(primary->cc.num_ecn_loss_episodes == 1);

    /* Retain old BBR metadata while switching through an unrelated union. */
    ok(quicly_request_path_probe(client, 1) == 0);
    client->next_send_path_index = 1;
    transmit_multipath_with_loss(client, server, 20000);
    quicly_sentmap_iter_t old;
    quicly_sent_t *old_meta = NULL;
    quicly_sentmap_init_iter(&alternative->loss.sentmap, &old);
    while (quicly_sentmap_get(&old)->packet_number != UINT64_MAX) {
        old_meta = quicly_sentmap_find_frame(&old, on_ack_bbr_meta);
        if (old_meta != NULL && quicly_sentmap_get(&old)->ack_eliciting)
            break;
        quicly_sentmap_skip(&old);
    }
    ok(old_meta != NULL);
    uint32_t generation = alternative->bbr_generation;
    ok(quicly_set_cc(client, &quicly_cc_type_cubic) == 1);
    uint32_t initial_cwnd = alternative->cc.cwnd_initial;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
    ok(alternative->cc.cwnd_initial == initial_cwnd);
    ok(alternative->cc.state.bbr.engine.initial_cwnd == initial_cwnd);
    ok(alternative->bbr_generation != generation);
    ok(alternative->cc.state.bbr.engine.rst == &alternative->cc.state.bbr.sampler.rst);
    if (old_meta != NULL) {
        quicly_bbr_begin_ack(&alternative->cc, quic_now);
        ok(quicly_sentmap_update(&alternative->loss.sentmap, &old, QUICLY_SENTMAP_EVENT_ACKED) == 0);
        ok(alternative->cc.state.bbr.sampler.rst.delivered == 0);
    }
    uint32_t unchanged = alternative->bbr_generation;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
    ok(alternative->bbr_generation == unchanged);
    struct st_quicly_cc_type_t rejected = quicly_cc_type_cubic;
    rejected.name = "rejected";
    alternative->cc.type = &rejected;
    uint32_t primary_generation = primary->bbr_generation;
    ok(quicly_set_cc(client, &quicly_cc_type_cubic) == 0);
    ok(primary->cc.type == &quicly_cc_type_bbr);
    ok(primary->cc.state.bbr.engine.rst == &primary->cc.state.bbr.sampler.rst);
    ok(primary->bbr_generation == primary_generation);
    alternative->cc.type = &quicly_cc_type_bbr;
    quic_ctx.egress[0].ecn = QUICLY_ECN_MODE_L4S;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 0);
    quic_ctx.egress[0].ecn = saved.egress[0].ecn;
    ok(quicly_set_cc(client, &quicly_cc_type_cubic) == 1);
    /* A rejected later path rolls back earlier changes without retaining
     * engine pointers into the temporary backup array. */
    struct st_quicly_cc_type_t custom = quicly_cc_type_cubic;
    custom.name = "custom";
    alternative->cc.type = &custom;
    uint32_t old_cwnd = primary->cc.cwnd;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 0);
    ok(primary->cc.type == &quicly_cc_type_cubic && primary->cc.cwnd == old_cwnd);
    ok(alternative->cc.type == &custom);
    alternative->cc.type = &quicly_cc_type_cubic;
    quicly_pacer_t *pacer = primary->pacer;
    primary->pacer = NULL;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 0);
    primary->pacer = pacer;
    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx = saved;
    quic_now = saved_now;
}

static void test_bbr_switch_clock(void)
{
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quic_now = 10000;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_cubic_init;
    quic_ctx.egress[0].pacing = 1;
    quicly_conn_t *client, *server;
    health_setup(&client, &server);
    quicly_path_space_t *primary = client->path_spaces[0];

    /* An application call has no cached clock. Starting the model at zero would
     * immediately expire ProbeRTT on its first ACK at this clock value. */
    ok(client->stash.lock_count == 0 && isnan(client->stash.now_double));
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
    uint64_t switched_at = quicly_bbr_time(quic_now + quic_now_submillisec);
    for (size_t i = 0; i < PTLS_ELEMENTSOF(client->path_spaces); ++i)
        if (client->path_spaces[i] != NULL)
            ok(client->path_spaces[i]->cc.state.bbr.engine.probe_rtt_min_stamp == switched_at);
    ok(client->stash.lock_count == 0 && isnan(client->stash.now_double));

    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(quicly_set_stream_path_affinity(stream, 0) == 0);
    uint8_t payload[1000] = {0};
    ok(quicly_streambuf_egress_write(stream, payload, sizeof(payload)) == 0);
    for (size_t i = 0; i < 100 && primary->cc.state.bbr.sampler.rst.delivered == 0; ++i) {
        ++quic_now;
        transmit_multipath(client, server);
        transmit_multipath(server, client);
    }
    ok(primary->cc.state.bbr.sampler.rst.delivered != 0);
    ok(primary->cc.state.bbr.engine.state == QUICLY_BBR_BBR_STATE_STARTUP);
    ok(!primary->cc.state.bbr.engine.probe_rtt_expired);

    /* A switch from a protocol callback must retain its caller's clock lock. */
    ok(quicly_set_cc(client, &quicly_cc_type_cubic) == 1);
    lock_now(client, 0);
    double callback_time = client->stash.now_double;
    quic_now += 100;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
    ok(client->stash.lock_count == 1 && client->stash.now_double == callback_time);
    ok(primary->cc.state.bbr.engine.probe_rtt_min_stamp == quicly_bbr_time(callback_time));
    unlock_now(client);
    ok(client->stash.lock_count == 0 && isnan(client->stash.now_double));

    /* A later path rejecting the switch must leave both the model and the
     * caller's clock intact; no path has been configured at that point. */
    ok(quicly_set_cc(client, &quicly_cc_type_cubic) == 1);
    quicly_path_space_t *alternative = client->path_spaces[1];
    quicly_cc_type_t custom = quicly_cc_type_cubic;
    alternative->cc.type = &custom;
    uint32_t generation = primary->bbr_generation, cwnd = primary->cc.cwnd;
    lock_now(client, 0);
    callback_time = client->stash.now_double;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 0);
    ok(primary->cc.type == &quicly_cc_type_cubic && primary->cc.cwnd == cwnd);
    ok(primary->bbr_generation == generation && alternative->cc.type == &custom);
    ok(client->stash.lock_count == 1 && client->stash.now_double == callback_time);
    unlock_now(client);
    alternative->cc.type = &quicly_cc_type_cubic;

    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    quic_ctx = saved;
    quic_now = saved_now;
}

static void test_bbr_congestion_and_undo(void)
{
    quicly_cc_t cc;
    quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
    quicly_bbr_configure(&cc, 1200, 100, 1, 0);
    quicly_loss_t loss;
    uint16_t delay = 25;
    uint8_t exponent = 3;
    quicly_loss_init(&loss, &quic_ctx.egress[0].loss, 100, &delay, &exponent);
    loss.rtt.latest = loss.rtt.minimum = loss.rtt.smoothed = 100;
    loss.rtt.variance = 5;
    quicly_bbr_packet_t packets[2];
    uint32_t initial = cc.cwnd;
    ok(quicly_bbr_packet_sent(&cc, packets, 1000, 1000, 0, 0));
    ok(quicly_bbr_packet_sent(&cc, packets + 1, 1000, 2000, 1, 1000));
    loss.sentmap.bytes_in_flight = 2000;
    for (size_t i = 0; i < 2; ++i) {
        quicly_bbr_packet_lost(&cc, &packets[i].meta, i, i * 1000, (uint32_t)loss.sentmap.bytes_in_flight, 2000);
        cc.type->cc_on_lost(&cc, &loss, 1000, i, 2, 2000, 1200);
        loss.sentmap.bytes_in_flight -= 1000;
    }
    ok(cc.state.bbr.persistent_pending);
    quicly_bbr_begin_ack(&cc, 2000);
    cc.type->cc_on_acked(&cc, &loss, 0, 1, 0, 0, 2, 2000, 1200, NULL);
    ok(cc.state.bbr.persistent_events == 1);
    ok(cc.cwnd == 4800);
    quicly_bbr_begin_ack(&cc, 3000);
    quicly_bbr_packet_acked(&cc, packets, 0, 0, 3000);
    ok(cc.num_loss_episodes_undone == 0 && cc.cwnd == 4800);
    quicly_bbr_packet_acked(&cc, packets + 1, 1, 1000, 3000);
    ok(cc.num_loss_episodes_undone == 1 && cc.cwnd >= initial);
    quicly_bbr_packet_acked(&cc, packets + 1, 1, 1000, 3001);
    ok(cc.num_loss_episodes_undone == 1);
    quicly_loss_dispose(&loss);
}

static void test_bbr_idle_restart(void)
{
    quicly_cc_t cc;
    quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
    quicly_bbr_configure(&cc, 1200, 100, 1, 0);
    quicly_loss_t loss;
    uint16_t delay = 25;
    uint8_t exponent = 3;
    quicly_loss_init(&loss, &quic_ctx.egress[0].loss, 100, &delay, &exponent);
    loss.rtt.latest = loss.rtt.minimum = loss.rtt.smoothed = 100;
    quicly_cc_bbr_t *b = &cc.state.bbr;
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_CRUISE;
    b->engine.full_bw_reached = 1;
    b->engine.bw = b->engine.max_bw = 10000000;
    b->stats.pacing_interval_m = 1; /* obsolete probe pacing before the idle */
    quicly_bbr_set_app_limited(&cc, 0);
    quicly_bbr_packet_t packet;
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 1200, 0, 1000.5));
    /* Quicly calls cc_on_sent after committing the new packet. BBR's
     * on_pkt_sent must still see the pre-send empty flight to restart idle. */
    loss.sentmap.bytes_in_flight = 1200;
    cc.type->cc_on_sent(&cc, &loss, 1200, 1000);
    ok(b->engine.idle_restart);
    ok(b->engine.extra_acked_interval_start == quicly_bbr_time(1000.5));
    ok(quicly_bbr_pacing_rate(&cc) >= 9800 && quicly_bbr_pacing_rate(&cc) <= 10000);
    ok(b->stats.bytes_in_flight == 1200);

    /* An additional packet in the same flight is not another idle restart. */
    b->engine.idle_restart = 0;
    uint64_t restarted_at = b->engine.extra_acked_interval_start;
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 2400, 1, 1001.5));
    loss.sentmap.bytes_in_flight = 2400;
    cc.type->cc_on_sent(&cc, &loss, 1200, 1001);
    ok(!b->engine.idle_restart);
    ok(b->engine.extra_acked_interval_start == restarted_at);
    ok(b->stats.bytes_in_flight == 2400);

    /* An empty flight alone does not establish application idleness. */
    b->sampler.rst.app_limited = 0;
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 1200, 2, 2000.5));
    loss.sentmap.bytes_in_flight = 1200;
    cc.type->cc_on_sent(&cc, &loss, 1200, 2000);
    ok(!b->engine.idle_restart);

    /* If an idle completes ProbeRTT, the restored window must be visible
     * immediately to Quicly, rather than waiting for another ACK. */
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_RTT;
    b->engine.probe_rtt_done_stamp = quicly_bbr_time(2500);
    b->engine.prior_cwnd = 50000;
    cc.cwnd = b->stats.cwnd = 4800;
    quicly_bbr_set_app_limited(&cc, 0);
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 1200, 3, 3000.5));
    loss.sentmap.bytes_in_flight = 1200;
    cc.type->cc_on_sent(&cc, &loss, 1200, 3000);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_CRUISE);
    ok(cc.cwnd == 50000 && b->stats.cwnd == 50000);
    ok(b->stats.bytes_in_flight == 1200);
    quicly_loss_dispose(&loss);
}

static void test_bbr_blackout(void)
{
    quicly_context_t saved = quic_ctx;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_bbr_init;
    quic_ctx.egress[0].pacing = 1;
    test_multipath_automatic_failover_with_scheduler(&quicly_round_robin_path_scheduler);
    quic_ctx = saved;
}

static void test_bbr_configuration(void)
{
    quicly_context_t ctx = quic_ctx;
    ctx.egress[0].cc.init_cc = &quicly_cc_bbr_init;
    for (size_t i = 0; i != 2; ++i) {
        ctx.egress[0].pacing = i;
        ctx.egress[0].ecn = i == 0 ? QUICLY_ECN_MODE_CLASSIC : QUICLY_ECN_MODE_L4S;
        quicly_conn_t *conn = NULL;
        ok(quicly_connect(&conn, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL, NULL,
                          NULL) != 0);
        ok(conn == NULL);
    }
}
