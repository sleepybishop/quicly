/* native per-path accounting and controller transition regressions */
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

    /* classic ECN must reduce the model once per recovery flight and exit Startup/ProbeBW_UP */
    primary->cc.cwnd = primary->cc.state.bbr.stats.cwnd = 20000;
    primary->cc.state.bbr.engine.state = QUICLY_BBR_BBR_STATE_STARTUP;
    primary->cc.state.bbr.engine.full_bw_reached = 0;
    uint64_t next = primary->packet_number + 1;
    primary->cc.type->cc_on_lost(&primary->cc, &primary->loss, 0, next - 1, next, quic_now, primary->max_udp_payload_size);
    ok(primary->cc.cwnd == 14000 && primary->cc.state.bbr.engine.prior_cwnd == 14000);
    ok(primary->cc.state.bbr.engine.state == QUICLY_BBR_BBR_STATE_DRAIN && primary->cc.state.bbr.engine.full_bw_reached);
    primary->cc.type->cc_on_lost(&primary->cc, &primary->loss, 0, next - 1, next, quic_now, primary->max_udp_payload_size);
    ok(primary->cc.cwnd == 14000);
    ok(primary->cc.num_ecn_loss_episodes == 1);
    primary->cc.state.bbr.engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_UP;
    primary->cc.type->cc_on_lost(&primary->cc, &primary->loss, 0, next, next + 1, quic_now, primary->max_udp_payload_size);
    ok(primary->cc.state.bbr.engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_DOWN);
    ok(primary->cc.state.bbr.engine.prev_probe_too_high);

    /* retain old BBR metadata while switching through an unrelated union */
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
    /* switching from BBR to pico or cubic-legacy must preserve cc.conn */
    ok(quicly_set_cc(client, &quicly_cc_type_pico) == 1);
    ok(primary->cc.conn == client && alternative->cc.conn == client);
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
    ok(quicly_set_cc(client, &quicly_cc_type_cubic_legacy) == 1);
    ok(primary->cc.conn == client && alternative->cc.conn == client);
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
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
    /* a rejected later path rolls back earlier changes without retaining engine pointers into the backup array */
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

    /* application-limited stream and datagram sends must mark the final flight's sentmap snapshots */
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
    primary->cc.state.bbr.sampler.rst.app_limited = 0;
    uint8_t small_dg[64] = {0x42};
    ptls_iovec_t dg_vec = ptls_iovec_init(small_dg, sizeof(small_dg));
    quicly_send_datagram_frames_path(client, 0, &dg_vec, 1);
    client->next_send_path_index = 0;
    ++quic_now;
    transmit_multipath_with_loss(client, server, 20000);
    ok(primary->cc.state.bbr.sampler.rst.app_limited != 0);
    quicly_sentmap_iter_t dg_iter;
    quicly_sent_t *dg_meta = NULL;
    quicly_sentmap_init_iter(&primary->loss.sentmap, &dg_iter);
    while (quicly_sentmap_get(&dg_iter)->packet_number != UINT64_MAX) {
        if (quicly_sentmap_get(&dg_iter)->frames_in_flight)
            dg_meta = quicly_sentmap_find_frame(&dg_iter, on_ack_bbr_meta);
        quicly_sentmap_skip(&dg_iter);
    }
    ok(dg_meta != NULL && dg_meta->data.bbr_meta.app_limited == 1);

    /* RTT follows the largest newly ACKed packet even when that packet has no BBR delivery snapshot */
    ++quic_now;
    lock_now(client, 0);
    double data_sent_at = client->stash.now_double;
    uint64_t data_pn = primary->packet_number++;
    quicly_bbr_packet_t sample;
    ok(quicly_bbr_packet_sent(&primary->cc, &sample, 1200, (uint32_t)primary->loss.sentmap.bytes_in_flight + 1200,
                              data_pn, data_sent_at));
    ok(quicly_sentmap_prepare(&primary->loss.sentmap, data_pn, data_sent_at, QUICLY_EPOCH_1RTT) == 0);
    primary->loss.sentmap._pending_packet->data.packet.path_id = primary->path_id;
    quicly_sent_t *times = quicly_sentmap_allocate(&primary->loss.sentmap, on_ack_bbr_times);
    quicly_sent_t *meta = quicly_sentmap_allocate(&primary->loss.sentmap, on_ack_bbr_meta);
    ok(times != NULL && meta != NULL);
    times->data.bbr_times = sample.times;
    meta->data.bbr_meta = sample.meta;
    quicly_sentmap_commit(&primary->loss.sentmap, 1200, 0);
    primary->last_retransmittable_sent_at = data_sent_at;
    unlock_now(client);

    quic_now += 10;
    lock_now(client, 0);
    uint64_t ack_only_pn = primary->packet_number++;
    ok(quicly_sentmap_prepare(&primary->loss.sentmap, ack_only_pn, client->stash.now_double, QUICLY_EPOCH_1RTT) == 0);
    primary->loss.sentmap._pending_packet->data.packet.path_id = primary->path_id;
    quicly_sentmap_commit(&primary->loss.sentmap, 0, 0);
    unlock_now(client);

    quic_now += 10;
    lock_now(client, 0);
    primary->loss.rtt.latest = primary->loss.rtt.minimum = primary->loss.rtt.smoothed = 10;
    quicly_cc_bbr_t *b = &primary->cc.state.bbr;
    b->engine.min_rtt = b->engine.probe_rtt_min_delay = UINT64_MAX;
    uint64_t delivered_before = b->sampler.rst.delivered;
    quicly_ack_frame_t ack = {.largest_acknowledged = ack_only_pn, .smallest_acknowledged = data_pn, .ack_block_lengths = {2}};
    struct st_quicly_handle_payload_state_t ack_state = {.epoch = QUICLY_EPOCH_1RTT, .frame_type = QUICLY_FRAME_TYPE_ACK};
    ok(process_ack_frame_core(client, &ack_state, primary->path_id, &ack) == 0);
    ok(b->sampler.rst.delivered == delivered_before + 1200);
    ok(b->ack_largest_sent_at == quicly_bbr_time(data_sent_at));
    ok(b->ack_rtt == 10 * QUICLY_BBR_MILLISECONDS);
    ok(b->stats.latest_rtt == 10 * QUICLY_BBR_MILLISECONDS && b->engine.min_rtt == 10 * QUICLY_BBR_MILLISECONDS);
    unlock_now(client);

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

    /* an application call has no cached clock; starting at zero would expire ProbeRTT on the first ACK */
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

    /* a switch from a protocol callback must retain its caller's clock lock */
    ok(quicly_set_cc(client, &quicly_cc_type_cubic) == 1);
    lock_now(client, 0);
    double callback_time = client->stash.now_double;
    quic_now += 100;
    ok(quicly_set_cc(client, &quicly_cc_type_bbr) == 1);
    ok(client->stash.lock_count == 1 && client->stash.now_double == callback_time);
    ok(primary->cc.state.bbr.engine.probe_rtt_min_stamp == quicly_bbr_time(callback_time));
    unlock_now(client);
    ok(client->stash.lock_count == 0 && isnan(client->stash.now_double));

    /* a later path rejecting the switch must leave both the model and the caller's clock intact */
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

static quicly_sent_t *bbr_record_test_packet(quicly_path_space_t *ps, uint64_t pn, double sent_at, uint16_t bytes, int skipped)
{
    quicly_bbr_packet_t sample;
    if (bytes != 0)
        ok(quicly_bbr_packet_sent(&ps->cc, &sample, bytes, (uint32_t)ps->loss.sentmap.bytes_in_flight + bytes, pn, sent_at));
    ok(quicly_sentmap_prepare(&ps->loss.sentmap, pn, sent_at, QUICLY_EPOCH_1RTT) == 0);
    ps->loss.sentmap._pending_packet->data.packet.path_id = ps->path_id;
    quicly_sent_t *meta = NULL;
    if (bytes != 0) {
        quicly_sent_t *times = quicly_sentmap_allocate(&ps->loss.sentmap, on_ack_bbr_times);
        meta = quicly_sentmap_allocate(&ps->loss.sentmap, on_ack_bbr_meta);
        ok(times != NULL && meta != NULL);
        times->data.bbr_times = sample.times;
        meta->data.bbr_meta = sample.meta;
    } else if (skipped) {
        ok(quicly_sentmap_allocate(&ps->loss.sentmap, on_invalid_ack) != NULL);
    }
    quicly_sentmap_commit(&ps->loss.sentmap, bytes, 0);
    ps->packet_number = pn + 1;
    return meta;
}

static void bbr_lose_test_packet(quicly_path_space_t *ps, uint64_t pn, double now)
{
    quicly_sentmap_iter_t iter;
    quicly_sentmap_init_iter(&ps->loss.sentmap, &iter);
    while (quicly_sentmap_get(&iter)->packet_number < pn)
        quicly_sentmap_skip(&iter);
    const quicly_sent_packet_t *packet = quicly_sentmap_get(&iter);
    ok(packet->packet_number == pn && packet->cc_bytes_in_flight != 0);
    quicly_sent_t *meta = quicly_sentmap_find_frame(&iter, on_ack_bbr_meta);
    ok(meta != NULL);
    quicly_bbr_packet_lost(&ps->cc, &meta->data.bbr_meta, pn, packet->sent_at,
                           (uint32_t)ps->loss.sentmap.bytes_in_flight, now);
    ps->cc.type->cc_on_lost(&ps->cc, &ps->loss, packet->cc_bytes_in_flight, pn, ps->packet_number, now, 1200);
    ok(quicly_sentmap_update(&ps->loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_LOST) == 0);
}

static void bbr_ack_test_packet(quicly_path_space_t *ps, uint64_t pn, double now)
{
    quicly_sentmap_iter_t iter;
    quicly_sentmap_init_iter(&ps->loss.sentmap, &iter);
    while (quicly_sentmap_get(&iter)->packet_number < pn)
        quicly_sentmap_skip(&iter);
    ok(quicly_sentmap_get(&iter)->packet_number == pn);
    ps->conn->stash.now_double = now;
    quicly_bbr_begin_ack(&ps->cc, now);
    quicly_bbr_acknowledge_packet(&ps->cc, pn);
    ok(quicly_sentmap_update(&ps->loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);
}

static void test_bbr_congestion_and_undo(void)
{
    quicly_path_space_t ps = {0};
    quicly_cc_t *cc = &ps.cc;
    quicly_loss_t *loss = &ps.loss;
    quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, cc, &conf, 1200, 0);
    quicly_bbr_configure(cc, 1200, 100, 1, 0);
    uint16_t delay = 25;
    uint8_t exponent = 3;
    quicly_loss_init(loss, &quic_ctx.egress[0].loss, 100, &delay, &exponent);
    loss->rtt.latest = loss->rtt.minimum = loss->rtt.smoothed = 100;
    loss->rtt.variance = 5;
    cc->state.bbr.stats.first_rtt_sample_ts = 0;
    uint32_t initial = cc->cwnd;
    quicly_sent_t *meta[2];
    meta[0] = bbr_record_test_packet(&ps, 0, 0, 1000, 0);
    meta[1] = bbr_record_test_packet(&ps, 1, 1000, 1000, 0);
    bbr_lose_test_packet(&ps, 0, 2000);
    bbr_lose_test_packet(&ps, 1, 2000);
    check_bbr_persistent_congestion(&ps);
    ok(cc->state.bbr.persistent_pending);
    quicly_bbr_begin_ack(cc, 2000);
    cc->type->cc_on_acked(cc, loss, 0, 1, 0, 0, 2, 2000, 1200, NULL);
    ok(cc->state.bbr.persistent_events == 1);
    ok(cc->cwnd == 4800);
    quicly_bbr_packet_t packets[2] = {{.times = {0, 0, 0}, .meta = meta[0]->data.bbr_meta},
                                      {.times = {0, 0, 0}, .meta = meta[1]->data.bbr_meta}};
    quicly_bbr_begin_ack(cc, 3000);
    quicly_bbr_packet_acked(cc, packets, 0, 0, 3000);
    ok(cc->num_loss_episodes_undone == 0 && cc->cwnd == 4800);
    quicly_bbr_packet_acked(cc, packets + 1, 1, 1000, 3000);
    ok(cc->num_loss_episodes_undone == 1 && cc->cwnd >= initial);
    quicly_bbr_packet_acked(cc, packets + 1, 1, 1000, 3001);
    ok(cc->num_loss_episodes_undone == 1);
    quicly_loss_dispose(loss);
}

static void bbr_test_detected_loss(quicly_loss_t *loss, const quicly_sent_packet_t *packet, int is_time_threshold)
{
    (void)is_time_threshold;
    quicly_path_space_t *ps = (void *)((char *)loss - offsetof(quicly_path_space_t, loss));
    quicly_sent_t *meta = quicly_sentmap_find_frame(loss->on_loss_iter, on_ack_bbr_meta);
    ok(meta != NULL);
    quicly_bbr_packet_lost(&ps->cc, &meta->data.bbr_meta, packet->packet_number, packet->sent_at,
                           (uint32_t)loss->sentmap.bytes_in_flight, ps->conn->stash.now_double);
    ps->cc.type->cc_on_lost(&ps->cc, loss, packet->cc_bytes_in_flight, packet->packet_number, ps->packet_number,
                            (int64_t)ps->conn->stash.now_double, 1200);
}

static void test_bbr_persistent_expiration(void)
{
    quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    uint16_t delay = 25;
    uint8_t exponent = 3;
    for (int scenario = 0; scenario != 6; ++scenario) {
        quicly_conn_t conn = {0};
        quicly_path_space_t ps = {.conn = &conn};
        quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &ps.cc, &conf, 1200, 0);
        quicly_bbr_configure(&ps.cc, 1200, 100, 1, 0);
        quicly_loss_init(&ps.loss, &quic_ctx.egress[0].loss, 100, &delay, &exponent);
        ps.loss.before_expire = before_sentmap_expire;
        ps.loss.rtt.latest = ps.loss.rtt.minimum = ps.loss.rtt.smoothed = 100;
        ps.loss.rtt.variance = 5;
        ps.cc.state.bbr.stats.first_rtt_sample_ts = 0;
        if (scenario < 2) {
            /* an expired unacknowledged ACK-only packet bridges the run, whereas an ACKed one splits it */
            bbr_record_test_packet(&ps, 0, 1, 1000, 0);
            bbr_record_test_packet(&ps, 1, 250, 0, 0);
            bbr_record_test_packet(&ps, 2, 500, 1000, 0);
            for (uint64_t pn = 3; pn != 40; ++pn)
                bbr_record_test_packet(&ps, pn, 800, 1000, 0);
            if (scenario == 1)
                bbr_ack_test_packet(&ps, 1, 850);
            conn.stash.now_double = 900;
            ps.loss.largest_acked_packet_plus1.all_ = ps.loss.largest_acked_packet_plus1.per_epoch[QUICLY_EPOCH_1RTT] = 4;
            ok(quicly_loss_detect_loss(&ps.loss, 900, delay, 1, bbr_test_detected_loss) == 0);
            check_bbr_persistent_congestion(&ps);
            ok(ps.cc.state.bbr.persistent_pending == (scenario == 0));
        } else if (scenario < 4) {
            /* the second cleanup pass while initial/handshake remain active must not erase a newly detected loss batch */
            for (uint64_t pn = 0; pn != 40; ++pn)
                bbr_record_test_packet(&ps, pn, pn == 0 ? 0 : 1000 + pn, 1000, 0);
            conn.stash.now_double = 2000;
            ps.loss.largest_acked_packet_plus1.all_ = ps.loss.largest_acked_packet_plus1.per_epoch[QUICLY_EPOCH_1RTT] = 42;
            ok(quicly_loss_detect_loss(&ps.loss, 2000, delay, scenario == 3, bbr_test_detected_loss) == 0);
            check_bbr_persistent_congestion(&ps);
            ok(ps.cc.state.bbr.persistent_pending);
            ok(ps.loss.sentmap.num_packets == (scenario == 2 ? 31 : 40));
        } else {
            /* preserve a safe expiration prefix, including when it reaches the tail before another packet is sent */
            bbr_record_test_packet(&ps, 0, 0, 1000, 0);
            bbr_record_test_packet(&ps, 1, 100, 0, 0);
            if (scenario == 4)
                bbr_record_test_packet(&ps, 2, 1000, 1000, 0);
            bbr_lose_test_packet(&ps, 0, 1100);
            check_bbr_persistent_congestion(&ps);
            quicly_sentmap_iter_t iter;
            quicly_sentmap_init_iter(&ps.loss.sentmap, &iter);
            ok(quicly_sentmap_update(&ps.loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_EXPIRED) == 0);
            ok(quicly_sentmap_update(&ps.loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_EXPIRED) == 0);
            if (scenario == 5)
                bbr_record_test_packet(&ps, 2, 1200, 1000, 0);
            bbr_lose_test_packet(&ps, 2, 1300);
            check_bbr_persistent_congestion(&ps);
            ok(ps.cc.state.bbr.persistent_pending);
        }
        quicly_loss_dispose(&ps.loss);
    }
}

static void test_bbr_persistent_congestion(void)
{
    test_bbr_persistent_expiration();
    enum { SKIPPED, ACK_ONLY, ACKED_ACK_ONLY, MISSING, UNRESOLVED, OLD_GENERATION, ACKED_DATA };
    for (int kind = SKIPPED; kind <= ACKED_DATA; ++kind) {
        quicly_conn_t conn = {0};
        quicly_path_space_t ps = {.conn = &conn};
        quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
        quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &ps.cc, &conf, 1200, 0);
        quicly_bbr_configure(&ps.cc, 1200, 100, 1, 0);
        uint16_t delay = 25;
        uint8_t exponent = 3;
        quicly_loss_init(&ps.loss, &quic_ctx.egress[0].loss, 100, &delay, &exponent);
        ps.loss.rtt.latest = ps.loss.rtt.minimum = ps.loss.rtt.smoothed = 100;
        ps.loss.rtt.variance = 5;
        ps.cc.state.bbr.stats.first_rtt_sample_ts = 0;
        bbr_record_test_packet(&ps, 0, 0, 1000, 0);
        quicly_sent_t *middle = NULL;
        if (kind != MISSING)
            middle = bbr_record_test_packet(&ps, 1, 500, kind >= UNRESOLVED ? 1000 : 0, kind == SKIPPED);
        bbr_record_test_packet(&ps, 2, 1000, 1000, 0);
        if (kind == ACKED_ACK_ONLY || kind == ACKED_DATA) {
            bbr_ack_test_packet(&ps, 1, 1500);
        } else if (kind == OLD_GENERATION) {
            bbr_lose_test_packet(&ps, 1, 1500);
            --middle->data.bbr_meta.generation;
        }
        bbr_lose_test_packet(&ps, 0, 2000);
        check_bbr_persistent_congestion(&ps);
        bbr_lose_test_packet(&ps, 2, 2000);
        check_bbr_persistent_congestion(&ps);
        int persistent = kind == SKIPPED || kind == ACK_ONLY;
        ok(ps.cc.state.bbr.persistent_pending == persistent);
        quicly_bbr_apply_persistent_congestion(&ps.cc);
        ok(ps.cc.state.bbr.persistent_events == persistent);
        if (kind == UNRESOLVED) {
            /* different ACK epochs can leave an unresolved packet between already-lost packets */
            bbr_lose_test_packet(&ps, 1, 2100);
            check_bbr_persistent_congestion(&ps);
            ok(ps.cc.state.bbr.persistent_pending);
            quicly_bbr_apply_persistent_congestion(&ps.cc);
            ok(ps.cc.state.bbr.persistent_events == 1);
            /* replaying the same retained evidence must not notify twice */
            ps.cc.state.bbr.loss_scan_first_pn = 0;
            ps.cc.state.bbr.loss_scan_last_pn = 2;
            check_bbr_persistent_congestion(&ps);
            ok(!ps.cc.state.bbr.persistent_pending);
        }
        if (kind == ACK_ONLY || kind == UNRESOLVED) {
            /* a late ACK splits the run so the retained suffix plus a later loss can form a fresh interval */
            bbr_ack_test_packet(&ps, 1, 2200);
            check_bbr_persistent_congestion(&ps);
            ok(ps.cc.state.bbr.loss_run_valid && ps.cc.state.bbr.loss_first_pn == 2);
            ok(!ps.cc.state.bbr.persistent_notified);
            bbr_record_test_packet(&ps, 3, 2300, 1000, 0);
            bbr_lose_test_packet(&ps, 3, 2400);
            check_bbr_persistent_congestion(&ps);
            ok(ps.cc.state.bbr.persistent_pending);
            quicly_bbr_apply_persistent_congestion(&ps.cc);
            ok(ps.cc.state.bbr.persistent_events == 2);
        }
        quicly_loss_dispose(&ps.loss);
    }

    /* exercise ACK-only success through the native ACK path */
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_bbr_init;
    quic_ctx.egress[0].cc.initcwnd_packets = 100;
    quic_ctx.egress[0].pacing = 1;
    for (int ack_middle = 0; ack_middle != 2; ++ack_middle) {
        quicly_conn_t *client, *server;
        health_setup(&client, &server);
        quicly_path_space_t *ps = client->path_spaces[0];
        uint64_t pn = ps->packet_number, events = ps->cc.state.bbr.persistent_events;
        double sent_at = quic_now;
        bbr_record_test_packet(ps, pn, sent_at, 1000, 0);
        bbr_record_test_packet(ps, pn + 1, sent_at + 500, 0, 0);
        bbr_record_test_packet(ps, pn + 2, sent_at + 1000, 1000, 0);
        bbr_record_test_packet(ps, pn + 3, sent_at + 1900, 0, 0);
        ps->last_retransmittable_sent_at = sent_at + 1000;
        ps->loss.rtt.latest = ps->loss.rtt.minimum = ps->loss.rtt.smoothed = 100;
        ps->loss.rtt.variance = 5;
        quic_now += 2000;
        lock_now(client, 0);
        quicly_ack_frame_t ack = {.largest_acknowledged = pn + 3,
                                   .smallest_acknowledged = pn + (ack_middle ? 1 : 3),
                                   .ack_block_lengths = {1, 1},
                                   .gaps = {1},
                                   .num_gaps = ack_middle};
        struct st_quicly_handle_payload_state_t state = {.epoch = QUICLY_EPOCH_1RTT, .frame_type = QUICLY_FRAME_TYPE_ACK};
        ok(process_ack_frame_core(client, &state, ps->path_id, &ack) == 0);
        ok(ps->cc.state.bbr.persistent_events == events + !ack_middle);
        if (!ack_middle) {
            ack = (quicly_ack_frame_t){.largest_acknowledged = pn + 1, .smallest_acknowledged = pn + 1,
                                       .ack_block_lengths = {1}};
            ok(process_ack_frame_core(client, &state, ps->path_id, &ack) == 0);
            ok(ps->cc.state.bbr.loss_run_valid && ps->cc.state.bbr.loss_first_pn == pn + 2);
            ok(!ps->cc.state.bbr.persistent_notified);
        }
        unlock_now(client);
        quicly_free(client);
        quicly_free(server);
        quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    }
    quic_ctx = saved;
    quic_now = saved_now;
}

struct st_bbr_idle_switch_scheduler_t {
    quicly_stream_scheduler_t super;
    int called, switch_back;
};

static quicly_error_t bbr_switch_during_idle_send(quicly_stream_scheduler_t *self, quicly_conn_t *conn, quicly_send_context_t *s)
{
    (void)s;
    struct st_bbr_idle_switch_scheduler_t *sched = (void *)self;
    if (!sched->called++) {
        ok(quicly_set_cc(conn, &quicly_cc_type_cubic));
        if (sched->switch_back)
            ok(quicly_set_cc(conn, &quicly_cc_type_bbr));
    }
    return 0;
}

static void test_bbr_idle_switch(void)
{
    for (int switch_back = 0; switch_back != 2; ++switch_back) {
        quicly_conn_t *client, *server;
        health_setup(&client, &server);
        quicly_path_space_t *ps = client->path_spaces[0];
        ok(ps->cc.type == &quicly_cc_type_bbr && ps->loss.sentmap.bytes_in_flight == 0);
        quicly_bbr_set_app_limited(&ps->cc, 0);
        uint32_t generation = ps->bbr_generation;
        quicly_stream_t *stream;
        ok(quicly_open_stream(client, &stream, 0) == 0);
        ok(quicly_set_stream_path_affinity(stream, 0) == 0);
        ok(quicly_streambuf_egress_write(stream, "pending", 7) == 0);
        quicly_stream_scheduler_t *original = quic_ctx.stream_scheduler;
        struct st_bbr_idle_switch_scheduler_t sched = {.super = *original, .switch_back = switch_back};
        sched.super.do_send = bbr_switch_during_idle_send;
        quic_ctx.stream_scheduler = &sched.super;
        quicly_address_t dest, src;
        struct iovec dgrams[10];
        uint8_t dgram_buf[15000];
        size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
        ok(quicly_send(client, &dest, &src, dgrams, &num_dgrams, dgram_buf, sizeof(dgram_buf)) == 0);
        ok(sched.called != 0 && num_dgrams == 0);
        for (size_t i = 0; i != PTLS_ELEMENTSOF(client->path_spaces); ++i) {
            quicly_path_space_t *current = client->path_spaces[i];
            if (current == NULL)
                continue;
            ok(current->cc.type == (switch_back ? &quicly_cc_type_bbr : &quicly_cc_type_cubic));
            if (switch_back) {
                ok(current->cc.state.bbr.sampler.generation == current->bbr_generation);
                ok(current->cc.state.bbr.engine.rst == &current->cc.state.bbr.sampler.rst);
            }
        }
        if (switch_back)
            ok(ps->bbr_generation != generation);
        quic_ctx.stream_scheduler = original;
        quicly_free(client);
        quicly_free(server);
        quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    }
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
    /* quicly calls cc_on_sent after committing the new packet; on_pkt_sent must still see the pre-send empty flight */
    loss.sentmap.bytes_in_flight = 1200;
    cc.type->cc_on_sent(&cc, &loss, 1200, 1000);
    ok(b->engine.idle_restart);
    ok(b->engine.extra_acked_interval_start == quicly_bbr_time(1000.5));
    ok(quicly_bbr_pacing_rate(&cc) >= 9800 && quicly_bbr_pacing_rate(&cc) <= 10000);
    ok(b->stats.bytes_in_flight == 1200);

    /* an additional packet in the same flight is not another idle restart */
    b->engine.idle_restart = 0;
    uint64_t restarted_at = b->engine.extra_acked_interval_start;
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 2400, 1, 1001.5));
    loss.sentmap.bytes_in_flight = 2400;
    cc.type->cc_on_sent(&cc, &loss, 1200, 1001);
    ok(!b->engine.idle_restart);
    ok(b->engine.extra_acked_interval_start == restarted_at);
    ok(b->stats.bytes_in_flight == 2400);

    /* an empty flight alone does not establish application idleness */
    b->sampler.rst.app_limited = 0;
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 1200, 2, 2000.5));
    loss.sentmap.bytes_in_flight = 1200;
    cc.type->cc_on_sent(&cc, &loss, 1200, 2000);
    ok(!b->engine.idle_restart);

    /* if an idle completes probe_rtt, the restored window must be visible immediately */
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_RTT;
    b->engine.probe_rtt_done_stamp = quicly_bbr_time(2500);
    b->engine.prior_cwnd = 50000;
    b->engine.extra_acked_delivered = 9999;
    cc.cwnd = b->stats.cwnd = 4800;
    quicly_bbr_set_app_limited(&cc, 0);
    ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 1200, 3, 3000.5));
    loss.sentmap.bytes_in_flight = 1200;
    cc.type->cc_on_sent(&cc, &loss, 1200, 3000);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_CRUISE);
    ok(b->engine.extra_acked_delivered == 0);
    ok(cc.cwnd == 50000 && b->stats.cwnd == 50000);
    ok(b->stats.bytes_in_flight == 1200);

    /* idle restart in probe_rtt with unarmed done_stamp arms the timer */
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_RTT;
    b->engine.probe_rtt_done_stamp = UINT64_MAX;
    b->engine.min_rtt = 100 * QUICLY_BBR_MILLISECONDS;
    cc.cwnd = b->stats.cwnd = 4800;
    loss.sentmap.bytes_in_flight = 0;
    quicly_bbr_set_app_limited(&cc, 0);
    quicly_bbr_restart_from_idle(&cc, &loss, 1200, 4000.0);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_RTT);
    ok(b->engine.probe_rtt_done_stamp == quicly_bbr_time(4200.0));
    quicly_loss_dispose(&loss);

    /* do_send must restore probe_rtt cwnd before computing send_window, while ACK-only do_send rolls back */
    quicly_context_t saved = quic_ctx;
    int64_t saved_now = quic_now;
    quic_ctx.egress[0].cc.init_cc = &quicly_cc_bbr_init;
    quic_ctx.egress[0].cc.initcwnd_packets = 100;
    quic_ctx.egress[0].pacing = 1;
    quicly_conn_t *client, *server;
    health_setup(&client, &server);
    quicly_path_space_t *primary = client->path_spaces[0];
    quicly_cc_bbr_t *pb = &primary->cc.state.bbr;
    pb->engine.state = QUICLY_BBR_BBR_STATE_PROBE_RTT;
    pb->engine.full_bw_reached = 1;
    pb->engine.bw = pb->engine.max_bw = 10000000;
    pb->engine.min_rtt = 10 * QUICLY_BBR_MILLISECONDS;
    pb->engine.prior_cwnd = 60000;
    primary->cc.cwnd = pb->stats.cwnd = 4800;
    quic_now += 1000;
    pb->engine.probe_rtt_done_stamp = quicly_bbr_time(quic_now - 10);
    quicly_bbr_set_app_limited(&primary->cc, 0);
    /* no-op send (with empty flight and nothing queued) must roll back the tentative idle restart */
    quicly_address_t dest, src;
    struct iovec dgrams[10];
    uint8_t dgram_buf[15000];
    size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
    ok(quicly_send(client, &dest, &src, dgrams, &num_dgrams, dgram_buf, sizeof(dgram_buf)) == 0);
    ok(num_dgrams == 0);
    ok(pb->engine.state == QUICLY_BBR_BBR_STATE_PROBE_RTT);
    ok(primary->cc.cwnd == 4800);
    /* now write 10000 bytes (> 4800 probe_rtt cwnd) and verify a single quicly_send sends the full flight */
    quicly_stream_t *stream;
    ok(quicly_open_stream(client, &stream, 0) == 0);
    ok(quicly_set_stream_path_affinity(stream, 0) == 0);
    uint8_t burst[10000];
    memset(burst, 0x5a, sizeof(burst));
    ok(quicly_streambuf_egress_write(stream, burst, sizeof(burst)) == 0);
    num_dgrams = PTLS_ELEMENTSOF(dgrams);
    ok(quicly_send(client, &dest, &src, dgrams, &num_dgrams, dgram_buf, sizeof(dgram_buf)) == 0);
    ok(pb->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_CRUISE);
    ok(primary->cc.cwnd == 60000);
    ok(primary->loss.sentmap.bytes_in_flight > 4800);
    quicly_free(client);
    quicly_free(server);
    quicly_free_default_cid_encryptor(quic_ctx.cid_encryptor);
    test_bbr_idle_switch();
    quic_ctx = saved;
    quic_now = saved_now;
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
