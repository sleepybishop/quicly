#include "test.h"
#include "quicly/cc-bbr-sampler.h"
#define MS QUICLY_BBR_MILLISECONDS

static void test_compression_and_ack_order(void)
{
    quicly_bbr_sampler_t s;
    quicly_bbr_packet_t p[3];
    quicly_bbr_conn_stat stats = {.min_rtt = MS};
    quicly_bbr_sampler_init(&s, 7);
    ok(quicly_bbr_sampler_on_sent(&s, p, 1000, 1000, 0, 0));
    ok(quicly_bbr_sampler_on_sent(&s, p + 1, 1000, 2000, 1, MS));
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, p, 0, 0, 100 * MS));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(stats.delivery_rate_sec == 10000);
    /* earlier flight still has a packet in flight; compressed ACKs must not report ACK spacing as network capacity */
    ok(quicly_bbr_sampler_on_sent(&s, p + 2, 1000, 2000, 2, 150 * MS));
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, p + 2, 2, 150 * MS, 151 * MS));
    /* an older packet in the same ACK cannot replace the newest snapshot */
    ok(quicly_bbr_sampler_on_ack(&s, p + 1, 1, MS, 151 * MS));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(s.rst.rs.send_elapsed == 150 * MS);
    ok(s.rst.rs.ack_elapsed == 51 * MS);
    ok(s.rst.rs.last_acked_pkt_id == 2);
    ok(stats.delivery_rate_sec == 2000 * QUICLY_BBR_SECONDS / (150 * MS));
    ok(s.rst.delivered == 3000);
    ok(!quicly_bbr_sampler_on_ack(&s, p + 2, 2, 150 * MS, 152 * MS));
    ok(s.rst.delivered == 3000);
}

static void test_loss_late_ack_and_generation(void)
{
    quicly_bbr_sampler_t s;
    quicly_bbr_packet_t p[2];
    quicly_bbr_conn_stat stats = {.min_rtt = MS};
    quicly_bbr_sampler_init(&s, 1);
    ok(quicly_bbr_sampler_on_sent(&s, p, 1000, 1000, 0, MS));
    ok(quicly_bbr_sampler_on_lost(&s, &p->meta));
    ok(!quicly_bbr_sampler_on_lost(&s, &p->meta));
    ok(s.rst.lost == 1000);
    /* a late ACK still supplies delivery evidence, exactly once */
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, p, 0, MS, 101 * MS));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(s.rst.delivered == 1000 && s.rst.rs.lost == 1000);
    ok(!quicly_bbr_sampler_on_lost(&s, &p->meta));
    ok(quicly_bbr_sampler_on_sent(&s, p + 1, 1000, 1000, 1, 102 * MS));
    quicly_bbr_sampler_init(&s, 2);
    ok(!quicly_bbr_sampler_on_ack(&s, p + 1, 1, 102 * MS, 202 * MS));
    ok(!quicly_bbr_sampler_on_lost(&s, &p[1].meta));
    ok(s.rst.delivered == 0 && s.rst.lost == 0);
}

static void test_loss_discovered_during_ack(void)
{
    quicly_bbr_sampler_t s;
    quicly_bbr_packet_t p[2];
    quicly_bbr_conn_stat stats = {.min_rtt = MS};
    quicly_bbr_sampler_init(&s, 1);
    ok(quicly_bbr_sampler_on_sent(&s, p, 1000, 1000, 0, 0));
    ok(quicly_bbr_sampler_on_sent(&s, p + 1, 1000, 2000, 1, MS));
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, p + 1, 1, MS, 101 * MS));
    /* include losses discovered during ACK processing in this rate sample */
    ok(quicly_bbr_sampler_on_lost(&s, &p[0].meta));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(s.rst.rs.lost == 1000 && s.rst.rs.tx_in_flight == 2000);
    quicly_bbr_sampler_app_limited(&s, 1000);
    ok(s.rst.app_limited == 2000);
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, p, 0, 0, 201 * MS));
    ok(s.rst.app_limited == 2000); /* marker equality is still limited */
}

static void test_idle_and_application_limit(void)
{
    quicly_bbr_sampler_t s;
    quicly_bbr_packet_t p;
    quicly_bbr_conn_stat stats = {.min_rtt = 100 * MS};
    quicly_bbr_sampler_init(&s, 0);
    quicly_bbr_sampler_app_limited(&s, 0);
    ok(s.rst.app_limited == 1);
    ok(quicly_bbr_sampler_on_sent(&s, &p, 1000, 1000, 0, MS));
    ok(p.meta.app_limited);
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, &p, 0, MS, 101 * MS));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(s.rst.rs.is_app_limited && s.rst.app_limited == 0);
    /* a long idle period must not enter the next delivery interval */
    ok(quicly_bbr_sampler_on_sent(&s, &p, 1000, 1000, 1, 10000 * MS));
    ok(p.times.first_sent_at == 10000 * MS && p.times.delivered_at == 10000 * MS);
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, &p, 1, 10000 * MS, 10100 * MS));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(stats.delivery_rate_sec == 10000);
    quicly_bbr_sampler_begin_ack(&s);
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(stats.delivery_rate_sec == 0);
}

static void test_invalid_time_and_wide_arithmetic(void)
{
    quicly_bbr_sampler_t s;
    quicly_bbr_packet_t p;
    quicly_bbr_conn_stat stats = {.min_rtt = MS};
    quicly_bbr_sampler_init(&s, 1);
    ok(!quicly_bbr_sampler_on_sent(&s, &p, 0, 1, 0, MS));
    ok(!quicly_bbr_sampler_on_sent(&s, &p, 1000, 999, 0, MS));
    ok(quicly_bbr_sampler_on_sent(&s, &p, 1000, 1000, 0, MS));
    ok(!quicly_bbr_sampler_on_ack(&s, &p, 0, MS, 0));
    ok(!quicly_bbr_sampler_on_sent(&s, &p, 1000, 1000, 1, 0));
    ok(s.rst.delivered == 0 && s.rst.first_sent_ts == MS);
    ok(quicly_bbr_sampler_on_ack(&s, &p, 0, MS, MS));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(stats.delivery_rate_sec == 0); /* sub-min-RTT sample rejected */
    quicly_bbr_sampler_init(&s, 1);
    s.rst.delivered = UINT64_C(1) << 50;
    ok(quicly_bbr_sampler_on_sent(&s, &p, 1000, 1000, 0, MS));
    s.rst.delivered += UINT64_C(1) << 50;
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, &p, 0, MS, MS + QUICLY_BBR_SECONDS));
    quicly_bbr_sampler_finish_ack(&s, &stats);
    ok(stats.delivery_rate_sec == (UINT64_C(1) << 50) + 1000);
}

static void test_switch_with_inflight_packets(void)
{
    quicly_bbr_sampler_t sampler;
    quicly_bbr_packet_t packet;
    quicly_bbr_conn_stat stats = {.min_rtt = 100 * MS};
    quicly_bbr_sampler_init(&sampler, 2);
    ok(quicly_bbr_sampler_on_sent(&sampler, &packet, 1000, 5000, 20, 10000 * MS));
    ok(packet.times.first_sent_at == 10000 * MS && packet.times.delivered_at == 10000 * MS);
    quicly_bbr_sampler_begin_ack(&sampler);
    ok(quicly_bbr_sampler_on_ack(&sampler, &packet, 20, 10000 * MS, 10100 * MS));
    quicly_bbr_sampler_finish_ack(&sampler, &stats);
    ok(stats.delivery_rate_sec == 10000);
}

static void test_engine_initialization_and_persistent_congestion(void)
{
    quicly_bbr_sampler_t sampler;
    quicly_bbr_cc_bbr engine;
    quicly_bbr_pcg32 random;
    quicly_bbr_conn_stat stats = {.cwnd = 120000,
                                  .max_tx_udp_payload_size = 1200,
                                  .min_rtt = 100 * MS,
                                  .smoothed_rtt = 100 * MS,
                                  .first_rtt_sample_ts = 1,
                                  .congestion_recovery_start_ts = UINT64_MAX};
    quicly_bbr_sampler_init(&sampler, 1);
    quicly_bbr_pcg32_init(&random, 12345);
    quicly_bbr_cc_bbr_init(&engine, NULL, &stats, &sampler.rst, 1, &random);
    ok(engine.state == QUICLY_BBR_BBR_STATE_STARTUP && stats.pacing_interval_m > 0);
    stats.bytes_in_flight = 2400;
    engine.cc.on_persistent_congestion(&engine.cc, &stats, 200 * MS);
    ok(stats.cwnd == 4800 && !engine.in_loss_recovery);
}

static void test_loss_undo_preserves_bandwidth_plateau(void)
{
    for (int probe_bw = 0; probe_bw != 2; ++probe_bw) {
        quicly_bbr_rst rst = {0};
        quicly_bbr_cc_bbr engine;
        quicly_bbr_pcg32 random;
        quicly_bbr_conn_stat stats = {.cwnd = 120000,
                                      .max_tx_udp_payload_size = 1200,
                                      .smoothed_rtt = 100 * MS,
                                      .min_rtt = 100 * MS,
                                      .congestion_recovery_start_ts = UINT64_MAX,
                                      .delivery_rate_sec = 1000000};
        quicly_bbr_pcg32_init(&random, 1);
        quicly_bbr_cc_bbr_init(&engine, NULL, &stats, &rst, 0, &random);
        if (probe_bw) {
            engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_UP;
            engine.full_bw_reached = engine.is_bw_probe_sample = 1;
            engine.pacing_gain_h = 125;
            engine.cwnd_gain_h = 225;
        }
        /* a single loss below the loss threshold must not undo an independently observed bandwidth plateau */
        for (size_t round = 0; round != 4; ++round) {
            if (round == 3) {
                quicly_bbr_cc_pkt packet = {.pkt_num = 100, .pktlen = 1200, .sent_ts = 250 * MS, .tx_in_flight = 120000};
                rst.lost = packet.pktlen;
                engine.cc.on_pkt_lost(&engine.cc, &stats, &packet, 399 * MS);
                ok(engine.undo_state == QUICLY_BBR_BBR_STATE_NONE);
            }
            uint64_t prior = rst.delivered;
            rst.delivered += 100000;
            rst.rs = (quicly_bbr_rs){.prior_delivered = prior,
                                     .delivered = 100000,
                                     .tx_in_flight = 120000,
                                     .lost = rst.lost};
            quicly_bbr_cc_ack ack = {.bytes_delivered = 100000,
                                     .bytes_lost = round == 3 ? 1200 : 0,
                                     .pkt_delivered = prior,
                                     .largest_pkt_sent_ts = (round * 100 + 1) * MS,
                                     .rtt = 100 * MS};
            engine.cc.on_ack_recv(&engine.cc, &stats, &ack, (round + 1) * 100 * MS);
        }
        ok(engine.full_bw_reached && engine.full_bw_count == 3);
        ok(engine.state == (probe_bw ? QUICLY_BBR_BBR_STATE_PROBE_BW_DOWN : QUICLY_BBR_BBR_STATE_PROBE_BW_CRUISE));
        quicly_bbr_bbr_state state = engine.state;
        uint64_t pacing_gain = engine.pacing_gain_h;
        /* a late ACK disproves the only loss after the normal plateau transition has completed */
        engine.cc.on_spurious_congestion(&engine.cc, &stats, 410 * MS);
        quicly_bbr_cc_bbr_update_pacing(&engine, &stats);
        ok(engine.state == state && engine.full_bw_reached);
        ok(engine.pacing_gain_h == pacing_gain);
    }
}

static void test_startup_high_loss_undo(void)
{
    quicly_bbr_rst rst = {.delivered = 120000};
    quicly_bbr_cc_bbr engine;
    quicly_bbr_pcg32 random;
    quicly_bbr_conn_stat stats = {.cwnd = 120000,
                                  .max_tx_udp_payload_size = 1200,
                                  .smoothed_rtt = 100 * MS,
                                  .min_rtt = 100 * MS,
                                  .congestion_recovery_start_ts = 100 * MS,
                                  .delivery_rate_sec = 1000000};
    quicly_bbr_pcg32_init(&random, 1);
    quicly_bbr_cc_bbr_init(&engine, NULL, &stats, &rst, 0, &random);
    /* losses in a round after the first full recovery round can end Startup */
    engine.in_loss_recovery = 1;
    engine.round_count = 2;
    engine.round_count_at_recovery = 1;
    engine.next_round_delivered = rst.delivered;
    for (size_t i = 0; i != 7; ++i) {
        quicly_bbr_cc_pkt packet = {.pkt_num = (int64_t)i, .pktlen = 1200, .sent_ts = MS, .tx_in_flight = 120000};
        rst.lost += packet.pktlen;
        engine.cc.on_pkt_lost(&engine.cc, &stats, &packet, (200 + i) * MS);
        rst.delivered += 1200;
        rst.rs = (quicly_bbr_rs){.delivered = 1200 * (i + 1), .tx_in_flight = 120000, .lost = rst.lost};
        quicly_bbr_cc_ack ack = {.bytes_delivered = 1200, .bytes_lost = 1200, .largest_pkt_sent_ts = 50 * MS, .rtt = 100 * MS};
        engine.cc.on_ack_recv(&engine.cc, &stats, &ack, (200 + i) * MS);
    }
    ok(engine.full_bw_reached && engine.state != QUICLY_BBR_BBR_STATE_STARTUP);
    ok(engine.undo_state == QUICLY_BBR_BBR_STATE_STARTUP);
    engine.cc.on_spurious_congestion(&engine.cc, &stats, 210 * MS);
    ok(!engine.full_bw_reached && engine.state == QUICLY_BBR_BBR_STATE_STARTUP);
    ok(engine.pacing_gain_h == 277 && engine.undo_state == QUICLY_BBR_BBR_STATE_NONE);
}

static void init_probe_bw_loss_test(quicly_cc_t *cc, quicly_loss_t *loss)
{
    static const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    static const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    static const uint16_t max_ack_delay = 25;
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, cc, &conf, 1200, 0);
    quicly_bbr_configure(cc, 1200, 100, 1, 0);
    *loss = (quicly_loss_t){.conf = &loss_conf,
                            .max_ack_delay = &max_ack_delay,
                            .rtt = {.latest = 100, .minimum = 100, .smoothed = 100, .variance = 5}};
    quicly_cc_bbr_t *b = &cc->state.bbr;
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_UP;
    b->engine.full_bw_reached = 1;
    b->engine.is_bw_probe_sample = 1;
    b->engine.inflight_longterm = 100000;
    b->engine.bw = b->engine.max_bw = 1000000;
    b->engine.bdp = 100000;
    b->stats.cwnd = cc->cwnd = 100000;
}

static void lose_probe_bw_packet(quicly_cc_t *cc, quicly_loss_t *loss, quicly_bbr_packet_t *packet, uint64_t pn,
                                 uint64_t next_pn, double sent_at, double now)
{
    quicly_bbr_packet_lost(cc, &packet->meta, pn, sent_at, (uint32_t)loss->sentmap.bytes_in_flight, now);
    cc->type->cc_on_lost(cc, loss, packet->meta.bytes, pn, next_pn, now, 1200);
    loss->sentmap.bytes_in_flight -= packet->meta.bytes;
}

static void test_probe_bw_loss_undo(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss;
    init_probe_bw_loss_test(&cc, &loss);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_bbr_packet_t packets[2];
    for (size_t i = 0; i < 2; ++i)
        ok(quicly_bbr_packet_sent(&cc, packets + i, 1000, (i + 1) * 1000, i, i + 1));
    loss.sentmap.bytes_in_flight = 2000;
    for (size_t i = 0; i < 2; ++i)
        lose_probe_bw_packet(&cc, &loss, packets + i, i, 2, i + 1, 200);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_DOWN);
    ok(b->engine.undo_state == QUICLY_BBR_BBR_STATE_PROBE_BW_UP);
    ok(b->engine.inflight_longterm < 100000);
    ok(packets[0].meta.loss_epoch == packets[1].meta.loss_epoch);
    quicly_bbr_begin_ack(&cc, 200);
    cc.type->cc_on_acked(&cc, &loss, 0, 1, 0, 0, 2, 200, 1200, NULL);

    /* an ACK of only the second lost packet must not undo the entire recovery flight */
    quicly_bbr_begin_ack(&cc, 300);
    quicly_bbr_packet_acked(&cc, packets + 1, 1, 2, 300);
    ok(cc.num_loss_episodes_undone == 0);
    ok(b->undo_pending == 1 && b->engine.in_loss_recovery);
    cc.type->cc_on_acked(&cc, &loss, 0, 1, 0, 0, 2, 300, 1200, NULL);

    /* once both losses are disproved, restore the snapshot from before UP was interrupted */
    quicly_bbr_begin_ack(&cc, 400);
    quicly_bbr_packet_acked(&cc, packets, 0, 1, 400);
    ok(cc.num_loss_episodes_undone == 1);
    ok(b->undo_pending == 0 && !b->engine.in_loss_recovery);
    ok(b->engine.inflight_longterm == 100000);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_REFILL);
    quicly_bbr_packet_acked(&cc, packets, 0, 1, 400);
    ok(cc.num_loss_episodes_undone == 1);
}

static void test_probe_bw_new_loss_round_undo(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss;
    init_probe_bw_loss_test(&cc, &loss);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_bbr_packet_t packets[4];
    for (size_t i = 0; i < 2; ++i)
        ok(quicly_bbr_packet_sent(&cc, packets + i, 1000, (i + 1) * 1000, i, i + 1));
    loss.sentmap.bytes_in_flight = 2000;
    for (size_t i = 0; i < 2; ++i)
        lose_probe_bw_packet(&cc, &loss, packets + i, i, 2, i + 1, 200);
    uint32_t first_epoch = packets[0].meta.loss_epoch;

    /* delivery of a packet sent after the loss begins another loss round */
    ok(quicly_bbr_packet_sent(&cc, packets + 2, 1000, 1000, 2, 201));
    quicly_bbr_begin_ack(&cc, 301);
    quicly_bbr_packet_acked(&cc, packets + 2, 2, 201, 301);
    cc.type->cc_on_acked(&cc, &loss, 1000, 2, 0, 0, 3, 301, 1200, NULL);
    uint64_t latest_bound = b->engine.inflight_longterm;
    ok(latest_bound < 100000);

    ok(quicly_bbr_packet_sent(&cc, packets + 3, 1000, 1000, 3, 302));
    loss.sentmap.bytes_in_flight = 1000;
    lose_probe_bw_packet(&cc, &loss, packets + 3, 3, 4, 302, 500);
    ok(packets[3].meta.loss_epoch != first_epoch);
    quicly_bbr_begin_ack(&cc, 600);
    quicly_bbr_packet_acked(&cc, packets, 0, 1, 600);
    quicly_bbr_packet_acked(&cc, packets + 1, 1, 2, 600);
    ok(cc.num_loss_episodes_undone == 0 && b->undo_pending == 1);
    quicly_bbr_packet_acked(&cc, packets + 3, 3, 302, 600);
    ok(cc.num_loss_episodes_undone == 1 && b->undo_pending == 0);
    ok(b->engine.inflight_longterm == latest_bound);
    ok(b->engine.state != QUICLY_BBR_BBR_STATE_PROBE_BW_REFILL);
}

static void test_startup_loss_round_undo(void)
{
    static const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    static const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    static const uint16_t max_ack_delay = 25;
    quicly_cc_t cc;
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
    quicly_bbr_configure(&cc, 1200, 100, 1, 0);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_loss_t loss = {.conf = &loss_conf,
                          .max_ack_delay = &max_ack_delay,
                          .rtt = {.latest = 100, .minimum = 100, .smoothed = 100, .variance = 5}};
    quicly_bbr_packet_t packets[32];
    for (size_t i = 0; i < PTLS_ELEMENTSOF(packets); ++i)
        ok(quicly_bbr_packet_sent(&cc, packets + i, 1200, (i + 1) * 1200, i, 1 + i / 100.0));
    loss.sentmap.bytes_in_flight = sizeof(packets) / sizeof(packets[0]) * 1200;

    /* reordering produces seven ACKs with packet-threshold losses in the same flight */
    for (size_t batch = 0; batch < 7; ++batch) {
        uint64_t largest = 3 + 4 * batch;
        quicly_bbr_begin_ack(&cc, 100 + batch);
        quicly_bbr_packet_acked(&cc, packets + largest, largest, 1 + largest / 100.0, 100 + batch);
        loss.sentmap.bytes_in_flight -= 1200;
        for (size_t i = 0; i <= largest - 3; ++i) {
            if (packets[i].meta.flags != 0)
                continue;
            lose_probe_bw_packet(&cc, &loss, packets + i, i, PTLS_ELEMENTSOF(packets), 1 + i / 100.0, 100 + batch);
        }
        cc.type->cc_on_acked(&cc, &loss, 1200, largest, (uint32_t)loss.sentmap.bytes_in_flight, 1,
                             PTLS_ELEMENTSOF(packets), 100 + batch, 1200, NULL);
    }
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_STARTUP && b->engine.in_loss_recovery);
    ok(b->engine.loss_events_in_round == 7 && b->engine.bytes_lost_in_round != 0);
    uint64_t round = b->engine.round_count, cumulative_lost = b->sampler.rst.lost, stats_lost = b->stats.bytes_lost;

    quicly_bbr_begin_ack(&cc, 200);
    for (size_t i = 0; i < PTLS_ELEMENTSOF(packets); ++i)
        if (packets[i].meta.flags & QUICLY_BBR_PACKET_LOST)
            quicly_bbr_packet_acked(&cc, packets + i, i, 1 + i / 100.0, 200);
    ok(cc.num_loss_episodes_undone == 1 && b->undo_pending == 0 && !b->engine.in_loss_recovery);
    ok(cc.num_loss_episodes_undone_in_startup == 1);
    cc.type->cc_on_acked(&cc, &loss, 0, 27, (uint32_t)loss.sentmap.bytes_in_flight, 1,
                         PTLS_ELEMENTSOF(packets), 200, 1200, NULL);

    /* undo must work before a new round clears counters, without rewriting packet loss snapshots */
    ok(b->engine.round_count == round && !b->engine.round_start);
    ok(b->sampler.rst.lost == cumulative_lost && b->stats.bytes_lost == stats_lost);
    ok(b->sampler.rst.rs.lost == cumulative_lost);
    ok(b->engine.loss_events_in_round == 0 && b->engine.bytes_lost_in_round == 0);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_STARTUP && !b->engine.full_bw_reached);
}

static void test_startup_loss_round_undo_preserves_prior_epoch(void)
{
    static const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    static const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    static const uint16_t max_ack_delay = 25;
    quicly_cc_t cc;
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
    quicly_bbr_configure(&cc, 1200, 100, 1, 0);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_loss_t loss = {.conf = &loss_conf,
                          .max_ack_delay = &max_ack_delay,
                          .rtt = {.latest = 100, .minimum = 100, .smoothed = 100, .variance = 5}};
    quicly_bbr_packet_t packets[10];
    for (size_t i = 0; i < 6; ++i)
        ok(quicly_bbr_packet_sent(&cc, packets + i, 1200, (i + 1) * 1200, i, 1 + i / 100.0));
    loss.sentmap.bytes_in_flight = 7200;

    quicly_bbr_begin_ack(&cc, 101);
    quicly_bbr_packet_acked(&cc, packets, 0, 1, 101);
    loss.sentmap.bytes_in_flight -= 1200;
    cc.type->cc_on_acked(&cc, &loss, 1200, 0, (uint32_t)loss.sentmap.bytes_in_flight, 1, 6, 101, 1200, NULL);
    for (size_t i = 6; i < 8; ++i) {
        loss.sentmap.bytes_in_flight += 1200;
        ok(quicly_bbr_packet_sent(&cc, packets + i, 1200, (uint32_t)loss.sentmap.bytes_in_flight, i, 96 + i));
    }

    /* start a loss round after the packet round has already begun */
    quicly_bbr_begin_ack(&cc, 104);
    quicly_bbr_packet_acked(&cc, packets + 1, 1, 1.01, 104);
    loss.sentmap.bytes_in_flight -= 1200;
    lose_probe_bw_packet(&cc, &loss, packets + 2, 2, 8, 1.02, 104);
    cc.type->cc_on_acked(&cc, &loss, 1200, 1, (uint32_t)loss.sentmap.bytes_in_flight, 1, 8, 104, 1200, NULL);
    for (size_t i = 8; i < 10; ++i) {
        loss.sentmap.bytes_in_flight += 1200;
        ok(quicly_bbr_packet_sent(&cc, packets + i, 1200, (uint32_t)loss.sentmap.bytes_in_flight, i, 97 + i));
    }

    /* a new packet round can contain losses from the preceding undo epoch */
    quicly_bbr_begin_ack(&cc, 107);
    quicly_bbr_packet_acked(&cc, packets + 6, 6, 102, 107);
    loss.sentmap.bytes_in_flight -= 1200;
    lose_probe_bw_packet(&cc, &loss, packets + 3, 3, 10, 1.03, 107);
    cc.type->cc_on_acked(&cc, &loss, 1200, 6, (uint32_t)loss.sentmap.bytes_in_flight, 1, 10, 107, 1200, NULL);
    ok(b->engine.round_start && b->engine.loss_events_in_round == 1);
    ok(packets[2].meta.loss_epoch == packets[3].meta.loss_epoch);
    uint64_t round = b->engine.round_count;

    quicly_bbr_begin_ack(&cc, 108);
    quicly_bbr_packet_acked(&cc, packets + 8, 8, 105, 108);
    loss.sentmap.bytes_in_flight -= 1200;
    cc.type->cc_on_acked(&cc, &loss, 1200, 8, (uint32_t)loss.sentmap.bytes_in_flight, 1, 10, 108, 1200, NULL);
    ok(b->engine.loss_round_start && !b->engine.round_start && !b->engine.undo_loss_in_round);

    /* only this later epoch is disproved; the genuine loss from packet 3 must remain counted */
    quicly_bbr_begin_ack(&cc, 109);
    quicly_bbr_packet_acked(&cc, packets + 9, 9, 106, 109);
    loss.sentmap.bytes_in_flight -= 1200;
    lose_probe_bw_packet(&cc, &loss, packets + 4, 4, 10, 1.04, 109);
    cc.type->cc_on_acked(&cc, &loss, 1200, 9, (uint32_t)loss.sentmap.bytes_in_flight, 1, 10, 109, 1200, NULL);
    ok(packets[4].meta.loss_epoch != packets[3].meta.loss_epoch);
    ok(b->engine.loss_events_in_round == 2 && b->engine.bytes_lost_in_round == 2400);

    quicly_bbr_begin_ack(&cc, 110);
    quicly_bbr_packet_acked(&cc, packets + 4, 4, 1.04, 110);
    cc.type->cc_on_acked(&cc, &loss, 0, 4, (uint32_t)loss.sentmap.bytes_in_flight, 1, 10, 110, 1200, NULL);
    ok(cc.num_loss_episodes_undone == 1);
    ok(b->engine.round_count == round && !b->engine.round_start);
    ok(b->engine.loss_events_in_round == 1 && b->engine.bytes_lost_in_round == 1200);
    ok(b->sampler.rst.lost == 3600 && b->stats.bytes_lost == 3600);
}

static void test_probe_bw_growth_with_cumulative_acks(void)
{
    quicly_bbr_rst rst = {.delivered = 120000};
    quicly_bbr_pcg32 random;
    quicly_bbr_pcg32_init(&random, 1);
    quicly_bbr_conn_stat stats = {.cwnd = 12000,
                                  .max_tx_udp_payload_size = 1200,
                                  .smoothed_rtt = 100 * MS,
                                  .min_rtt = 100 * MS,
                                  .congestion_recovery_start_ts = UINT64_MAX};
    quicly_bbr_cc_bbr engine;
    quicly_bbr_cc_bbr_init(&engine, NULL, &stats, &rst, 0, &random);
    engine.full_bw_reached = 1;
    engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_REFILL;
    engine.ack_phase = QUICLY_BBR_BBR_ACK_PHASE_ACKS_REFILLING;
    engine.min_rtt = engine.probe_rtt_min_delay = 100 * MS;
    engine.max_bw = engine.bw = 120000;
    engine.inflight_longterm = engine.bdp = 12000;
    engine.next_round_delivered = rst.delivered;
    quicly_bbr_wf_update(&engine.max_bw_filter, 120000, 0);
    /* one cumulative ACK per flight starts a new round; its CWND-limited evidence must survive until probe growth */
    for (size_t i = 0; i < 5; ++i) {
        uint64_t before = rst.delivered;
        rst.delivered += 12000;
        rst.is_cwnd_limited = 1;
        rst.rs = (quicly_bbr_rs){.delivered = 12000, .prior_delivered = before, .tx_in_flight = 12000};
        stats.delivery_rate_sec = 120000;
        stats.bytes_in_flight = 0;
        quicly_bbr_cc_ack ack = {.bytes_delivered = 12000,
                                 .pkt_delivered = before,
                                 .largest_pkt_sent_ts = i * 100 * MS,
                                 .rtt = 100 * MS};
        engine.cc.on_ack_recv(&engine.cc, &stats, &ack, (i + 1) * 100 * MS);
    }
    ok(engine.inflight_longterm > 12000);
    ok(engine.bw_probe_up_rounds > 1);
    ok(stats.cwnd > 12000);
}

static void test_submillisec_rtt_and_recovery_ordering(void)
{
    quicly_cc_t cc;
    static const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    static const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    static const uint16_t max_ack_delay = 25;
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
    quicly_bbr_configure(&cc, 1200, 100, 1, 0);
    quicly_loss_t loss = {.conf = &loss_conf, .max_ack_delay = &max_ack_delay, .rtt = {.minimum = FLT_MAX}};
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_bbr_packet_t p[5];

    /* float ULP rounding on 100.3 ms and sub-microsecond RTTs must not drop valid delivery rate samples */
    ok(quicly_bbr_packet_sent(&cc, p, 1200, 1200, 0, 10.0));
    quicly_rtt_update(&loss.rtt, 100.3, 0, 110);
    quicly_bbr_begin_ack(&cc, 110.3);
    b->rtt_sample_valid = 1;
    quicly_bbr_packet_acked(&cc, p, 0, 10.0, 110.3);
    quicly_bbr_update_rtt(&cc, loss.rtt.latest, 10.0, 110.3);
    cc.type->cc_on_acked(&cc, &loss, 1200, 0, 0, 1, 1, 110, 1200, NULL);
    ok(b->stats.min_rtt == quicly_bbr_time(110.3) - quicly_bbr_time(10.0));
    ok(b->stats.delivery_rate_sec != 0 && b->engine.max_bw != 0);

    /* sub-microsecond RTT (500 ns) preserves exact nanosecond min_rtt despite loss.rtt.minimum clamping to 1 us */
    ok(quicly_bbr_packet_sent(&cc, p + 1, 1200, 1200, 1, 200.0));
    quicly_rtt_update(&loss.rtt, 0.0005, 0, 200);
    quicly_bbr_begin_ack(&cc, 200.0005);
    b->rtt_sample_valid = 1;
    quicly_bbr_packet_acked(&cc, p + 1, 1, 200.0, 200.0005);
    quicly_bbr_update_rtt(&cc, loss.rtt.latest, 200.0, 200.0005);
    cc.type->cc_on_acked(&cc, &loss, 1200, 1, 0, 1, 2, 200, 1200, NULL);
    ok(b->stats.min_rtt == 500 && b->engine.min_rtt == 500);
    ok(b->stats.delivery_rate_sec != 0);

    /* recovery exit and round_count_at_recovery must align when ACK processing runs before cc_on_acked */
    quicly_bbr_configure(&cc, 1200, 100, 2, 0);
    loss.rtt = (quicly_rtt_t){.latest = 100, .minimum = 100, .smoothed = 100, .variance = 5};
    b->engine.bw = b->engine.max_bw = 1200000;
    b->engine.bdp = 120000;
    b->stats.cwnd = cc.cwnd = 120000;
    ok(quicly_bbr_packet_sent(&cc, p, 1200, 1200, 0, 10));
    ok(quicly_bbr_packet_sent(&cc, p + 1, 1200, 2400, 1, 11));
    loss.sentmap.bytes_in_flight = 2400;
    quicly_bbr_begin_ack(&cc, 111);
    b->rtt_sample_valid = 1;
    quicly_bbr_packet_acked(&cc, p + 1, 1, 11, 111);
    quicly_bbr_update_rtt(&cc, loss.rtt.latest, 11, 111);
    lose_probe_bw_packet(&cc, &loss, p, 0, 2, 10, 111);
    loss.sentmap.bytes_in_flight = 0;
    cc.type->cc_on_acked(&cc, &loss, 1200, 1, 0, 0, 2, 111, 1200, NULL);
    ok(b->engine.in_loss_recovery);
    ok(b->engine.round_count_at_recovery == b->engine.round_count);
    ok(b->engine.prior_cwnd == 120000);

    /* an ACK that exits recovery and also detects a new loss must restore prior_cwnd before saving it again */
    b->stats.cwnd = cc.cwnd = 6000;
    ok(quicly_bbr_packet_sent(&cc, p + 2, 1200, 1200, 2, 120));
    ok(quicly_bbr_packet_sent(&cc, p + 3, 1200, 2400, 3, 121));
    loss.sentmap.bytes_in_flight = 2400;
    quicly_bbr_begin_ack(&cc, 221);
    b->rtt_sample_valid = 1;
    quicly_bbr_packet_acked(&cc, p + 3, 3, 121, 221);
    quicly_bbr_update_rtt(&cc, loss.rtt.latest, 121, 221);
    lose_probe_bw_packet(&cc, &loss, p + 2, 2, 4, 120, 221);
    loss.sentmap.bytes_in_flight = 0;
    cc.type->cc_on_acked(&cc, &loss, 1200, 3, 0, 0, 4, 221, 1200, NULL);
    ok(b->engine.in_loss_recovery);
    ok(b->engine.prior_cwnd == 120000);

    /* zero-delivered loss batch (e.g. loss timer) still counts toward loss_events_in_round */
    ok(quicly_bbr_packet_sent(&cc, p + 4, 1200, 1200, 4, 230));
    loss.sentmap.bytes_in_flight = 1200;
    size_t prev_events = b->engine.loss_events_in_round;
    uint64_t prev_lost = b->engine.bytes_lost_in_round;
    lose_probe_bw_packet(&cc, &loss, p + 4, 4, 5, 230, 330);
    quicly_bbr_begin_ack(&cc, 330);
    cc.type->cc_on_acked(&cc, &loss, 0, 3, 0, 0, 5, 330, 1200, NULL);
    ok(b->engine.loss_events_in_round == prev_events + 1);
    ok(b->engine.bytes_lost_in_round == prev_lost + 1200);
}

static void test_native_rtt_adjustments(void)
{
    static const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    static const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    static const uint16_t max_ack_delay = 25;
    static const uint8_t ack_delay_exponent = 3;
    static const struct {
        double raw_rtt;
        uint64_t ack_delay_encoded, expected_rtt;
    } cases[] = {
        {36, 3125, 11 * MS},  /* subtract the admitted 25 ms delay */
        {36, 12500, 11 * MS}, /* cap a reported 100 ms delay at max_ack_delay */
        {20, 3125, 20 * MS},  /* reject a delay that would undercut the measured minimum */
        {0, 0, 1000},        /* retain the native positive floor for a zero-duration sample */
    };

    for (size_t i = 0; i < PTLS_ELEMENTSOF(cases); ++i) {
        quicly_cc_t cc;
        quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
        quicly_bbr_configure(&cc, 1200, 100, 1, 0);
        quicly_cc_bbr_t *b = &cc.state.bbr;
        quicly_loss_t loss = {.conf = &loss_conf,
                              .max_ack_delay = &max_ack_delay,
                              .ack_delay_exponent = &ack_delay_exponent,
                              .rtt = {.latest = 10, .minimum = 10, .smoothed = 10, .variance = 1}};
        b->engine.min_rtt = b->engine.probe_rtt_min_delay = 10 * MS;

        /* expire both BBR RTT filters so receiver delay would contaminate the refreshed BDP */
        double sent_at = 11000, now = sent_at + cases[i].raw_rtt;
        quicly_bbr_packet_t packet;
        ok(quicly_bbr_packet_sent(&cc, &packet, 1200, 1200, 0, sent_at));
        quicly_bbr_begin_ack(&cc, now);
        quicly_bbr_packet_acked(&cc, &packet, 0, sent_at, now);
        quicly_loss_on_ack_received(&loss, 0, UINT64_MAX, 1, QUICLY_EPOCH_1RTT, now, sent_at,
                                    cases[i].ack_delay_encoded, QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
        b->rtt_sample_valid = 1;
        quicly_bbr_update_rtt(&cc, loss.rtt.latest, sent_at, now);
        cc.type->cc_on_acked(&cc, &loss, 1200, 0, 0, 1, 1, now, 1200, NULL);
        ok(b->stats.latest_rtt == cases[i].expected_rtt);
        ok(b->engine.min_rtt == cases[i].expected_rtt);
        if (cases[i].raw_rtt != 0)
            ok(b->stats.min_rtt == 10 * MS); /* the delivery sampler retains its raw minimum */
    }
}

static void test_max_bw_filter_ecn_and_probe_rtt_ordering(void)
{
    static const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    static const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    static const uint16_t max_ack_delay = 25;
    quicly_cc_t cc;
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
    quicly_bbr_configure(&cc, 1200, 100, 1, 0);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_loss_t loss = {.conf = &loss_conf,
                          .max_ack_delay = &max_ack_delay,
                          .rtt = {.latest = 100, .minimum = 100, .smoothed = 100, .variance = 1}};

    /* max_bw_filter win = 1 retains max_bw across cycles c and c + 1, expiring cycle c in cycle c + 2 */
    quicly_bbr_wf_update(&b->engine.max_bw_filter, 1000000, 0);
    quicly_bbr_wf_update(&b->engine.max_bw_filter, 500000, 1);
    ok(quicly_bbr_wf_get_best(&b->engine.max_bw_filter) == 1000000);
    quicly_bbr_wf_update(&b->engine.max_bw_filter, 400000, 2);
    ok(quicly_bbr_wf_get_best(&b->engine.max_bw_filter) == 500000);

    /* classic ECN bounds survive REFILL and probe_rtt until a clean post-CE packet is acked */
    quicly_bbr_configure(&cc, 1200, 100, 2, 0);
    b->engine.full_bw_reached = 1;
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_CRUISE;
    quicly_bbr_wf_update(&b->engine.max_bw_filter, 1000000, 0);
    b->engine.max_bw = b->engine.bw = 1000000;
    b->engine.min_rtt = b->engine.probe_rtt_min_delay = 100 * MS;
    b->engine.inflight_longterm = 80000;
    cc.cwnd = b->stats.cwnd = 50000;
    b->engine.prev_probe_precautionary = 1;
    b->engine.prev_probe_too_high = 0;

    quicly_bbr_packet_t p[3];
    ok(quicly_bbr_packet_sent(&cc, p, 1200, 1200, 0, 10));
    ok(quicly_bbr_packet_sent(&cc, p + 1, 1200, 2400, 1, 20));
    loss.sentmap.bytes_in_flight = 2400;
    cc.type->cc_on_lost(&cc, &loss, 0, 0, 2, 110, 1200);
    ok(b->engine.ecn_cwnd == 35000 && cc.cwnd == 35000);
    ok(b->engine.ecn_bw == 700000 && b->engine.bw == 700000);
    ok(b->engine.inflight_longterm == 80000);
    ok(b->engine.prev_probe_too_high == 1);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_DOWN);

    /* ACK of packet 1 (sent before ecn_ce_end_pn == 2) that triggers REFILL must not release ECN bounds */
    b->engine.bw_probe_wait = 0;
    b->engine.cycle_stamp = 0;
    loss.sentmap.bytes_in_flight = 0;
    quicly_bbr_begin_ack(&cc, 120);
    b->rtt_sample_valid = 1;
    quicly_bbr_packet_acked(&cc, p + 1, 1, 20, 120);
    quicly_bbr_update_rtt(&cc, 100, 20, 120);
    cc.type->cc_on_acked(&cc, &loss, 1200, 1, 0, 0, 2, 120, 1200, NULL);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_BW_REFILL);
    ok(b->engine.ecn_cwnd == 35000 && b->engine.ecn_bw == 700000);
    ok(cc.cwnd <= 35000 && b->engine.bw == 700000);

    /* clean ACK of packet 2 (sent at pn == 2 >= ecn_ce_end_pn) releases ECN bounds */
    ok(quicly_bbr_packet_sent(&cc, p + 2, 1200, 1200, 2, 130));
    quicly_bbr_begin_ack(&cc, 230);
    b->rtt_sample_valid = 1;
    quicly_bbr_packet_acked(&cc, p + 2, 2, 130, 230);
    quicly_bbr_update_rtt(&cc, 100, 130, 230);
    cc.type->cc_on_acked(&cc, &loss, 1200, 2, 0, 0, 3, 230, 1200, NULL);
    ok(b->engine.ecn_cwnd == UINT64_MAX && b->engine.ecn_bw == UINT64_MAX);
    ok(b->engine.bw == 1000000);

    /* probe_rtt entry clears stale prev_probe_precautionary and uses the current ACK's updated bw */
    quicly_bbr_configure(&cc, 1200, 100, 3, 0);
    b->engine.full_bw_reached = 1;
    b->engine.state = QUICLY_BBR_BBR_STATE_PROBE_BW_CRUISE;
    b->engine.prev_probe_precautionary = 1;
    b->engine.min_rtt = b->engine.probe_rtt_min_delay = 100 * MS;
    b->engine.probe_rtt_min_stamp = 0;
    b->engine.min_rtt_stamp = 0;
    ok(quicly_bbr_packet_sent(&cc, p, 12000, 12000, 0, 5000));
    /* leave 5500 bytes in flight: > 4800 (4 * MTU if bw were still 0), but <= 6000 (0.5 * BDP once current ACK updates bw) */
    loss.sentmap.bytes_in_flight = 5500;
    quicly_bbr_begin_ack(&cc, 5100);
    b->rtt_sample_valid = 1;
    quicly_bbr_packet_acked(&cc, p, 0, 5000, 5100);
    quicly_bbr_update_rtt(&cc, 100, 5000, 5100);
    cc.type->cc_on_acked(&cc, &loss, 12000, 0, 5500, 0, 1, 5100, 1200, NULL);
    ok(b->engine.state == QUICLY_BBR_BBR_STATE_PROBE_RTT);
    ok(!b->engine.prev_probe_precautionary);
    ok(b->engine.probe_rtt_done_stamp != UINT64_MAX);

    /* MTU change updates send_quantum, offload_budget, and cwnd floor without resetting state */
    cc.cwnd = b->stats.cwnd = 4800;
    quicly_bbr_sync_mtu(&cc, 1500);
    ok(b->stats.max_tx_udp_payload_size == 1500);
    ok(cc.cwnd == 6000);
    ok(b->stats.send_quantum >= 3000 && b->engine.offload_budget == 3 * b->stats.send_quantum);
}

void test_bbr_sampler(void)
{
    subtest("initialization-and-persistent-congestion", test_engine_initialization_and_persistent_congestion);
    subtest("loss-undo-preserves-bandwidth-plateau", test_loss_undo_preserves_bandwidth_plateau);
    subtest("startup-high-loss-undo", test_startup_high_loss_undo);
    subtest("compression-and-ack-order", test_compression_and_ack_order);
    subtest("loss-late-ack-and-generation", test_loss_late_ack_and_generation);
    subtest("loss-during-ack", test_loss_discovered_during_ack);
    subtest("idle-and-application-limit", test_idle_and_application_limit);
    subtest("invalid-time-and-wide-arithmetic", test_invalid_time_and_wide_arithmetic);
    subtest("switch-with-inflight-packets", test_switch_with_inflight_packets);
    subtest("probe-bw-loss-undo", test_probe_bw_loss_undo);
    subtest("probe-bw-new-loss-round-undo", test_probe_bw_new_loss_round_undo);
    subtest("startup-loss-round-undo", test_startup_loss_round_undo);
    subtest("startup-loss-round-undo-preserves-prior-epoch", test_startup_loss_round_undo_preserves_prior_epoch);
    subtest("probe-bw-growth-with-cumulative-acks", test_probe_bw_growth_with_cumulative_acks);
    subtest("submillisec-rtt-and-recovery-ordering", test_submillisec_rtt_and_recovery_ordering);
    subtest("native-rtt-adjustments", test_native_rtt_adjustments);
    subtest("max-bw-filter-ecn-and-probe-rtt-ordering", test_max_bw_filter_ecn_and_probe_rtt_ordering);
}
