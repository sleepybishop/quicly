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
    /* The earlier flight still has a packet in flight. Compressed ACKs must
     * not report the much faster ACK spacing as network capacity. */
    ok(quicly_bbr_sampler_on_sent(&s, p + 2, 1000, 2000, 2, 150 * MS));
    quicly_bbr_sampler_begin_ack(&s);
    ok(quicly_bbr_sampler_on_ack(&s, p + 2, 2, 150 * MS, 151 * MS));
    /* An older packet in the same ACK cannot replace the newest snapshot. */
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
    /* A late ACK still supplies delivery evidence, exactly once. */
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
    /* Native loss detection can run after examining ACK ranges. Include its
     * losses in this ACK's rate sample, without double-counting the packet. */
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
    /* A long idle period must not enter the next delivery interval. */
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
    ok(b->engine.inflight_longterm < 100000);
    ok(packets[0].meta.loss_epoch == packets[1].meta.loss_epoch);
    quicly_bbr_begin_ack(&cc, 200);
    cc.type->cc_on_acked(&cc, &loss, 0, 1, 0, 0, 2, 200, 1200, NULL);

    /* The first loss moves UP to DOWN. That transition must not let an ACK
     * of only the second lost packet undo the entire recovery flight. */
    quicly_bbr_begin_ack(&cc, 300);
    quicly_bbr_packet_acked(&cc, packets + 1, 1, 2, 300);
    ok(cc.num_loss_episodes_undone == 0);
    ok(b->undo_pending == 1 && b->engine.in_loss_recovery);
    cc.type->cc_on_acked(&cc, &loss, 0, 1, 0, 0, 2, 300, 1200, NULL);

    /* Once both losses are disproved, restore the snapshot from before UP
     * was interrupted, including its original long-term inflight bound. */
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

    /* Delivery of a packet sent after the loss begins another loss round. */
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
    /* One cumulative ACK per flight starts a new round on every callback.
     * Its CWND-limited evidence must survive until probe growth consumes it. */
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

void test_bbr_sampler(void)
{
    subtest("initialization-and-persistent-congestion", test_engine_initialization_and_persistent_congestion);
    subtest("compression-and-ack-order", test_compression_and_ack_order);
    subtest("loss-late-ack-and-generation", test_loss_late_ack_and_generation);
    subtest("loss-during-ack", test_loss_discovered_during_ack);
    subtest("idle-and-application-limit", test_idle_and_application_limit);
    subtest("invalid-time-and-wide-arithmetic", test_invalid_time_and_wide_arithmetic);
    subtest("switch-with-inflight-packets", test_switch_with_inflight_packets);
    subtest("probe-bw-loss-undo", test_probe_bw_loss_undo);
    subtest("probe-bw-new-loss-round-undo", test_probe_bw_new_loss_round_undo);
    subtest("probe-bw-growth-with-cumulative-acks", test_probe_bw_growth_with_cumulative_acks);
}
