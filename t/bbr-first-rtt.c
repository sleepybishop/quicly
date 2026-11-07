#include "test.h"

static void lose_packet(quicly_cc_t *cc, quicly_loss_t *loss, quicly_bbr_packet_t *packet, uint64_t pn, double sent_at, double now)
{
    quicly_bbr_packet_lost(cc, &packet->meta, pn, sent_at, (uint32_t)loss->sentmap.bytes_in_flight, now);
    cc->type->cc_on_lost(cc, loss, packet->meta.bytes, pn, pn + 1, (int64_t)now, 1200);
    loss->sentmap.bytes_in_flight -= packet->meta.bytes;
    quicly_bbr_track_persistent_loss(cc, loss, pn, sent_at);
}

void test_bbr_first_rtt(void)
{
    const quicly_cc_conf_t conf = {.init_cc = &quicly_cc_bbr_init, .initcwnd_packets = 100};
    const quicly_loss_conf_t loss_conf = {.min_pto = 1};
    const uint16_t max_ack_delay = 25;
    const uint8_t ack_delay_exponent = 3;
    quicly_cc_t cc;
    quicly_loss_t loss;
    quicly_cc_bbr_init.cb(&quicly_cc_bbr_init, &cc, &conf, 1200, 0);
    quicly_bbr_configure(&cc, 1200, 100, 1, 0);
    quicly_loss_init(&loss, &loss_conf, 100, &max_ack_delay, &ack_delay_exponent);
    quicly_cc_bbr_t *b = &cc.state.bbr;
    quicly_bbr_packet_t packets[6];

    /* initial probes use the initial RTT and must not establish persistent congestion when the first ACK reveals a shorter RTT */
    for (size_t i = 0; i < 3; ++i)
        ok(quicly_bbr_packet_sent(&cc, packets + i, 1200, (uint32_t)(i + 1) * 1200, i, i * 1000));
    ok(b->stats.first_rtt_sample_ts == UINT64_MAX);
    quicly_bbr_begin_ack(&cc, 2010);
    quicly_bbr_packet_acked(&cc, packets + 2, 2, 2000, 2010);
    quicly_loss_on_ack_received(&loss, 2, UINT64_MAX, 3, QUICLY_EPOCH_1RTT, 2010, 2000, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    b->rtt_sample_valid = 1;
    quicly_bbr_update_rtt(&cc, loss.rtt.latest, 2000, 2010);
    loss.sentmap.bytes_in_flight = 2400;
    lose_packet(&cc, &loss, packets, 0, 0, 2010);
    lose_packet(&cc, &loss, packets + 1, 1, 1000, 2010);
    ok(b->stats.first_rtt_sample_ts == quicly_bbr_time(2010));
    ok(!b->persistent_pending && !b->loss_run_valid);
    uint32_t cwnd = cc.cwnd;
    quicly_bbr_apply_persistent_congestion(&cc);
    ok(b->persistent_events == 0 && cc.cwnd == cwnd);

    /* packets sent at or after the first sample are eligible for persistent congestion */
    const double sent_at[] = {2010, 2090, 2300};
    for (size_t i = 0; i < 3; ++i)
        ok(quicly_bbr_packet_sent(&cc, packets + i + 3, 1200, (uint32_t)(i + 1) * 1200, i + 3, sent_at[i]));
    loss.sentmap.bytes_in_flight = 3600;
    lose_packet(&cc, &loss, packets + 3, 3, sent_at[0], 2400);
    ok(!b->persistent_pending && b->loss_first_pn == 3);
    lose_packet(&cc, &loss, packets + 4, 4, sent_at[1], 2400);
    ok(!b->persistent_pending);
    lose_packet(&cc, &loss, packets + 5, 5, sent_at[2], 2400);
    ok(b->persistent_pending);
    quicly_bbr_apply_persistent_congestion(&cc);
    ok(b->persistent_events == 1 && cc.cwnd == 4800);

    /* a fresh path or controller generation must wait for its own first RTT sample */
    quicly_bbr_configure(&cc, 1200, 100, 2, 3000);
    quicly_rtt_init(&loss.rtt, &loss_conf, 100);
    quicly_bbr_track_persistent_loss(&cc, &loss, 6, 3000);
    quicly_bbr_track_persistent_loss(&cc, &loss, 7, 5000);
    ok(!b->persistent_pending && !b->loss_run_valid);
    quicly_loss_dispose(&loss);
}
