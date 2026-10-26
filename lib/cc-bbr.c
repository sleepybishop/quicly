/* Quicly packet-event and pacing adapter for the imported ngtcp2 BBR core. */
#include <limits.h>
#include <math.h>
#include "quicly.h"
#include "quicly/cc-bbr.h"

uint64_t quicly_bbr_time(double ms)
{
    if (!(ms >= 0))
        return 0;
    if (ms >= (double)UINT64_MAX / QUICLY_BBR_MILLISECONDS)
        return UINT64_MAX;
    return (uint64_t)(ms * QUICLY_BBR_MILLISECONDS);
}

static void sync_window(quicly_cc_t *cc)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    uint64_t floor = 4 * b->stats.max_tx_udp_payload_size;
    if (b->stats.cwnd < floor)
        b->stats.cwnd = floor;
    if (b->stats.cwnd > INT32_MAX)
        b->stats.cwnd = INT32_MAX;
    cc->cwnd = (uint32_t)b->stats.cwnd;
    if (cc->cwnd < cc->cwnd_minimum)
        cc->cwnd_minimum = cc->cwnd;
    if (cc->cwnd > cc->cwnd_maximum)
        cc->cwnd_maximum = cc->cwnd;
    if (b->engine.full_bw_reached && cc->exit_slow_start_at == INT64_MAX) {
        cc->cwnd_exiting_slow_start = cc->cwnd;
        cc->exit_slow_start_at = (int64_t)(b->event_time / QUICLY_BBR_MILLISECONDS);
    }
}

static void sync_path(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t mtu, uint64_t inflight, int64_t now)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    uint64_t at = quicly_bbr_time(now);
    if (at > b->event_time)
        b->event_time = at;
    b->stats.max_tx_udp_payload_size = mtu;
    b->stats.bytes_in_flight = inflight;
    b->stats.latest_rtt = quicly_bbr_time(loss->rtt.latest);
    b->stats.smoothed_rtt = quicly_bbr_time(loss->rtt.smoothed);
    b->stats.min_rtt = loss->rtt.minimum == FLT_MAX ? UINT64_MAX : quicly_bbr_time(loss->rtt.minimum);
    if (loss->rtt.latest != 0 && b->stats.first_rtt_sample_ts == UINT64_MAX)
        b->stats.first_rtt_sample_ts = b->event_time;
}

void quicly_bbr_configure(quicly_cc_t *cc, uint16_t mtu, double initial_rtt, uint32_t generation, double now)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    *b = (quicly_cc_bbr_t){.stats = {.cwnd = cc->cwnd,
                                     .max_tx_udp_payload_size = mtu,
                                     .min_rtt = UINT64_MAX,
                                     .first_rtt_sample_ts = UINT64_MAX,
                                     .congestion_recovery_start_ts = UINT64_MAX,
                                     .initial_rtt = quicly_bbr_time(initial_rtt)}};
    b->event_time = quicly_bbr_time(now);
    quicly_bbr_sampler_init(&b->sampler, generation);
    quicly_bbr_pcg32_init(&b->random, quicly_bbr_time(now) ^ ((uint64_t)generation << 32) ^ (uintptr_t)cc);
    quicly_bbr_cc_bbr_init(&b->engine, NULL, &b->stats, &b->sampler.rst, quicly_bbr_time(now), &b->random);
    /* Use the configured initial RTT while the estimator has no real sample.
     * Do not install a fabricated minimum RTT in the bandwidth model. */
    uint64_t rtt = b->stats.initial_rtt != 0 ? b->stats.initial_rtt : QUICLY_BBR_MILLISECONDS;
    __uint128_t interval = (__uint128_t)rtt * 1024 * 100 / 277 / cc->cwnd;
    b->stats.pacing_interval_m = interval > UINT64_MAX ? UINT64_MAX : interval != 0 ? (uint64_t)interval : 1;
}

void quicly_bbr_begin_ack(quicly_cc_t *cc, double now)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    b->event_time = quicly_bbr_time(now);
    b->rtt_sample_valid = 0;
    quicly_bbr_sampler_begin_ack(&b->sampler);
    b->ack_bytes = 0;
    b->ack_largest_sent_at = UINT64_MAX;
    b->ack_times_valid = 0;
}

int quicly_bbr_packet_sent(quicly_cc_t *cc, quicly_bbr_packet_t *packet, uint16_t bytes, uint32_t inflight, uint64_t pn, double now)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    b->event_time = quicly_bbr_time(now);
    return quicly_bbr_sampler_on_sent(&b->sampler, packet, bytes, inflight, pn, b->event_time);
}

void quicly_bbr_packet_acked(quicly_cc_t *cc, quicly_bbr_packet_t *packet, uint64_t pn, double sent_at, double now)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    b->event_time = quicly_bbr_time(now);
    if (!quicly_bbr_sampler_on_ack(&b->sampler, packet, pn, quicly_bbr_time(sent_at), quicly_bbr_time(now)))
        return;
    b->ack_bytes += packet->meta.bytes;
    if ((packet->meta.flags & QUICLY_BBR_PACKET_LOST) && packet->meta.loss_epoch == b->undo_epoch && b->undo_pending != 0) {
        if (--b->undo_pending == 0) {
            /* All losses since this undo snapshot are now known false. Do not
             * subtract individual old packets from a newer pending-loss batch. */
            b->pending_lost = 0;
            if (b->engine.undo_state == QUICLY_BBR_BBR_STATE_STARTUP)
                cc->num_loss_episodes_undone_in_startup++;
            b->engine.cc.on_spurious_congestion(&b->engine.cc, &b->stats, b->event_time);
            cc->num_loss_episodes_undone++;
            sync_window(cc);
        }
    }
    if (b->loss_run_valid && pn >= b->loss_first_pn && pn <= b->loss_last_pn) {
        b->loss_run_valid = 0;
        b->persistent_pending = 0;
    }
    uint64_t at = quicly_bbr_time(sent_at);
    if (b->ack_largest_sent_at == UINT64_MAX || at > b->ack_largest_sent_at)
        b->ack_largest_sent_at = at;
}

void quicly_bbr_packet_lost(quicly_cc_t *cc, quicly_bbr_packet_meta_t *packet, uint64_t pn, double sent_at, uint32_t inflight,
                            double now)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    b->event_time = quicly_bbr_time(now);
    b->loss_event_valid = 0;
    if (!quicly_bbr_sampler_on_lost(&b->sampler, packet))
        return;
    /* A probe phase change can reset congestion signals within this loss
     * batch. Keep every loss attached to the engine's original undo snapshot. */
    if (!b->engine.undo_loss_in_round) {
        if (++b->undo_epoch == 0)
            ++b->undo_epoch;
        b->undo_pending = 0;
    }
    packet->loss_epoch = b->undo_epoch;
    b->undo_pending++;
    b->pending_lost += packet->bytes;
    b->stats.bytes_lost += packet->bytes;
    b->stats.bytes_in_flight = inflight >= packet->bytes ? inflight - packet->bytes : 0;
    b->last_lost_sent_at = quicly_bbr_time(sent_at);
    b->loss_event_valid = 1;
    quicly_bbr_cc_pkt pkt = {.pkt_num = (int64_t)pn,
                             .pktlen = packet->bytes,
                             .sent_ts = b->last_lost_sent_at,
                             .lost = packet->lost,
                             .tx_in_flight = packet->inflight,
                             .is_app_limited = packet->app_limited};
    b->engine.cc.on_pkt_lost(&b->engine.cc, &b->stats, &pkt, b->event_time);
}

uint32_t quicly_bbr_pacing_rate(quicly_cc_t *cc)
{
    uint64_t interval = cc->state.bbr.stats.pacing_interval_m;
    uint64_t rate = interval != 0 ? (QUICLY_BBR_MILLISECONDS << 10) / interval : 0;
    return rate > UINT32_MAX ? UINT32_MAX : rate != 0 ? (uint32_t)rate : 1;
}

void quicly_bbr_set_app_limited(quicly_cc_t *cc, uint64_t inflight)
{
    quicly_bbr_sampler_app_limited(&cc->state.bbr.sampler, inflight);
}

static void apply_persistent_congestion(quicly_cc_t *cc)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    if (!b->persistent_pending)
        return;
    b->engine.cc.on_persistent_congestion(&b->engine.cc, &b->stats, b->event_time);
    b->persistent_pending = 0;
    b->persistent_events++;
    sync_window(cc);
}

static void on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                     int cc_limited, uint64_t next_pn, int64_t now, uint32_t mtu, const quicly_cc_ecn_counts_t *l4s)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    (void)bytes;
    (void)largest_acked;
    (void)inflight;
    (void)next_pn;
    (void)l4s;
    sync_path(cc, loss, mtu, loss->sentmap.bytes_in_flight, now);
    if (cc_limited)
        b->sampler.rst.is_cwnd_limited = 1;
    apply_persistent_congestion(cc);
    quicly_bbr_sampler_finish_ack(&b->sampler, &b->stats);
    quicly_bbr_cc_ack ack = {.bytes_delivered = b->ack_bytes,
                             .bytes_lost = b->pending_lost,
                             .pkt_delivered = b->sampler.rst.rs.prior_delivered,
                             .largest_pkt_sent_ts = b->ack_largest_sent_at,
                             .rtt = b->rtt_sample_valid ? quicly_bbr_time(loss->rtt.latest) : UINT64_MAX};
    b->engine.cc.on_ack_recv(&b->engine.cc, &b->stats, &ack, b->event_time);
    b->pending_lost = 0;
    sync_window(cc);
}

static void on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn, int64_t now,
                    uint32_t mtu)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    if (bytes != 0 && !b->loss_event_valid)
        return; /* pre-switch packets have no snapshot for this model */
    uint64_t remaining = loss->sentmap.bytes_in_flight;
    if (bytes != 0)
        remaining = remaining >= bytes ? remaining - bytes : 0;
    sync_path(cc, loss, mtu, remaining, now);
    if (bytes != 0) {
        if (!b->loss_run_valid || lost_pn != b->loss_last_pn + 1 || b->last_lost_sent_at < b->loss_first_sent_at) {
            b->loss_first_pn = lost_pn;
            b->loss_first_sent_at = b->last_lost_sent_at;
            b->persistent_notified = 0;
        }
        b->loss_last_pn = lost_pn;
        b->loss_run_valid = 1;
        uint64_t span = b->last_lost_sent_at - b->loss_first_sent_at;
        uint64_t threshold =
            quicly_bbr_time(3 * quicly_rtt_get_pto((quicly_rtt_t *)&loss->rtt, *loss->max_ack_delay, loss->conf->min_pto));
        /* Consecutive lost packet numbers are a conservative contiguous run:
         * gaps (including ACK-only packets) prevent a persistent declaration. */
        if (!b->persistent_notified && loss->rtt.latest != 0 && span >= threshold) {
            b->persistent_pending = 1;
            b->persistent_notified = 1;
        }
    }
    int new_episode = lost_pn >= cc->recovery_end;
    if (new_episode) {
        cc->recovery_end = next_pn;
        cc->num_loss_episodes++;
        if (bytes == 0)
            cc->num_ecn_loss_episodes++;
    }
    if (bytes == 0) {
        /* The imported core has no scalable ECN response. Apply a conservative
         * classic-ECN model bound once per recovery flight; L4S is rejected by
         * native connection setup and controller switching. */
        if (new_episode) {
            uint64_t cap = b->stats.cwnd * 7 / 10;
            if (cap < 4 * mtu)
                cap = 4 * mtu;
            if (b->engine.inflight_shortterm > cap)
                b->engine.inflight_shortterm = cap;
            if (b->engine.inflight_longterm > cap)
                b->engine.inflight_longterm = cap;
            b->stats.cwnd = cap;
            uint64_t bandwidth = b->engine.bw;
            if (bandwidth == 0 && b->stats.pacing_interval_m != 0)
                bandwidth = (QUICLY_BBR_SECONDS << 10) / b->stats.pacing_interval_m;
            uint64_t rate_cap = bandwidth / 10 * 7 + bandwidth % 10 * 7 / 10;
            if (rate_cap != 0 && b->engine.bw_shortterm > rate_cap)
                b->engine.bw_shortterm = rate_cap;
            b->stats.pacing_interval_m =
                b->stats.pacing_interval_m > UINT64_MAX / 10 ? UINT64_MAX : b->stats.pacing_interval_m * 10 / 7;
        }
    }
    quicly_bbr_cc_ack empty = {.largest_pkt_sent_ts = UINT64_MAX, .rtt = UINT64_MAX};
    b->engine.cc.congestion_event(&b->engine.cc, &b->stats, bytes != 0 ? b->last_lost_sent_at : b->ack_largest_sent_at, &empty,
                                  b->event_time);
    b->loss_event_valid = 0;
    sync_window(cc);
}

static void on_sent(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now)
{
    quicly_cc_bbr_t *b = &cc->state.bbr;
    sync_path(cc, loss, (uint32_t)b->stats.max_tx_udp_payload_size, loss->sentmap.bytes_in_flight, now);
    apply_persistent_congestion(cc);
    /* Quicly has already committed this packet. The imported engine's send
     * hook runs before insertion into ngtcp2's retransmit buffer and needs
     * the prior flight to recognize an application-limited idle restart. */
    uint64_t inflight = b->stats.bytes_in_flight;
    b->stats.bytes_in_flight = inflight >= bytes ? inflight - bytes : 0;
    quicly_bbr_cc_pkt pkt = {.pktlen = bytes, .sent_ts = b->event_time};
    b->engine.cc.on_pkt_sent(&b->engine.cc, &b->stats, &pkt);
    b->stats.bytes_in_flight = inflight;
    sync_window(cc);
}

static void reset(quicly_cc_t *cc, const quicly_cc_conf_t *conf, uint32_t cwnd, uint16_t mtu, int64_t now)
{
    if (cwnd > INT32_MAX)
        cwnd = INT32_MAX;
    *cc = (quicly_cc_t){.type = &quicly_cc_type_bbr,
                        .conf = conf,
                        .cwnd = cwnd,
                        .cwnd_initial = cwnd,
                        .cwnd_minimum = cwnd,
                        .cwnd_maximum = cwnd,
                        .ssthresh = UINT32_MAX,
                        .exit_slow_start_at = INT64_MAX};
    quicly_bbr_configure(cc, mtu, QUICLY_DEFAULT_INITIAL_RTT, 0, now);
}

static void init(quicly_init_cc_t *self, quicly_cc_t *cc, const quicly_cc_conf_t *conf, uint16_t mtu, int64_t now)
{
    (void)self;
    reset(cc, conf, quicly_cc_calc_initial_cwnd(conf->initcwnd_packets, mtu), mtu, now);
}

static int on_switch(quicly_cc_t *cc)
{
    if (cc->type == &quicly_cc_type_bbr)
        return 1;
    if (cc->type != &quicly_cc_type_reno && cc->type != &quicly_cc_type_cubic && cc->type != &quicly_cc_type_cubic_legacy &&
        cc->type != &quicly_cc_type_pico && cc->type != &quicly_cc_type_cuback)
        return 0;
    quicly_conn_t *conn = cc->conn;
    const quicly_cc_conf_t *conf = cc->conf;
    uint16_t mtu = QUICLY_CC_REFERENCE_MTU;
    reset(cc, conf, cc->cwnd_initial, mtu, 0);
    cc->conn = conn;
    return 1;
}

quicly_cc_type_t quicly_cc_type_bbr = {.name = "bbr",
                                       .cc_init = &quicly_cc_bbr_init,
                                       .cc_on_acked = on_acked,
                                       .cc_on_lost = on_lost,
                                       .cc_on_sent = on_sent,
                                       .cc_switch = on_switch};
quicly_init_cc_t quicly_cc_bbr_init = {init};
