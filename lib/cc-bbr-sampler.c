/* Packet delivery sampling following the BBR delivery-rate estimator.
 * Times and durations are monotonic nanoseconds, rates are bytes per second. */
#include <limits.h>
#include <string.h>
#include "quicly/cc-bbr-sampler.h"

_Static_assert(sizeof(quicly_bbr_packet_times_t) == 24, "sentmap time payload");
_Static_assert(sizeof(quicly_bbr_packet_meta_t) == 24, "sentmap metadata payload");

void quicly_bbr_sampler_begin_ack(quicly_bbr_sampler_t *sampler)
{
    sampler->rst.rs = (quicly_bbr_rs){.interval = UINT64_MAX, .prior_ts = UINT64_MAX, .last_acked_pkt_id = -1};
    sampler->selected_lost = 0;
}

void quicly_bbr_sampler_init(quicly_bbr_sampler_t *sampler, uint32_t generation)
{
    *sampler = (quicly_bbr_sampler_t){.rst.pkt_id = -1, .generation = generation};
    quicly_bbr_sampler_begin_ack(sampler);
}

int quicly_bbr_sampler_on_sent(quicly_bbr_sampler_t *sampler, quicly_bbr_packet_t *packet, uint16_t bytes, uint32_t inflight,
                               uint64_t packet_id, uint64_t now)
{
    quicly_bbr_rst *rst = &sampler->rst;
    if (bytes == 0 || inflight < bytes || packet_id > INT64_MAX || (int64_t)packet_id <= rst->pkt_id)
        return 0;
    if (now < rst->first_sent_ts || now < rst->delivered_ts)
        return 0;
    /* A controller switch can leave an older generation in flight. Start the
     * first sample at this send even when that unrelated flight is nonempty. */
    if (rst->pkt_id == -1 || inflight == bytes)
        rst->first_sent_ts = rst->delivered_ts = now;
    *packet = (quicly_bbr_packet_t){.times = {rst->delivered, rst->delivered_ts, rst->first_sent_ts},
                                    .meta = {.lost = rst->lost,
                                             .inflight = inflight,
                                             .generation = sampler->generation,
                                             .bytes = bytes,
                                             .app_limited = rst->app_limited != 0}};
    rst->pkt_id = (int64_t)packet_id;
    return 1;
}

int quicly_bbr_sampler_on_ack(quicly_bbr_sampler_t *sampler, quicly_bbr_packet_t *packet, uint64_t packet_id, uint64_t sent_at,
                              uint64_t now)
{
    quicly_bbr_rst *rst = &sampler->rst;
    quicly_bbr_rs *rs = &rst->rs;
    if (packet->meta.generation != sampler->generation || (packet->meta.flags & QUICLY_BBR_PACKET_ACKED) ||
        packet->meta.bytes == 0 || packet_id > INT64_MAX || (int64_t)packet_id > rst->pkt_id || now < sent_at ||
        now < packet->times.delivered_at || sent_at < packet->times.first_sent_at || packet->times.delivered > rst->delivered ||
        packet->meta.lost > rst->lost || rst->delivered > UINT64_MAX - packet->meta.bytes)
        return 0;
    packet->meta.flags |= QUICLY_BBR_PACKET_ACKED;
    rst->delivered += packet->meta.bytes;
    rst->delivered_ts = now;
    if (rs->prior_ts == UINT64_MAX || (int64_t)packet_id > rs->last_acked_pkt_id) {
        rs->prior_delivered = packet->times.delivered;
        rs->prior_ts = packet->times.delivered_at;
        rs->is_app_limited = packet->meta.app_limited;
        rs->send_elapsed = sent_at - packet->times.first_sent_at;
        rs->ack_elapsed = now - packet->times.delivered_at;
        rs->last_acked_pkt_id = (int64_t)packet_id;
        rs->tx_in_flight = packet->meta.inflight;
        sampler->selected_lost = packet->meta.lost;
        rst->first_sent_ts = sent_at;
    }
    if (rst->app_limited != 0 && rst->delivered > rst->app_limited)
        rst->app_limited = 0;
    return 1;
}

int quicly_bbr_sampler_on_lost(quicly_bbr_sampler_t *sampler, quicly_bbr_packet_meta_t *packet)
{
    if (packet->generation != sampler->generation || packet->bytes == 0 ||
        (packet->flags & (QUICLY_BBR_PACKET_LOST | QUICLY_BBR_PACKET_ACKED)) || sampler->rst.lost > UINT64_MAX - packet->bytes)
        return 0;
    packet->flags |= QUICLY_BBR_PACKET_LOST;
    sampler->rst.lost += packet->bytes;
    return 1;
}

void quicly_bbr_sampler_finish_ack(quicly_bbr_sampler_t *sampler, quicly_bbr_conn_stat *stats)
{
    quicly_bbr_rst *rst = &sampler->rst;
    quicly_bbr_rs *rs = &rst->rs;
    stats->delivery_rate_sec = 0;
    if (rs->prior_ts == UINT64_MAX)
        return;
    rs->interval = rs->send_elapsed > rs->ack_elapsed ? rs->send_elapsed : rs->ack_elapsed;
    rs->delivered = rst->delivered - rs->prior_delivered;
    rs->lost = rst->lost - sampler->selected_lost;
    if (rs->interval == 0 || rs->interval < stats->min_rtt)
        return;
    __uint128_t rate = (__uint128_t)rs->delivered * QUICLY_BBR_SECONDS / rs->interval;
    stats->delivery_rate_sec = rate > UINT64_MAX ? UINT64_MAX : (uint64_t)rate;
}

void quicly_bbr_sampler_app_limited(quicly_bbr_sampler_t *sampler, uint64_t inflight)
{
    uint64_t delivered = sampler->rst.delivered;
    uint64_t marker = delivered > UINT64_MAX - inflight ? UINT64_MAX : delivered + inflight;
    sampler->rst.app_limited = marker != 0 ? marker : 1;
}
