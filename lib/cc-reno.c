/*
 * Copyright (c) 2019 Fastly, Janardhan Iyengar
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "quicly/cc.h"
#include "quicly.h"
#include "quicly/pacer.h"

/* TODO: Avoid increase if sender was application limited. */
static void reno_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                          uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    /* Do not increase congestion window while in recovery, unless in case the loss is observed during jumpstart. If a loss is
     * observed due to jumpstart, CWND is adjusted so that it would become bytes that passed through to the client during the
     * jumpstart phase of exactly 1 RTT, when the last ACK for the jumpstart phase is received. */
    if (largest_acked < cc->recovery_end) {
        if (largest_acked < cc->state.reno.jumpstart.exit_pn)
            cc->cwnd += bytes;
        return;
    }

    /* remember the amount of bytes acked contiguously for the packets send in jumpstart */
    if (cc->state.reno.jumpstart.enter_pn <= largest_acked && largest_acked < cc->state.reno.jumpstart.exit_pn)
        cc->state.reno.jumpstart.bytes_acked += bytes;

    /* when receiving the first ack for jumpstart, stop jumpstart and go back to slow start, adopting current inflight as cwnd */
    if (cc->pacer_multiplier == QUICLY_PACER_CALC_MULTIPLIER(1) && cc->state.reno.jumpstart.enter_pn <= largest_acked) {
        assert(cc->cwnd < cc->ssthresh);
        cc->cwnd = inflight;
        cc->state.reno.jumpstart.exit_pn = next_pn;
        cc->pacer_multiplier = QUICLY_PACER_CALC_MULTIPLIER(2); /* revert to pacing of slow start */
    }

    /* Slow start. */
    if (cc->cwnd < cc->ssthresh) {
        cc->cwnd += bytes;
        if (cc->cwnd_maximum < cc->cwnd)
            cc->cwnd_maximum = cc->cwnd;
        return;
    }
    /* Congestion avoidance. */
    cc->state.reno.stash += bytes;
    if (cc->state.reno.stash < cc->cwnd)
        return;
    /* Increase congestion window by 1 MSS per congestion window acked. */
    uint32_t count = cc->state.reno.stash / cc->cwnd;
    cc->state.reno.stash -= count * cc->cwnd;
    cc->cwnd += count * max_udp_payload_size;
    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

void quicly_cc_reno_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                            int64_t now, uint32_t max_udp_payload_size)
{
    quicly_cc__update_ecn_episodes(cc, bytes, lost_pn);

    /* Nothing to do if loss is in recovery window. */
    if (lost_pn < cc->recovery_end)
        return;
    cc->recovery_end = next_pn;
    cc->pacer_multiplier = QUICLY_PACER_CALC_MULTIPLIER(1.2);

    /* if detected loss before receiving all acks for jumpstart, restore original CWND */
    if (cc->ssthresh == UINT32_MAX && lost_pn < cc->state.reno.jumpstart.exit_pn) {
        assert(cc->cwnd < cc->ssthresh);
        /* CWND is set to the amount of bytes ACKed during the jump start phase plus the value before jump start. As we multiply by
         * beta below, we compensate for that by dividing by beta here. */
        cc->cwnd = cc->state.reno.jumpstart.bytes_acked / QUICLY_RENO_BETA;
    }

    ++cc->num_loss_episodes;
    if (cc->cwnd_exiting_slow_start == 0)
        cc->cwnd_exiting_slow_start = cc->cwnd;

    /* Reduce congestion window. */
    cc->cwnd *= QUICLY_RENO_BETA;
    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
    cc->ssthresh = cc->cwnd;

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;
}

void quicly_cc_reno_on_persistent_congestion(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now)
{
    /* TODO */
}

void quicly_cc_reno_on_sent(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now)
{
    /* Unused */
}

static void reno_enter_jumpstart(quicly_cc_t *cc, uint32_t jump_cwnd, uint64_t next_pn)
{
    if (cc->cwnd * 2 >= jump_cwnd)
        return;

    /* retain state to be restored upon loss */
    cc->state.reno.jumpstart.enter_pn = next_pn;

    /* adjust */
    cc->cwnd = jump_cwnd;
    cc->pacer_multiplier = QUICLY_PACER_CALC_MULTIPLIER(1);
}

static void reno_reset(quicly_cc_t *cc, uint32_t initcwnd)
{
    memset(cc, 0, sizeof(quicly_cc_t));
    cc->type = &quicly_cc_type_reno;
    cc->cwnd = cc->cwnd_initial = cc->cwnd_maximum = initcwnd;
    cc->ssthresh = cc->cwnd_minimum = UINT32_MAX;
    cc->pacer_multiplier = QUICLY_PACER_CALC_MULTIPLIER(2);
    cc->state.reno.jumpstart.enter_pn = UINT64_MAX;
}

static int reno_on_switch(quicly_cc_t *cc)
{
    if (cc->type == &quicly_cc_type_reno) {
        return 1; /* nothing to do */
    } else if (cc->type == &quicly_cc_type_pico) {
        cc->type = &quicly_cc_type_reno;
        cc->state.reno.stash = cc->state.pico.stash;
        return 1;
    } else if (cc->type == &quicly_cc_type_cubic) {
        /* When in slow start, state can be reused as-is; otherwise, restart. */
        if (cc->cwnd_exiting_slow_start == 0) {
            cc->type = &quicly_cc_type_reno;
        } else {
            reno_reset(cc, cc->cwnd_initial);
        }
        return 1;
    }

    return 0;
}

static void reno_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int64_t now)
{
    reno_reset(cc, initcwnd);
}

quicly_cc_type_t quicly_cc_type_reno = {"reno",
                                        &quicly_cc_reno_init,
                                        reno_on_acked,
                                        quicly_cc_reno_on_lost,
                                        quicly_cc_reno_on_persistent_congestion,
                                        quicly_cc_reno_on_sent,
                                        reno_on_switch,
                                        reno_enter_jumpstart};
quicly_init_cc_t quicly_cc_reno_init = {reno_init};

quicly_cc_type_t *quicly_cc_all_types[] = {&quicly_cc_type_reno, &quicly_cc_type_cubic, &quicly_cc_type_pico, NULL};

uint32_t quicly_cc_calc_initial_cwnd(uint32_t max_packets, uint16_t max_udp_payload_size)
{
    static const uint32_t mtu_max = 1472;

    /* apply filters to the two arguments */
    if (max_packets < QUICLY_MIN_CWND)
        max_packets = QUICLY_MIN_CWND;
    if (max_udp_payload_size > mtu_max)
        max_udp_payload_size = mtu_max;

    return max_packets * max_udp_payload_size;
}
