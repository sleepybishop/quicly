/*
 * Copyright (c) 2026 Joseph Calderon
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
#ifndef quicly_flexicast_cc_h
#define quicly_flexicast_cc_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct st_quicly_flexicast_cc_t quicly_flexicast_cc_t;
typedef const struct st_quicly_flexicast_cc_type_t quicly_flexicast_cc_type_t;

#define QUICLY_FLEXICAST_CC_DEFAULT_MAX_MEMBERS 64
#define QUICLY_FLEXICAST_CC_HARD_MAX_MEMBERS 16384

typedef struct st_quicly_flexicast_cc_config_t {
    /** Member-state capacity reserved by the controller. The owning flow
     * fills this from its configured maximum when zero. */
    size_t maximum_members;
    uint64_t startup_rate_bytes_per_second;
    uint64_t minimum_rate_bytes_per_second;
    uint64_t maximum_rate_bytes_per_second;
    uint32_t maximum_datagram_size;
    uint32_t feedback_timeout_msec;
    uint16_t packet_reordering_threshold;
} quicly_flexicast_cc_config_t;

typedef struct st_quicly_flexicast_cc_hints_t {
    uint32_t active_senders;
    uint64_t median_sender_rate_bytes_per_second;
    uint64_t aggregate_rate_limit_bytes_per_second;
    /** Transport-agnostic load that shares this controller's physical path
     * but is scheduled above the controller. It can suppress growth but is not
     * by itself path-congestion evidence. An increasing epoch publishes a new
     * measurement interval; repeated hints from one epoch are idempotent. */
    uint64_t external_load_epoch;
    uint64_t external_load_queued_bytes;
    uint64_t external_load_oldest_age_msec;
    uint32_t external_load_fraction_ppm;
} quicly_flexicast_cc_hints_t;

typedef struct st_quicly_flexicast_feedback_t {
    uint64_t member_id;
    uint64_t epoch;
    uint64_t largest_acknowledged;
    uint64_t acked_packets;
    uint64_t acked_bytes;
    uint64_t lost_packets;
    uint64_t lost_bytes;
    uint64_t delivered_bytes;
    uint64_t delivery_rate_bytes_per_second;
    uint64_t ecn_ce_count;
    uint32_t latest_rtt_msec;
    uint32_t minimum_rtt_msec;
    uint32_t smoothed_rtt_msec;
    uint32_t ack_delay_msec;
    int64_t now;
} quicly_flexicast_feedback_t;

#define QUICLY_FLEXICAST_CC_REASON_NONE 0U
#define QUICLY_FLEXICAST_CC_REASON_ACK 0x01U
#define QUICLY_FLEXICAST_CC_REASON_LOSS 0x02U
#define QUICLY_FLEXICAST_CC_REASON_ECN 0x04U
#define QUICLY_FLEXICAST_CC_REASON_TIMEOUT 0x08U
#define QUICLY_FLEXICAST_CC_REASON_HINT 0x10U
#define QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD 0x20U
#define QUICLY_FLEXICAST_CC_REASON_RTT 0x40U
#define QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT 0x80U
#define QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN 0x100U

typedef struct st_quicly_flexicast_cc_output_t {
    uint64_t rate_bytes_per_second;
    uint64_t burst_bytes;
    uint64_t inflight_bytes;
    uint64_t limiting_member_id;
    int64_t next_timeout;
    uint32_t reason;
    /** Cumulative transition telemetry maintained by the controller wrapper.
     * Cause counters classify rate changes, while floor counters identify
     * crossings of the configured minimum rate. */
    uint64_t rate_increase_events;
    uint64_t rate_reduction_events;
    uint64_t floor_entry_events;
    uint64_t floor_exit_events;
    uint64_t ack_growth_events;
    uint64_t other_growth_events;
    uint64_t loss_reduction_events;
    uint64_t rtt_reduction_events;
    uint64_t ecn_reduction_events;
    uint64_t timeout_reduction_events;
    uint64_t rate_limit_reduction_events;
    uint64_t other_reduction_events;
    uint64_t external_load_growth_freeze_events;
} quicly_flexicast_cc_output_t;

struct st_quicly_flexicast_cc_type_t {
    const char *name;
    size_t state_size;
    int (*init)(void *state, const quicly_flexicast_cc_config_t *config, int64_t now, quicly_flexicast_cc_output_t *output);
    void (*dispose)(void *state);
    void (*on_member_added)(void *state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output);
    void (*on_member_removed)(void *state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output);
    /** Starts a new packet-number and feedback epoch without discarding path
     * rate history. Controllers must invalidate epoch-local timers here. */
    void (*on_epoch_reset)(void *state, int64_t now, quicly_flexicast_cc_output_t *output);
    void (*on_feedback)(void *state, const quicly_flexicast_feedback_t *feedback, quicly_flexicast_cc_output_t *output);
    void (*on_timeout)(void *state, int64_t now, quicly_flexicast_cc_output_t *output);
    void (*set_hints)(void *state, const quicly_flexicast_cc_hints_t *hints, int64_t now, quicly_flexicast_cc_output_t *output);
};

int quicly_flexicast_cc_create(quicly_flexicast_cc_t **cc, quicly_flexicast_cc_type_t *type,
                               const quicly_flexicast_cc_config_t *config, int64_t now);
void quicly_flexicast_cc_free(quicly_flexicast_cc_t *cc);
void quicly_flexicast_cc_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
void quicly_flexicast_cc_on_member_removed(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
void quicly_flexicast_cc_on_epoch_reset(quicly_flexicast_cc_t *cc, int64_t now);
void quicly_flexicast_cc_on_feedback(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback);
void quicly_flexicast_cc_on_timeout(quicly_flexicast_cc_t *cc, int64_t now);
void quicly_flexicast_cc_set_hints(quicly_flexicast_cc_t *cc, const quicly_flexicast_cc_hints_t *hints, int64_t now);
void quicly_flexicast_cc_get_output(const quicly_flexicast_cc_t *cc, quicly_flexicast_cc_output_t *output);
quicly_flexicast_cc_type_t *quicly_flexicast_cc_get_type(const quicly_flexicast_cc_t *cc);

extern quicly_flexicast_cc_type_t quicly_flexicast_cc_type_multicast;
extern quicly_flexicast_cc_type_t quicly_flexicast_cc_type_adaptive;

#ifdef __cplusplus
}
#endif

#endif
