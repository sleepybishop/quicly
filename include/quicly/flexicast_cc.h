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
    /** zero means unlimited; otherwise this must be at least the minimum rate */
    uint64_t maximum_rate_bytes_per_second;
    uint32_t maximum_datagram_size;
    /** zero selects 1000 milliseconds */
    uint32_t feedback_timeout_msec;
    uint16_t packet_reordering_threshold;
} quicly_flexicast_cc_config_t;

typedef struct st_quicly_flexicast_cc_hints_t {
    uint32_t active_senders;
    /** Physical copies charged to the pacer for each logical datagram.
     * Zero selects one (native multicast); replicated unicast uses its fanout.
     * Delivery feedback is per receiver and must use the same rate units. */
    uint32_t delivery_rate_divisor;
    uint64_t median_sender_rate_bytes_per_second;
    /** A hard share of the physical path budget, including below the configured
     * minimum rate. Zero means unlimited. */
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

#define QUICLY_FLEXICAST_SAMPLE_PRESENT 0x01U
#define QUICLY_FLEXICAST_SAMPLE_VALID 0x02U
#define QUICLY_FLEXICAST_SAMPLE_APP_LIMITED 0x04U
#define QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED 0x08U
#define QUICLY_FLEXICAST_SAMPLE_MIXED 0x10U

#define QUICLY_FLEXICAST_RTT_PRESENT 0x01U
#define QUICLY_FLEXICAST_RTT_VALID 0x02U
#define QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT 0x04U

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
    /** Identifies the completed delivery-rate measurement, independently of
     * ACK-frame epochs. Repeated ACKs can carry the same published sample.
     * Zero uses now as the sample identity for callers without this clock. */
    uint64_t delivery_rate_sample_epoch;
    /** Native samples set PRESENT, including when context is unavailable.
     * Only VALID samples have one known send rate/fanout; limitations are
     * explicit transport observations, never inferred from low delivery.
     * With PRESENT, delivery_rate_bytes_per_second is this bucket's raw rate
     * over max(send interval, ACK interval), not the public stats EWMA.
     * Zero flags retain the legacy direct-controller caller convention. */
    uint32_t delivery_sample_flags;
    uint32_t delivery_sample_fanout;
    uint64_t delivery_sample_bytes;
    uint64_t delivery_sample_pacing_rate_bytes_per_second;
    int64_t delivery_sample_sent_at_start;
    int64_t delivery_sample_sent_at_end;
    int64_t delivery_sample_acked_at_start;
    int64_t delivery_sample_acked_at_end;
    uint64_t ecn_ce_count;
    uint32_t latest_rtt_msec;
    uint32_t minimum_rtt_msec;
    uint32_t smoothed_rtt_msec;
    uint32_t ack_delay_msec;
    /** Independent RTT provenance, retained unchanged on feedback that does
     * not newly acknowledge the frame's largest PN with a known send time.
     * rtt_ack_delay_msec is the capped delay used for this RTT sample;
     * ack_delay_msec above belongs to the current ACK frame. */
    uint64_t rtt_sample_epoch;
    int64_t rtt_sample_at;
    uint32_t raw_rtt_msec;
    uint32_t rtt_ack_delay_msec;
    uint32_t applied_ack_delay_msec;
    uint32_t rtt_sample_flags;
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

/** Optional observational state. Zero available means that this controller
 * does not expose these diagnostics. Reading state must never mutate it. */
typedef struct st_quicly_flexicast_cc_trace_state_t {
    uint32_t available;
    uint64_t control_epoch;
    uint64_t control_interval_msec;
    uint64_t last_growth_epoch;
    uint64_t last_reduction_epoch;
    int64_t last_growth_at;
    int64_t last_reduction_at;
    int64_t growth_blocked_until;
    int64_t next_timeout;
    uint32_t startup_probes;
    uint32_t unanswered_probes;
    uint32_t external_load;
    uint32_t member_present;
    uint64_t last_feedback_epoch;
    uint64_t last_delivery_sample_epoch;
    uint64_t last_rtt_sample_epoch;
    int64_t previous_rtt_at;
    uint64_t recent_delivery_rate;
    uint64_t expected_delivery_rate;
    uint32_t baseline_delivery_ratio_ppm;
    uint32_t recent_delivery_ratio_ppm;
    uint32_t degraded_delivery_epochs;
    uint32_t baseline_loss_ppm;
    uint32_t flat_loss_epochs;
    uint32_t minimum_rtt;
    uint32_t previous_rtt;
    uint32_t rising_delay_epochs;
} quicly_flexicast_cc_trace_state_t;

typedef enum en_quicly_flexicast_cc_trace_type_t {
    QUICLY_FLEXICAST_CC_TRACE_MEMBER_ADDED = 1,
    QUICLY_FLEXICAST_CC_TRACE_MEMBER_REMOVED,
    QUICLY_FLEXICAST_CC_TRACE_EPOCH_RESET,
    QUICLY_FLEXICAST_CC_TRACE_FEEDBACK,
    QUICLY_FLEXICAST_CC_TRACE_TIMEOUT,
    QUICLY_FLEXICAST_CC_TRACE_HINTS
} quicly_flexicast_cc_trace_type_t;

typedef struct st_quicly_flexicast_cc_trace_event_t {
    uint64_t sequence;
    int64_t now;
    quicly_flexicast_cc_trace_type_t type;
    uint64_t member_id;
    /** Populated only for FEEDBACK; otherwise zero. */
    quicly_flexicast_feedback_t feedback;
    /** Current hints, or the newly supplied input for HINTS. */
    quicly_flexicast_cc_hints_t hints;
    uint64_t rate_before;
    uint64_t rate_after;
    uint32_t reason;
    quicly_flexicast_cc_trace_state_t state_before;
    quicly_flexicast_cc_trace_state_t state_after;
} quicly_flexicast_cc_trace_event_t;

#define QUICLY_FLEXICAST_CC_TRACE_MAX_CAPACITY 16384U

struct st_quicly_flexicast_cc_type_t {
    const char *name;
    size_t state_size;
    /** state is zero-initialized; dispose is also called after a failed init */
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
    /** Stops considering a member for rate selection and feedback deadlines,
     * retaining its path history for a later on_member_added. If omitted,
     * the wrapper falls back to on_member_removed. */
    void (*on_member_suspended)(void *state, uint64_t member_id, int64_t now, quicly_flexicast_cc_output_t *output);
    /** Optional, read-only, and called only while tracing is enabled. */
    void (*get_trace_state)(const void *state, uint64_t member_id, int64_t now, quicly_flexicast_cc_trace_state_t *trace_state);
};

int quicly_flexicast_cc_create(quicly_flexicast_cc_t **cc, quicly_flexicast_cc_type_t *type,
                               const quicly_flexicast_cc_config_t *config, int64_t now);
void quicly_flexicast_cc_free(quicly_flexicast_cc_t *cc);
void quicly_flexicast_cc_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
void quicly_flexicast_cc_on_member_removed(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
void quicly_flexicast_cc_on_member_suspended(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
void quicly_flexicast_cc_on_epoch_reset(quicly_flexicast_cc_t *cc, int64_t now);
void quicly_flexicast_cc_on_feedback(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback);
void quicly_flexicast_cc_on_timeout(quicly_flexicast_cc_t *cc, int64_t now);
void quicly_flexicast_cc_set_hints(quicly_flexicast_cc_t *cc, const quicly_flexicast_cc_hints_t *hints, int64_t now);
void quicly_flexicast_cc_get_output(const quicly_flexicast_cc_t *cc, quicly_flexicast_cc_output_t *output);
quicly_flexicast_cc_type_t *quicly_flexicast_cc_get_type(const quicly_flexicast_cc_t *cc);

/** Tracing is off by default and allocates no ring until enabled. Capacity
 * must be in [1, TRACE_MAX_CAPACITY]. Enabling replaces the previous ring and
 * resets its sequence/overwrite counters; failure preserves the old ring.
 * These APIs, like controller updates, belong to the flow's owning thread. */
int quicly_flexicast_cc_enable_trace(quicly_flexicast_cc_t *cc, size_t capacity);
void quicly_flexicast_cc_disable_trace(quicly_flexicast_cc_t *cc);
/** Drain oldest first, at most capacity entries. overwritten is cumulative
 * since the last successful enable (and is not reset by reads or rekeys).
 * read(NULL, 0, &overwritten) queries that count without draining. Full rings
 * overwrite their oldest entry; no controller event waits for a reader. */
size_t quicly_flexicast_cc_read_trace(quicly_flexicast_cc_t *cc, quicly_flexicast_cc_trace_event_t *events, size_t capacity,
                                      uint64_t *overwritten);

extern quicly_flexicast_cc_type_t quicly_flexicast_cc_type_multicast;
extern quicly_flexicast_cc_type_t quicly_flexicast_cc_type_adaptive;

#ifdef __cplusplus
}
#endif

#endif
