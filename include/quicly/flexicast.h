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
#ifndef quicly_flexicast_h
#define quicly_flexicast_h

#include "quicly/flexicast_cc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "quicly.h"

#define QUICLY_FLEXICAST_FLOW_ID_SIZE 8
#define QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS 64
#define QUICLY_FLEXICAST_HARD_MAX_MEMBERS 16384
#define QUICLY_FLEXICAST_SENT_WINDOW 2048
#define QUICLY_FLEXICAST_REPLAY_WINDOW 64
#define QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE 65535
#define QUICLY_FLEXICAST_DEFAULT_ACK_FREQUENCY 8
#define QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE 2048

/* draft-navarre-quic-flexicast-02 leaves these frame types as TBD. Keeping
 * provisional values here makes replacement mechanical when values exist. */
#define QUICLY_FRAME_TYPE_FC_ANNOUNCE 0x173e00
#define QUICLY_FRAME_TYPE_FC_STATE 0x173e01
#define QUICLY_FRAME_TYPE_FC_KEY 0x173e02

#define QUICLY_FLEXICAST_STATE_JOIN 1
#define QUICLY_FLEXICAST_STATE_LEAVE 2
#define QUICLY_FLEXICAST_STATE_READY 3

/* This is an experimental DATAGRAM-only shared-path primitive. Its packet
 * format is intentionally private until Flexicast QUIC wire details settle. */
typedef struct st_quicly_flexicast_flow_t quicly_flexicast_flow_t;

typedef enum en_quicly_flexicast_result_t {
    QUICLY_FLEXICAST_OK = 0,
    QUICLY_FLEXICAST_ERROR_INVALID = -1,
    QUICLY_FLEXICAST_ERROR_NO_MEMORY = -2,
    QUICLY_FLEXICAST_ERROR_CRYPTO = -3,
    QUICLY_FLEXICAST_ERROR_WRONG_FLOW = -4,
    QUICLY_FLEXICAST_ERROR_REPLAY = -5,
    QUICLY_FLEXICAST_ERROR_NO_MEMBERS = -6,
    QUICLY_FLEXICAST_ERROR_MEMBER_LIMIT = -7,
    QUICLY_FLEXICAST_ERROR_SEND_WINDOW = -8,
    QUICLY_FLEXICAST_ERROR_NOT_FOUND = -9,
    QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL = -10,
    QUICLY_FLEXICAST_ERROR_FRAME_ENCODING = -11,
    QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION = -12
} quicly_flexicast_result_t;

size_t quicly_flexicast_announce_frame_capacity(const quicly_flexicast_announce_frame_t *frame);
int quicly_flexicast_encode_announce_frame(uint8_t *dst, size_t capacity, const quicly_flexicast_announce_frame_t *frame,
                                           size_t *encoded_size);
int quicly_flexicast_decode_announce_frame(const uint8_t *src, size_t len, quicly_flexicast_announce_frame_t *frame,
                                           size_t *consumed);

size_t quicly_flexicast_state_frame_capacity(const quicly_flexicast_state_frame_t *frame);
int quicly_flexicast_encode_state_frame(uint8_t *dst, size_t capacity, const quicly_flexicast_state_frame_t *frame,
                                        size_t *encoded_size);
int quicly_flexicast_decode_state_frame(const uint8_t *src, size_t len, quicly_flexicast_state_frame_t *frame, size_t *consumed);

size_t quicly_flexicast_key_frame_capacity(const quicly_flexicast_key_frame_t *frame);
int quicly_flexicast_encode_key_frame(uint8_t *dst, size_t capacity, const quicly_flexicast_key_frame_t *frame,
                                      size_t *encoded_size);
int quicly_flexicast_decode_key_frame(const uint8_t *src, size_t len, quicly_flexicast_key_frame_t *frame, size_t *consumed);

/** True only after both Flexicast and MPQUIC have been negotiated. */
int quicly_flexicast_is_negotiated(quicly_conn_t *conn);
/** Queues an ack-eliciting, retransmittable FC control frame on the unicast path. */
int quicly_flexicast_send_announce(quicly_conn_t *conn, const quicly_flexicast_announce_frame_t *frame);
int quicly_flexicast_send_state(quicly_conn_t *conn, const quicly_flexicast_state_frame_t *frame);
int quicly_flexicast_send_key(quicly_conn_t *conn, const quicly_flexicast_key_frame_t *frame);
/** Queues PATH_ACK feedback for one received flow packet on the unicast connection. */
int quicly_flexicast_send_path_ack(quicly_conn_t *conn, uint64_t flow_id, uint64_t packet_number);

typedef struct st_quicly_flexicast_config_t {
    uint64_t flow_id;
    /** Initial egress packet number, and the expected first ingress packet
     * number before any packet has been received. This is the First Packet
     * Number carried by FC_KEY. */
    uint64_t first_packet_number;
    ptls_cipher_suite_t *cipher_suite;
    quicly_crypto_engine_t *crypto_engine;
    /* Passed through to crypto-engine callbacks. The default engine permits
     * NULL; offload engines may require the owning control connection. */
    quicly_conn_t *crypto_conn;
    ptls_iovec_t traffic_secret;
    /** Maximum simultaneously known members. Zero selects
     * QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS. */
    size_t max_members;
    /** Optional multicast-specific congestion controller. A NULL type keeps
     * the legacy caller-owned pacing behavior. */
    quicly_flexicast_cc_type_t *cc_type;
    quicly_flexicast_cc_config_t cc_config;
    uint32_t ack_delay_msec;
    uint16_t ack_frequency;
    int64_t now;
} quicly_flexicast_config_t;

typedef struct st_quicly_flexicast_member_stats_t {
    uint64_t member_id;
    uint64_t feedback_epoch;
    uint64_t largest_acknowledged;
    uint64_t delivered_packets;
    uint64_t delivered_bytes;
    uint64_t lost_packets;
    uint64_t lost_bytes;
    uint64_t delivery_rate_bytes_per_second;
    uint64_t ecn_ce_count;
    uint32_t latest_rtt_msec;
    uint32_t minimum_rtt_msec;
    uint32_t smoothed_rtt_msec;
    int64_t last_feedback_at;
} quicly_flexicast_member_stats_t;

int quicly_flexicast_flow_create(quicly_flexicast_flow_t **flow, const quicly_flexicast_config_t *config);
/** Replaces the traffic keys and packet epoch in place. Congestion-controller
 * and known-member measurements are retained, while active delivery
 * membership, replay state, ACK ranges, and outstanding packets are reset. */
int quicly_flexicast_flow_rekey(quicly_flexicast_flow_t *flow, ptls_iovec_t traffic_secret, uint64_t first_packet_number,
                                int64_t now);
void quicly_flexicast_flow_free(quicly_flexicast_flow_t *flow);

uint64_t quicly_flexicast_get_flow_id(const quicly_flexicast_flow_t *flow);
uint64_t quicly_flexicast_get_next_packet_number(const quicly_flexicast_flow_t *flow);

int quicly_flexicast_attach(quicly_flexicast_flow_t *flow, uint64_t member_id);
int quicly_flexicast_attach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
int quicly_flexicast_detach(quicly_flexicast_flow_t *flow, uint64_t member_id);
int quicly_flexicast_detach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
size_t quicly_flexicast_num_members(const quicly_flexicast_flow_t *flow);
int quicly_flexicast_get_member_stats(const quicly_flexicast_flow_t *flow, uint64_t member_id,
                                      quicly_flexicast_member_stats_t *stats);

/* Builds one protected short-header packet containing exactly one DATAGRAM
 * frame. The same returned bytes may be sent to every attached member. */
int quicly_flexicast_send_datagram(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                   size_t *packet_size, uint64_t *packet_number);
int quicly_flexicast_send_datagram_at(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                      size_t *packet_size, uint64_t *packet_number, int64_t now);

/* Decrypts in place. The returned payload borrows storage from packet. */
int quicly_flexicast_receive_datagram(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                      uint64_t *packet_number);
int quicly_flexicast_receive_datagram_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                         uint64_t *packet_number, int64_t now);

/** Returns INT64_MAX when there is no pending feedback. */
int64_t quicly_flexicast_get_ack_deadline(const quicly_flexicast_flow_t *flow);
int quicly_flexicast_ack_is_due(const quicly_flexicast_flow_t *flow, int64_t now);
/** Encodes and reliably queues all pending receive ranges on the authenticated
 * unicast connection. force bypasses ACK-frequency and timer checks. */
int quicly_flexicast_send_pending_ack(quicly_flexicast_flow_t *flow, quicly_conn_t *conn, int64_t now, int force);

/* Helpers used by quicly's reliable-control queue implementation. */
int quicly_flexicast_encode_pending_ack(quicly_flexicast_flow_t *flow, uint8_t *dst, size_t capacity, int64_t now,
                                        size_t *encoded_size);
void quicly_flexicast_ack_sent(quicly_flexicast_flow_t *flow);

/* Aggregation bookkeeping for feedback received over member-specific unicast
 * paths. complete is set once every currently attached member acknowledged. */
int quicly_flexicast_ack(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete);
int quicly_flexicast_ack_at(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete, int64_t now);
/** Applies all newly acknowledged packets in a decoded PATH_ACK to one member. */
int quicly_flexicast_ack_frame(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame,
                               size_t *num_acked, size_t *num_completed);
/** Timed variant that also reports packets retired as lost. */
int quicly_flexicast_ack_frame_at(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame,
                                  size_t *num_acked, size_t *num_lost, size_t *num_completed, int64_t now);
int quicly_flexicast_get_pending_members(const quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t *pending);
/** Clears one member from a packet that was protected but could not be
 * submitted locally. This is not reported to congestion control as network
 * loss. */
int quicly_flexicast_abandon_datagram(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete);

void quicly_flexicast_cc_set_flow_hints(quicly_flexicast_flow_t *flow, const quicly_flexicast_cc_hints_t *hints, int64_t now);
void quicly_flexicast_cc_on_flow_timeout(quicly_flexicast_flow_t *flow, int64_t now);
void quicly_flexicast_cc_get_flow_output(const quicly_flexicast_flow_t *flow, quicly_flexicast_cc_output_t *output);

#ifdef __cplusplus
}
#endif

#endif
