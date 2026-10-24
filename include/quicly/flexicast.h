#ifndef quicly_flexicast_h
#define quicly_flexicast_h

#include "quicly/flexicast_cc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "quicly.h"

#define QUICLY_FLEXICAST_FLOW_ID_SIZE 8
#define QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS QUICLY_FLEXICAST_CC_DEFAULT_MAX_MEMBERS
#define QUICLY_FLEXICAST_HARD_MAX_MEMBERS QUICLY_FLEXICAST_CC_HARD_MAX_MEMBERS
#define QUICLY_FLEXICAST_SENT_WINDOW 2048
#define QUICLY_FLEXICAST_REPLAY_WINDOW 64
#define QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE 65535
#define QUICLY_FLEXICAST_DEFAULT_MAX_PACKET_SIZE 1200
/* maximum UDP payload that fits both IPv4 and IPv6 packets */
#define QUICLY_FLEXICAST_MAX_PACKET_SIZE 65507
#define QUICLY_FLEXICAST_DEFAULT_ACK_FREQUENCY 8
#define QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE 2048

/* provisional frame types for draft-navarre-quic-flexicast-03 */
#define QUICLY_FRAME_TYPE_FC_ANNOUNCE 0x173e00
#define QUICLY_FRAME_TYPE_FC_STATE 0x173e01
#define QUICLY_FRAME_TYPE_FC_KEY 0x173e02

#define QUICLY_FLEXICAST_STATE_JOIN 1
#define QUICLY_FLEXICAST_STATE_LEAVE 2
#define QUICLY_FLEXICAST_STATE_LISTEN 3
/* source compatibility with draft -02 */
#define QUICLY_FLEXICAST_STATE_READY QUICLY_FLEXICAST_STATE_LISTEN

/* experimental DATAGRAM-only shared-path primitive */
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
    QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION = -12,
    QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED = -13,
    QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED = -14
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

/* true only after both flexicast and MPQUIC have been negotiated */
int quicly_flexicast_is_negotiated(quicly_conn_t *conn);
/* queues an ack-eliciting, retransmittable FC control frame on the unicast path */
int quicly_flexicast_send_announce(quicly_conn_t *conn, const quicly_flexicast_announce_frame_t *frame);
int quicly_flexicast_send_state(quicly_conn_t *conn, const quicly_flexicast_state_frame_t *frame);
int quicly_flexicast_send_key(quicly_conn_t *conn, const quicly_flexicast_key_frame_t *frame);
/* queues PATH_ACK feedback for one received flow packet on the unicast connection */
int quicly_flexicast_send_path_ack(quicly_conn_t *conn, uint64_t flow_id, uint64_t packet_number);
/* closes the unicast connection on fatal protocol/frame/AEAD errors; ignores packet-local errors */
quicly_error_t quicly_flexicast_handle_receive_error(quicly_conn_t *conn, int result);

typedef struct st_quicly_flexicast_config_t {
    uint64_t flow_id;
    /* initial egress packet number and expected first ingress packet number from FC_KEY */
    uint64_t first_packet_number;
    ptls_cipher_suite_t *cipher_suite;
    quicly_crypto_engine_t *crypto_engine;
    /* passed through to crypto-engine callbacks; NULL is allowed for the default engine */
    quicly_conn_t *crypto_conn;
    ptls_iovec_t traffic_secret;
    /* maximum simultaneously known members; zero selects QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS */
    size_t max_members;
    /* optional multicast congestion controller; NULL keeps caller-owned pacing */
    quicly_flexicast_cc_type_t *cc_type;
    quicly_flexicast_cc_config_t cc_config;
    uint32_t ack_delay_msec;
    uint16_t ack_frequency;
    int64_t now;
    /* optional lower cryptographic usage limits; zero selects suite-specific QUIC defaults */
    uint64_t max_packets_per_key;
    uint64_t max_authentication_failures;
    /* maximum outgoing protected UDP payload in [1200, 65507]; zero selects 1200 */
    size_t max_packet_size;
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
    /* cumulative CE count for the current key epoch */
    uint64_t ecn_ce_count;
    uint32_t latest_rtt_msec;
    uint32_t minimum_rtt_msec;
    uint32_t smoothed_rtt_msec;
    int64_t last_feedback_at;
} quicly_flexicast_member_stats_t;

int quicly_flexicast_flow_create(quicly_flexicast_flow_t **flow, const quicly_flexicast_config_t *config);
/* replaces traffic keys and advances the packet-number epoch while retaining CC and member stats */
int quicly_flexicast_flow_rekey(quicly_flexicast_flow_t *flow, ptls_iovec_t traffic_secret, uint64_t first_packet_number,
                                int64_t now);
void quicly_flexicast_flow_free(quicly_flexicast_flow_t *flow);

uint64_t quicly_flexicast_get_flow_id(const quicly_flexicast_flow_t *flow);
uint64_t quicly_flexicast_get_next_packet_number(const quicly_flexicast_flow_t *flow);

/* member IDs are nonzero; attach is idempotent and reactivates known members after rekey */
int quicly_flexicast_attach(quicly_flexicast_flow_t *flow, uint64_t member_id);
int quicly_flexicast_attach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
int quicly_flexicast_detach(quicly_flexicast_flow_t *flow, uint64_t member_id);
int quicly_flexicast_detach_at(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
size_t quicly_flexicast_num_members(const quicly_flexicast_flow_t *flow);
int quicly_flexicast_get_member_stats(const quicly_flexicast_flow_t *flow, uint64_t member_id,
                                      quicly_flexicast_member_stats_t *stats);

/* exact protected packet size; zero for a NULL flow or unsupported payload size */
size_t quicly_flexicast_datagram_size(const quicly_flexicast_flow_t *flow, size_t payload_size);

/* builds one protected short-header packet containing one DATAGRAM frame */
int quicly_flexicast_send_datagram(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                   size_t *packet_size, uint64_t *packet_number);
int quicly_flexicast_send_datagram_at(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                      size_t *packet_size, uint64_t *packet_number, int64_t now);

/* records actual UDP submission time; member_id == 0 applies to all replicas, now <= 0 disables RTT sampling */
int quicly_flexicast_mark_submitted(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int64_t now);

typedef struct st_quicly_flexicast_send_context_t {
    uint64_t pacing_rate_bytes_per_second;
    uint32_t physical_fanout;
    /* QUICLY_FLEXICAST_SAMPLE_VALID plus explicit APP_LIMITED/HOST_LIMITED interval flags */
    uint32_t flags;
} quicly_flexicast_send_context_t;

/* records actual UDP submission time along with physical pacing rate and copy count */
int quicly_flexicast_mark_submitted_with_context(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number,
                                                 int64_t now, const quicly_flexicast_send_context_t *context);

/* decrypts in place into a borrowed payload view; returns BUFFER_TOO_SMALL if multiple DATAGRAMs are present */
int quicly_flexicast_receive_datagram(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                      uint64_t *packet_number);
int quicly_flexicast_receive_datagram_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payload,
                                         uint64_t *packet_number, int64_t now);
/* decrypts in place and outputs all DATAGRAM payload views without copying */
int quicly_flexicast_receive_datagrams_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size,
                                          ptls_iovec_t *payloads, size_t *num_payloads, uint64_t *packet_number, int64_t now);

/* like receive_datagram_at, recording the received IP ECN low two bits (Not-ECT=0, ECT(1)=1, ECT(0)=2, CE=3) */
int quicly_flexicast_receive_datagram_ecn_at(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size,
                                             ptls_iovec_t *payload, uint64_t *packet_number, int64_t now, uint8_t ecn);

/* returns INT64_MAX when there is no pending feedback */
int64_t quicly_flexicast_get_ack_deadline(const quicly_flexicast_flow_t *flow);
int quicly_flexicast_ack_is_due(const quicly_flexicast_flow_t *flow, int64_t now);
/* encodes and reliably queues the newest QUICLY_MAX_ACK_BLOCKS receive ranges on the unicast connection */
int quicly_flexicast_send_pending_ack(quicly_flexicast_flow_t *flow, quicly_conn_t *conn, int64_t now, int force);

/* helpers for reliable control queueing; call ack_sent immediately after queueing succeeds */
int quicly_flexicast_encode_pending_ack(quicly_flexicast_flow_t *flow, uint8_t *dst, size_t capacity, int64_t now,
                                        size_t *encoded_size);
void quicly_flexicast_ack_sent(quicly_flexicast_flow_t *flow);

/* records single-packet feedback from a member and retires older packets past the loss threshold */
int quicly_flexicast_ack(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete);
int quicly_flexicast_ack_at(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete, int64_t now);
/* applies all newly acknowledged packets in a decoded PATH_ACK (with ack_delay in msec) to one member */
int quicly_flexicast_ack_frame(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame,
                               size_t *num_acked, size_t *num_completed);
/* timed variant that also reports packets retired as lost */
int quicly_flexicast_ack_frame_at(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame,
                                  size_t *num_acked, size_t *num_lost, size_t *num_completed, int64_t now);
int quicly_flexicast_get_pending_members(const quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t *pending);
/* clears one member from a packet that could not be submitted locally without reporting network loss */
int quicly_flexicast_abandon_datagram(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete);

void quicly_flexicast_cc_set_flow_hints(quicly_flexicast_flow_t *flow, const quicly_flexicast_cc_hints_t *hints, int64_t now);
void quicly_flexicast_cc_on_flow_timeout(quicly_flexicast_flow_t *flow, int64_t now);
void quicly_flexicast_cc_get_flow_output(const quicly_flexicast_flow_t *flow, quicly_flexicast_cc_output_t *output);

/* optional bounded controller tracing */
int quicly_flexicast_cc_enable_flow_trace(quicly_flexicast_flow_t *flow, size_t capacity);
void quicly_flexicast_cc_disable_flow_trace(quicly_flexicast_flow_t *flow);
size_t quicly_flexicast_cc_read_flow_trace(quicly_flexicast_flow_t *flow, quicly_flexicast_cc_trace_event_t *events,
                                           size_t capacity, uint64_t *overwritten);

#ifdef __cplusplus
}
#endif

#endif
