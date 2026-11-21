#ifndef quicly_flexicast_h
#define quicly_flexicast_h

#include "quicly.h"
#include "quicly/flexicast_cc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* standalone multicast flow engine scoped to DATAGRAM, PING, and PADDING frames;
 * stream and control frames on multicast packets are rejected by design */

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

typedef struct st_quicly_flexicast_flow_t quicly_flexicast_flow_t;

typedef struct st_quicly_flexicast_config_t {
    /* 1..20 byte flexicast flow ID encoded verbatim as the multicast short-header DCID */
    quicly_flexicast_flow_id_t flow_id;
    /* initial egress PN and expected first ingress PN from FC_KEY */
    uint64_t first_packet_number;
    ptls_cipher_suite_t *cipher_suite;
    quicly_crypto_engine_t *crypto_engine;
    /* passed through to crypto-engine callbacks; NULL is allowed for default engine */
    quicly_conn_t *crypto_conn;
    ptls_iovec_t traffic_secret;
    /* maximum simultaneously known members; zero selects QUICLY_FLEXICAST_DEFAULT_MAX_MEMBERS */
    size_t max_members;
    /* optional borrowed multicast congestion controller; NULL keeps caller-owned pacing */
    quicly_flexicast_cc_t *cc;
    uint32_t ack_delay_msec;
    uint16_t ack_frequency;
    /* packet reordering threshold (< QUICLY_FLEXICAST_SENT_WINDOW); zero selects 3 */
    uint16_t packet_reordering_threshold;
    int64_t now;
    /* optional lower cryptographic usage limits; zero selects suite-specific QUIC defaults */
    uint64_t max_packets_per_key;
    uint64_t max_authentication_failures;
    /* maximum outgoing protected UDP payload in [1200, 65507]; zero selects 1200 */
    size_t max_packet_size;
    /* counts every ingress AEAD call including successes and replays; zero selects suite integrity limit */
    uint64_t max_decryption_attempts;
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

typedef struct st_quicly_flexicast_crypto_usage_t {
    uint64_t encrypted_packets, max_packets_per_key;
    uint64_t decryption_attempts, max_decryption_attempts;
    /* cumulative failure count across the entire flow */
    uint64_t authentication_failures, max_authentication_failures;
} quicly_flexicast_crypto_usage_t;

typedef struct st_quicly_flexicast_send_context_t {
    uint64_t pacing_rate_bytes_per_second;
    uint32_t physical_fanout;
    /* QUICLY_FLEXICAST_SAMPLE_VALID plus APP_LIMITED / HOST_LIMITED interval flags */
    uint32_t flags;
} quicly_flexicast_send_context_t;

typedef struct st_quicly_flexicast_decrypted_t {
    const uint8_t *src;
    const uint8_t *end;
    uint64_t packet_number;
    size_t num_datagrams;
} quicly_flexicast_decrypted_t;

int quicly_flexicast_flow_create(quicly_flexicast_flow_t **flow, const quicly_flexicast_config_t *config);
int quicly_flexicast_flow_rekey(quicly_flexicast_flow_t *flow, ptls_iovec_t traffic_secret, uint64_t first_packet_number,
                                int64_t now);
void quicly_flexicast_flow_free(quicly_flexicast_flow_t *flow);

const quicly_flexicast_flow_id_t *quicly_flexicast_get_flow_id(const quicly_flexicast_flow_t *flow);
uint64_t quicly_flexicast_get_next_packet_number(const quicly_flexicast_flow_t *flow);
int quicly_flexicast_flow_has_sender_state(const quicly_flexicast_flow_t *flow);

int quicly_flexicast_get_crypto_usage(const quicly_flexicast_flow_t *flow, quicly_flexicast_crypto_usage_t *usage);
int quicly_flexicast_set_decryption_attempts(quicly_flexicast_flow_t *flow, uint64_t attempts);
int quicly_flexicast_check_receive_floor(const quicly_flexicast_flow_t *flow, uint64_t next_unallocated);
int quicly_flexicast_install_receive_floor(quicly_flexicast_flow_t *flow, uint64_t next_unallocated);

/* member IDs are nonzero; attach is idempotent and reactivates known members after rekey */
int quicly_flexicast_attach(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
int quicly_flexicast_detach(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
int quicly_flexicast_suspend(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
int quicly_flexicast_resume(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
int quicly_flexicast_reset_member_path(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
int quicly_flexicast_note_member_feedback(quicly_flexicast_flow_t *flow, uint64_t member_id, int64_t now);
size_t quicly_flexicast_num_members(const quicly_flexicast_flow_t *flow);
int quicly_flexicast_get_member_stats(const quicly_flexicast_flow_t *flow, uint64_t member_id,
                                      quicly_flexicast_member_stats_t *stats);

size_t quicly_flexicast_datagram_size(const quicly_flexicast_flow_t *flow, size_t payload_size);
int quicly_flexicast_send_datagram(quicly_flexicast_flow_t *flow, ptls_iovec_t payload, uint8_t *packet, size_t packet_capacity,
                                   size_t *packet_size, uint64_t *packet_number, int64_t now);
int quicly_flexicast_mark_submitted(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int64_t now,
                                    const quicly_flexicast_send_context_t *context);

/* decrypts in place, validates all frames, commits receive state, and prepares zero-copy iteration */
int quicly_flexicast_receive_packet(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size,
                                    quicly_flexicast_decrypted_t *decrypted, uint8_t ecn, int64_t now);
/* yields 1 with the next DATAGRAM view, 0 at end of packet, or a negative error on invalid cursor */
int quicly_flexicast_next_datagram(quicly_flexicast_decrypted_t *decrypted, ptls_iovec_t *payload);

/* decrypts in place and outputs all DATAGRAM payload views; note that packet bytes are already decrypted in place on
 * BUFFER_TOO_SMALL, so callers with unknown frame counts should prefer quicly_flexicast_receive_packet + next_datagram */
int quicly_flexicast_receive_datagrams(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size, ptls_iovec_t *payloads,
                                       size_t *num_payloads, uint64_t *packet_number, uint8_t ecn, int64_t now);

static inline int quicly_flexicast_receive_datagram(quicly_flexicast_flow_t *flow, uint8_t *packet, size_t packet_size,
                                                    ptls_iovec_t *payload, uint64_t *packet_number, uint8_t ecn, int64_t now)
{
    if (payload == NULL)
        return QUICLY_FLEXICAST_ERROR_INVALID;
    size_t count = 1;
    int ret = quicly_flexicast_receive_datagrams(flow, packet, packet_size, payload, &count, packet_number, ecn, now);
    if (ret == 0 && count == 0)
        *payload = ptls_iovec_init(NULL, 0);
    return ret;
}

int64_t quicly_flexicast_get_ack_deadline(const quicly_flexicast_flow_t *flow);
int quicly_flexicast_ack_is_due(const quicly_flexicast_flow_t *flow, int64_t now);
int quicly_flexicast_send_pending_ack(quicly_flexicast_flow_t *flow, quicly_conn_t *conn, int64_t now, int force);
int quicly_flexicast_encode_pending_ack(quicly_flexicast_flow_t *flow, uint64_t ack_path_id, uint8_t *dst, size_t capacity,
                                        int64_t now, size_t *encoded_size);
void quicly_flexicast_ack_sent(quicly_flexicast_flow_t *flow);
int quicly_flexicast_get_receive_state(const quicly_flexicast_flow_t *flow, const quicly_range_t **ranges, size_t *num_ranges,
                                       uint64_t *history_lower_bound, int64_t *largest_received_at, uint64_t ecn_counts[3]);

#define QUICLY_FLEXICAST_ACK_OMIT_RTT 1u
#define QUICLY_FLEXICAST_ACK_OMIT_DELIVERY_RATE 2u
#define QUICLY_FLEXICAST_ACK_DEFER_LOSS 4u
#define QUICLY_FLEXICAST_ACK_ALLOW_INACTIVE 8u

int quicly_flexicast_ack_packet(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete,
                                int64_t now);
int quicly_flexicast_ack_frame(quicly_flexicast_flow_t *flow, uint64_t member_id, const quicly_ack_frame_t *frame, unsigned flags,
                               size_t *num_acked, size_t *num_lost, size_t *num_completed, int64_t now);
int quicly_flexicast_commit_ack_loss(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t coverage_lower_bound,
                                     uint64_t largest_received, size_t *num_lost, size_t *num_completed, int64_t now);

int quicly_flexicast_get_pending_members(const quicly_flexicast_flow_t *flow, uint64_t packet_number, size_t *pending);
int quicly_flexicast_abandon_datagram(quicly_flexicast_flow_t *flow, uint64_t member_id, uint64_t packet_number, int *complete);

void quicly_flexicast_cc_on_flow_timeout(quicly_flexicast_flow_t *flow, int64_t now);
void quicly_flexicast_cc_get_flow_output(const quicly_flexicast_flow_t *flow, quicly_flexicast_cc_output_t *output);

#ifdef __cplusplus
}
#endif

#endif
