/* Packet delivery sampling for the optional BBR controller. */
#ifndef quicly_cc_bbr_sampler_h
#define quicly_cc_bbr_sampler_h
#include "quicly/cc-bbr-engine.h"
#define QUICLY_BBR_PACKET_ACKED 1U
#define QUICLY_BBR_PACKET_LOST 2U

/* Each half fits one 24-byte sentmap payload. Keep snapshots until ACK or
 * expiry, including after a loss declaration, to support late acknowledgments. */
typedef struct st_quicly_bbr_packet_times_t {
    uint64_t delivered, delivered_at, first_sent_at;
} quicly_bbr_packet_times_t;
typedef struct st_quicly_bbr_packet_meta_t {
    uint64_t lost;
    uint32_t inflight, generation;
    uint16_t bytes;
    uint8_t app_limited, flags;
    uint32_t loss_epoch;
} quicly_bbr_packet_meta_t;
typedef struct st_quicly_bbr_packet_t {
    quicly_bbr_packet_times_t times;
    quicly_bbr_packet_meta_t meta;
} quicly_bbr_packet_t;
typedef struct st_quicly_bbr_sampler_t {
    quicly_bbr_rst rst;
    uint64_t selected_lost;
    uint32_t generation;
} quicly_bbr_sampler_t;

void quicly_bbr_sampler_init(quicly_bbr_sampler_t *sampler, uint32_t generation);
void quicly_bbr_sampler_begin_ack(quicly_bbr_sampler_t *sampler);
int quicly_bbr_sampler_on_sent(quicly_bbr_sampler_t *sampler, quicly_bbr_packet_t *packet, uint16_t bytes, uint32_t inflight,
                               uint64_t packet_id, uint64_t now);
int quicly_bbr_sampler_on_ack(quicly_bbr_sampler_t *sampler, quicly_bbr_packet_t *packet, uint64_t packet_id, uint64_t sent_at,
                              uint64_t now);
int quicly_bbr_sampler_on_lost(quicly_bbr_sampler_t *sampler, quicly_bbr_packet_meta_t *packet);
void quicly_bbr_sampler_finish_ack(quicly_bbr_sampler_t *sampler, quicly_bbr_conn_stat *stats);
void quicly_bbr_sampler_app_limited(quicly_bbr_sampler_t *sampler, uint64_t inflight);
#endif
