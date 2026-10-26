/* Internal state and packet hooks for the optional BBR controller. */
#ifndef quicly_cc_bbr_h
#define quicly_cc_bbr_h
#include "quicly/cc-bbr-sampler.h"
struct st_quicly_cc_t;
struct quicly_loss_t;

typedef struct st_quicly_cc_bbr_t {
    quicly_bbr_sampler_t sampler;
    quicly_bbr_cc_bbr engine;
    quicly_bbr_conn_stat stats;
    quicly_bbr_pcg32 random;
    quicly_bbr_packet_times_t ack_times;
    uint64_t event_time, ack_packet_id, ack_bytes, ack_largest_sent_at, pending_lost, last_lost_sent_at;
    uint64_t undo_pending, loss_first_pn, loss_last_pn, loss_first_sent_at, persistent_events;
    uint32_t undo_epoch;
    unsigned persistent_pending : 1;
    unsigned persistent_notified : 1;
    unsigned loss_run_valid : 1;
    unsigned rtt_sample_valid : 1;
    unsigned ack_times_valid : 1;
    unsigned loss_event_valid : 1;
} quicly_cc_bbr_t;

uint64_t quicly_bbr_time(double ms);
void quicly_bbr_configure(struct st_quicly_cc_t *cc, uint16_t mtu, double initial_rtt, uint32_t generation, double now);
void quicly_bbr_begin_ack(struct st_quicly_cc_t *cc, double now);
int quicly_bbr_packet_sent(struct st_quicly_cc_t *cc, quicly_bbr_packet_t *packet, uint16_t bytes, uint32_t inflight, uint64_t pn,
                           double now);
void quicly_bbr_packet_acked(struct st_quicly_cc_t *cc, quicly_bbr_packet_t *packet, uint64_t pn, double sent_at, double now);
void quicly_bbr_packet_lost(struct st_quicly_cc_t *cc, quicly_bbr_packet_meta_t *packet, uint64_t pn, double sent_at,
                            uint32_t inflight, double now);
uint32_t quicly_bbr_pacing_rate(struct st_quicly_cc_t *cc);
void quicly_bbr_set_app_limited(struct st_quicly_cc_t *cc, uint64_t inflight);
#endif
