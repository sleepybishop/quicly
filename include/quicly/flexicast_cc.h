#ifndef quicly_flexicast_cc_h
#define quicly_flexicast_cc_h

#include "quicly/constants.h"
#if !QUICLY_HAVE_FLEXICAST
#error "flexicast support is disabled in this build"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct st_quicly_flexicast_cc_t quicly_flexicast_cc_t;
typedef const struct st_quicly_flexicast_cc_type_t quicly_flexicast_cc_type_t;

#define QUICLY_FLEXICAST_CC_DEFAULT_MAX_MEMBERS 64
#define QUICLY_FLEXICAST_CC_HARD_MAX_MEMBERS 16384

typedef struct st_quicly_flexicast_cc_config_t {
    /* member capacity reserved by the controller; zero selects default */
    size_t maximum_members;
    uint64_t startup_rate_bytes_per_second;
    uint64_t minimum_rate_bytes_per_second;
    /* zero means unlimited; otherwise at least minimum_rate_bytes_per_second */
    uint64_t maximum_rate_bytes_per_second;
    uint32_t maximum_datagram_size;
    /* zero selects 1000 milliseconds */
    uint32_t feedback_timeout_msec;
} quicly_flexicast_cc_config_t;

#define QUICLY_FLEXICAST_SAMPLE_VALID 0x01U
#define QUICLY_FLEXICAST_SAMPLE_APP_LIMITED 0x02U
#define QUICLY_FLEXICAST_SAMPLE_HOST_LIMITED 0x04U
#define QUICLY_FLEXICAST_SAMPLE_MIXED 0x08U

#define QUICLY_FLEXICAST_RTT_VALID 0x01U
#define QUICLY_FLEXICAST_RTT_ACK_DELAY_INCONSISTENT 0x02U

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
    /* identifies completed delivery-rate sample; zero when unavailable */
    uint64_t delivery_rate_sample_epoch;
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
    /* independent RTT sample provenance, updated when largest_acknowledged is newly ACKed */
    uint64_t rtt_sample_epoch;
    int64_t rtt_sample_at;
    uint32_t raw_rtt_msec;
    uint32_t rtt_ack_delay_msec;
    uint32_t applied_ack_delay_msec;
    uint32_t rtt_sample_flags;
    int64_t now;
    /* post-retirement pending packet state for this member when pending_valid is non-zero */
    uint64_t oldest_pending_pn;
    int64_t oldest_pending_sent_at;
    uint8_t pending_valid;
    uint8_t has_pending;
} quicly_flexicast_feedback_t;

#define QUICLY_FLEXICAST_CC_REASON_NONE 0U
#define QUICLY_FLEXICAST_CC_REASON_ACK 0x01U
#define QUICLY_FLEXICAST_CC_REASON_LOSS 0x02U
#define QUICLY_FLEXICAST_CC_REASON_ECN 0x04U
#define QUICLY_FLEXICAST_CC_REASON_TIMEOUT 0x08U
#define QUICLY_FLEXICAST_CC_REASON_RTT 0x10U

typedef struct st_quicly_flexicast_cc_output_t {
    uint64_t rate_bytes_per_second;
    uint64_t burst_bytes;
    uint64_t inflight_bytes;
    uint64_t limiting_member_id;
    int64_t next_timeout;
    uint32_t reason;
} quicly_flexicast_cc_output_t;

struct st_quicly_flexicast_cc_type_t {
    const char *name;
    int (*on_member_added)(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
    void (*on_member_removed)(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
    void (*on_member_suspended)(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now);
    void (*on_epoch_reset)(quicly_flexicast_cc_t *cc, int64_t now);
    void (*on_packet_sent)(quicly_flexicast_cc_t *cc, uint64_t packet_number, size_t packet_size, int64_t now);
    void (*on_feedback)(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback);
    void (*on_timeout)(quicly_flexicast_cc_t *cc, int64_t now);
    void (*on_member_pending_updated)(quicly_flexicast_cc_t *cc, uint64_t member_id, int has_pending, uint64_t oldest_pending_pn,
                                      int64_t oldest_sent_at, int64_t now);
};

struct st_quicly_flexicast_cc_t {
    quicly_flexicast_cc_type_t *type;
    /* flow instance currently attached to this controller; NULL when unbound */
    void *bound_flow;
    quicly_flexicast_cc_config_t config;
    quicly_flexicast_cc_output_t output;
};

/* creates a built-in multicast congestion controller; destroy with quicly_flexicast_cc_free_multicast */
quicly_flexicast_cc_t *quicly_flexicast_cc_new_multicast(const quicly_flexicast_cc_config_t *config, int64_t now);
void quicly_flexicast_cc_free_multicast(quicly_flexicast_cc_t *cc);

static inline uint64_t quicly_flexicast_cc_clamp_rate(const quicly_flexicast_cc_config_t *config, uint64_t rate)
{
    if (rate < config->minimum_rate_bytes_per_second)
        rate = config->minimum_rate_bytes_per_second;
    if (config->maximum_rate_bytes_per_second != 0 && rate > config->maximum_rate_bytes_per_second)
        rate = config->maximum_rate_bytes_per_second;
    return rate;
}

static inline void quicly_flexicast_cc_normalize_output(quicly_flexicast_cc_t *cc)
{
    uint64_t min_burst = (uint64_t)cc->config.maximum_datagram_size * 4;
    uint64_t max_burst = (uint64_t)cc->config.maximum_datagram_size * 10;

    cc->output.rate_bytes_per_second = quicly_flexicast_cc_clamp_rate(&cc->config, cc->output.rate_bytes_per_second);
    if (cc->output.burst_bytes < min_burst) {
        uint64_t burst = cc->output.rate_bytes_per_second / 20;
        cc->output.burst_bytes = burst < min_burst ? min_burst : burst > max_burst ? max_burst : burst;
    }
    if (cc->output.inflight_bytes < min_burst) {
        uint64_t inflight = cc->output.rate_bytes_per_second / 10;
        cc->output.inflight_bytes = inflight < min_burst ? min_burst : inflight;
    }
}

static inline int quicly_flexicast_cc_init(quicly_flexicast_cc_t *cc, quicly_flexicast_cc_type_t *type,
                                           const quicly_flexicast_cc_config_t *config)
{
    quicly_flexicast_cc_config_t normalized;

    if (cc == NULL || type == NULL || config == NULL)
        return -1;
    normalized = *config;
    if (normalized.maximum_members == 0)
        normalized.maximum_members = QUICLY_FLEXICAST_CC_DEFAULT_MAX_MEMBERS;
    if (normalized.maximum_datagram_size == 0)
        normalized.maximum_datagram_size = 1200;
    if (normalized.startup_rate_bytes_per_second == 0)
        normalized.startup_rate_bytes_per_second = 64 * 1024;
    if (normalized.minimum_rate_bytes_per_second == 0)
        normalized.minimum_rate_bytes_per_second = 2 * 1024;
    if (normalized.feedback_timeout_msec == 0)
        normalized.feedback_timeout_msec = 1000;
    if (normalized.maximum_members > QUICLY_FLEXICAST_CC_HARD_MAX_MEMBERS ||
        (normalized.maximum_rate_bytes_per_second != 0 &&
         normalized.maximum_rate_bytes_per_second < normalized.minimum_rate_bytes_per_second))
        return -1;

    memset(cc, 0, sizeof(*cc));
    cc->type = type;
    cc->config = normalized;
    cc->output.rate_bytes_per_second = normalized.startup_rate_bytes_per_second;
    cc->output.next_timeout = INT64_MAX;
    quicly_flexicast_cc_normalize_output(cc);
    return 0;
}

static inline int quicly_flexicast_cc_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    if (cc == NULL)
        return 0;
    if (member_id == 0)
        return -1;
    if (cc->type->on_member_added != NULL) {
        int ret = cc->type->on_member_added(cc, member_id, now);
        quicly_flexicast_cc_normalize_output(cc);
        return ret;
    }
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    return 0;
}

static inline void quicly_flexicast_cc_on_member_removed(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    if (cc == NULL || member_id == 0)
        return;
    if (cc->type->on_member_removed != NULL) {
        cc->type->on_member_removed(cc, member_id, now);
        quicly_flexicast_cc_normalize_output(cc);
    } else {
        cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    }
}

static inline void quicly_flexicast_cc_on_member_suspended(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    if (cc == NULL || member_id == 0)
        return;
    if (cc->type->on_member_suspended != NULL) {
        cc->type->on_member_suspended(cc, member_id, now);
        quicly_flexicast_cc_normalize_output(cc);
    } else if (cc->type->on_member_removed != NULL) {
        cc->type->on_member_removed(cc, member_id, now);
        quicly_flexicast_cc_normalize_output(cc);
    } else {
        cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    }
}

static inline void quicly_flexicast_cc_on_epoch_reset(quicly_flexicast_cc_t *cc, int64_t now)
{
    if (cc == NULL)
        return;
    if (cc->type->on_epoch_reset != NULL) {
        cc->type->on_epoch_reset(cc, now);
        quicly_flexicast_cc_normalize_output(cc);
    } else {
        cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    }
}

static inline void quicly_flexicast_cc_on_packet_sent(quicly_flexicast_cc_t *cc, uint64_t packet_number, size_t packet_size,
                                                      int64_t now)
{
    if (cc == NULL)
        return;
    if (cc->type->on_packet_sent != NULL) {
        cc->type->on_packet_sent(cc, packet_number, packet_size, now);
        quicly_flexicast_cc_normalize_output(cc);
    }
}

static inline void quicly_flexicast_cc_on_member_pending_updated(quicly_flexicast_cc_t *cc, uint64_t member_id, int has_pending,
                                                                 uint64_t oldest_pending_pn, int64_t oldest_sent_at, int64_t now)
{
    if (cc == NULL)
        return;
    if (cc->type->on_member_pending_updated != NULL) {
        cc->type->on_member_pending_updated(cc, member_id, has_pending, oldest_pending_pn, oldest_sent_at, now);
        quicly_flexicast_cc_normalize_output(cc);
    }
}

static inline void quicly_flexicast_cc_on_feedback(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback)
{
    if (cc == NULL || feedback == NULL || feedback->member_id == 0)
        return;
    if (cc->type->on_feedback != NULL) {
        cc->type->on_feedback(cc, feedback);
        quicly_flexicast_cc_normalize_output(cc);
    } else {
        cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    }
}

static inline void quicly_flexicast_cc_on_timeout(quicly_flexicast_cc_t *cc, int64_t now)
{
    if (cc == NULL)
        return;
    if (cc->type->on_timeout != NULL) {
        cc->type->on_timeout(cc, now);
        quicly_flexicast_cc_normalize_output(cc);
    } else {
        cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    }
}

static inline void quicly_flexicast_cc_get_output(const quicly_flexicast_cc_t *cc, quicly_flexicast_cc_output_t *output)
{
    if (output == NULL)
        return;
    if (cc == NULL) {
        memset(output, 0, sizeof(*output));
        output->next_timeout = INT64_MAX;
        return;
    }
    *output = cc->output;
}

#ifdef __cplusplus
}
#endif

#endif
