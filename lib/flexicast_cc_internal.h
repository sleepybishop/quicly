#ifndef flexicast_cc_internal_h
#define flexicast_cc_internal_h

#include "quicly/flexicast_cc.h"

static inline int valid_cc_config(const quicly_flexicast_cc_config_t *config)
{
    return config != NULL && config->maximum_datagram_size != 0 &&
           config->maximum_members <= QUICLY_FLEXICAST_CC_HARD_MAX_MEMBERS &&
           (config->maximum_rate_bytes_per_second == 0 ||
            config->maximum_rate_bytes_per_second >= config->minimum_rate_bytes_per_second);
}

static inline uint64_t clamp_rate(const quicly_flexicast_cc_config_t *config, uint64_t rate)
{
    if (rate < config->minimum_rate_bytes_per_second)
        rate = config->minimum_rate_bytes_per_second;
    if (config->maximum_rate_bytes_per_second != 0 && rate > config->maximum_rate_bytes_per_second)
        rate = config->maximum_rate_bytes_per_second;
    return rate;
}

static inline uint64_t burst_size(const quicly_flexicast_cc_config_t *config, uint64_t rate)
{
    uint64_t minimum = (uint64_t)config->maximum_datagram_size * 4;
    uint64_t maximum = (uint64_t)config->maximum_datagram_size * 10;
    uint64_t burst = rate / 20;
    return burst < minimum ? minimum : burst > maximum ? maximum : burst;
}

/* scale down without overflowing the intermediate product (numerator <= denominator) */
static inline uint64_t scale_rate(uint64_t rate, uint32_t numerator, uint32_t denominator)
{
    return rate / denominator * numerator + rate % denominator * numerator / denominator;
}

static inline uint64_t increase_rate(uint64_t rate, uint64_t increase)
{
    return UINT64_MAX - rate < increase ? UINT64_MAX : rate + increase;
}

static inline int queue_delay_grew(uint32_t minimum_rtt, uint32_t latest_rtt)
{
    uint32_t margin = minimum_rtt / 4;
    if (margin < 5)
        margin = 5;
    return minimum_rtt != 0 && (uint64_t)latest_rtt > (uint64_t)minimum_rtt + margin;
}

#endif
