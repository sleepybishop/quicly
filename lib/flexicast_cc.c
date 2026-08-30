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
#include "quicly/flexicast_cc.h"

#include <stdlib.h>
#include <string.h>

struct st_quicly_flexicast_cc_t {
    quicly_flexicast_cc_type_t *type;
    void *state;
    quicly_flexicast_cc_config_t config;
    quicly_flexicast_cc_hints_t hints;
    quicly_flexicast_cc_output_t output;
};

static uint64_t clamp_rate(const quicly_flexicast_cc_config_t *config, uint64_t rate)
{
    if (rate < config->minimum_rate_bytes_per_second)
        rate = config->minimum_rate_bytes_per_second;
    if (config->maximum_rate_bytes_per_second != 0 && rate > config->maximum_rate_bytes_per_second)
        rate = config->maximum_rate_bytes_per_second;
    return rate;
}

static void normalize_output(quicly_flexicast_cc_t *cc)
{
    cc->output.rate_bytes_per_second = clamp_rate(&cc->config, cc->output.rate_bytes_per_second);
    if (cc->output.burst_bytes == 0)
        cc->output.burst_bytes = (uint64_t)cc->config.maximum_datagram_size * 4;
    if (cc->output.burst_bytes < cc->config.maximum_datagram_size)
        cc->output.burst_bytes = cc->config.maximum_datagram_size;
}

static void record_transition(quicly_flexicast_cc_t *cc, uint64_t previous_rate)
{
    uint64_t rate = cc->output.rate_bytes_per_second;
    uint32_t reason = cc->output.reason;
    int previous_at_floor = previous_rate <= cc->config.minimum_rate_bytes_per_second;
    int at_floor = rate <= cc->config.minimum_rate_bytes_per_second;

    if (rate > previous_rate) {
        ++cc->output.rate_increase_events;
        if ((reason & QUICLY_FLEXICAST_CC_REASON_ACK) != 0)
            ++cc->output.ack_growth_events;
        else
            ++cc->output.other_growth_events;
    } else if (rate < previous_rate) {
        int classified = 0;
        ++cc->output.rate_reduction_events;
#define COUNT_REDUCTION(reason_bit, counter)                                                                                       \
    do {                                                                                                                           \
        if ((reason & (reason_bit)) != 0) {                                                                                        \
            ++cc->output.counter;                                                                                                  \
            classified = 1;                                                                                                        \
        }                                                                                                                          \
    } while (0)
        COUNT_REDUCTION(QUICLY_FLEXICAST_CC_REASON_LOSS, loss_reduction_events);
        COUNT_REDUCTION(QUICLY_FLEXICAST_CC_REASON_RTT, rtt_reduction_events);
        COUNT_REDUCTION(QUICLY_FLEXICAST_CC_REASON_ECN, ecn_reduction_events);
        COUNT_REDUCTION(QUICLY_FLEXICAST_CC_REASON_TIMEOUT, timeout_reduction_events);
        COUNT_REDUCTION(QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT, rate_limit_reduction_events);
#undef COUNT_REDUCTION
        if (!classified)
            ++cc->output.other_reduction_events;
    }
    if (!previous_at_floor && at_floor)
        ++cc->output.floor_entry_events;
    else if (previous_at_floor && !at_floor)
        ++cc->output.floor_exit_events;
    if ((reason & (QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD | QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN)) ==
        (QUICLY_FLEXICAST_CC_REASON_EXTERNAL_LOAD | QUICLY_FLEXICAST_CC_REASON_GROWTH_FROZEN))
        ++cc->output.external_load_growth_freeze_events;
}

int quicly_flexicast_cc_create(quicly_flexicast_cc_t **cc, quicly_flexicast_cc_type_t *type,
                               const quicly_flexicast_cc_config_t *config, int64_t now)
{
    quicly_flexicast_cc_t *new_cc;

    if (cc == NULL || type == NULL || type->name == NULL || config == NULL || config->maximum_datagram_size == 0 ||
        config->maximum_members > QUICLY_FLEXICAST_CC_HARD_MAX_MEMBERS)
        return -1;
    *cc = NULL;
    if ((new_cc = calloc(1, sizeof(*new_cc))) == NULL)
        return -1;
    if (type->state_size != 0 && (new_cc->state = calloc(1, type->state_size)) == NULL) {
        free(new_cc);
        return -1;
    }
    new_cc->type = type;
    new_cc->config = *config;
    if (new_cc->config.maximum_members == 0)
        new_cc->config.maximum_members = QUICLY_FLEXICAST_CC_DEFAULT_MAX_MEMBERS;
    new_cc->output.rate_bytes_per_second = config->startup_rate_bytes_per_second;
    new_cc->output.burst_bytes = (uint64_t)config->maximum_datagram_size * 4;
    new_cc->output.next_timeout = INT64_MAX;
    if (type->init != NULL && type->init(new_cc->state, &new_cc->config, now, &new_cc->output) != 0) {
        quicly_flexicast_cc_free(new_cc);
        return -1;
    }
    normalize_output(new_cc);
    *cc = new_cc;
    return 0;
}

void quicly_flexicast_cc_free(quicly_flexicast_cc_t *cc)
{
    if (cc == NULL)
        return;
    if (cc->type->dispose != NULL)
        cc->type->dispose(cc->state);
    free(cc->state);
    memset(cc, 0, sizeof(*cc));
    free(cc);
}

void quicly_flexicast_cc_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL || member_id == 0)
        return;
    previous_rate = cc->output.rate_bytes_per_second;
    if (cc->type->on_member_added != NULL)
        cc->type->on_member_added(cc->state, member_id, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
}

void quicly_flexicast_cc_on_member_removed(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL || member_id == 0)
        return;
    previous_rate = cc->output.rate_bytes_per_second;
    if (cc->type->on_member_removed != NULL)
        cc->type->on_member_removed(cc->state, member_id, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
}

void quicly_flexicast_cc_on_epoch_reset(quicly_flexicast_cc_t *cc, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL)
        return;
    previous_rate = cc->output.rate_bytes_per_second;
    if (cc->type->on_epoch_reset != NULL)
        cc->type->on_epoch_reset(cc->state, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
}

void quicly_flexicast_cc_on_feedback(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback)
{
    uint64_t previous_rate;
    if (cc == NULL || feedback == NULL)
        return;
    previous_rate = cc->output.rate_bytes_per_second;
    if (cc->type->on_feedback != NULL)
        cc->type->on_feedback(cc->state, feedback, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
}

void quicly_flexicast_cc_on_timeout(quicly_flexicast_cc_t *cc, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL)
        return;
    previous_rate = cc->output.rate_bytes_per_second;
    if (cc->type->on_timeout != NULL)
        cc->type->on_timeout(cc->state, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
}

void quicly_flexicast_cc_set_hints(quicly_flexicast_cc_t *cc, const quicly_flexicast_cc_hints_t *hints, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL || hints == NULL)
        return;
    previous_rate = cc->output.rate_bytes_per_second;
    cc->hints = *hints;
    if (cc->type->set_hints != NULL)
        cc->type->set_hints(cc->state, &cc->hints, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
}

void quicly_flexicast_cc_get_output(const quicly_flexicast_cc_t *cc, quicly_flexicast_cc_output_t *output)
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

quicly_flexicast_cc_type_t *quicly_flexicast_cc_get_type(const quicly_flexicast_cc_t *cc)
{
    return cc != NULL ? cc->type : NULL;
}
