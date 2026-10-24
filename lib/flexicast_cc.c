#include "flexicast_cc_internal.h"

#include <stdlib.h>
#include <string.h>

struct st_quicly_flexicast_cc_t {
    quicly_flexicast_cc_type_t *type;
    void *state;
    quicly_flexicast_cc_config_t config;
    quicly_flexicast_cc_hints_t hints;
    quicly_flexicast_cc_output_t output;
    struct {
        quicly_flexicast_cc_trace_event_t *events;
        size_t capacity;
        size_t head;
        size_t count;
        uint64_t sequence;
        uint64_t overwritten;
    } trace;
};

static int begin_trace(const quicly_flexicast_cc_t *cc, quicly_flexicast_cc_trace_event_t *event,
                       quicly_flexicast_cc_trace_type_t type, uint64_t member_id, int64_t now)
{
    if (cc->trace.events == NULL)
        return 0;
    memset(event, 0, sizeof(*event));
    event->now = now;
    event->type = type;
    event->member_id = member_id;
    event->rate_before = cc->output.rate_bytes_per_second;
    event->hints = cc->hints;
    if (cc->type->get_trace_state != NULL)
        cc->type->get_trace_state(cc->state, member_id, now, &event->state_before);
    return 1;
}

static void finish_trace(quicly_flexicast_cc_t *cc, quicly_flexicast_cc_trace_event_t *event)
{
    if (cc->trace.events == NULL)
        return;
    event->sequence = ++cc->trace.sequence;
    event->rate_after = cc->output.rate_bytes_per_second;
    event->reason = cc->output.reason;
    if (cc->type->get_trace_state != NULL)
        cc->type->get_trace_state(cc->state, event->member_id, event->now, &event->state_after);
    if (cc->trace.count == cc->trace.capacity) {
        cc->trace.head = (cc->trace.head + 1) % cc->trace.capacity;
        if (cc->trace.overwritten != UINT64_MAX)
            ++cc->trace.overwritten;
    } else {
        ++cc->trace.count;
    }
    size_t tail = (cc->trace.head + cc->trace.count - 1) % cc->trace.capacity;
    cc->trace.events[tail] = *event;
}

static void normalize_output(quicly_flexicast_cc_t *cc)
{
    cc->output.rate_bytes_per_second = clamp_rate(&cc->config, cc->output.rate_bytes_per_second);
    /* enforce the aggregate rate limit even if it is below the flow's preferred minimum */
    if (cc->hints.aggregate_rate_limit_bytes_per_second != 0 &&
        cc->output.rate_bytes_per_second > cc->hints.aggregate_rate_limit_bytes_per_second) {
        cc->output.rate_bytes_per_second = cc->hints.aggregate_rate_limit_bytes_per_second;
        cc->output.reason |= QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT;
    }
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
        ++cc->output.rate_reduction_events;
        cc->output.loss_reduction_events += (reason & QUICLY_FLEXICAST_CC_REASON_LOSS) != 0;
        cc->output.rtt_reduction_events += (reason & QUICLY_FLEXICAST_CC_REASON_RTT) != 0;
        cc->output.ecn_reduction_events += (reason & QUICLY_FLEXICAST_CC_REASON_ECN) != 0;
        cc->output.timeout_reduction_events += (reason & QUICLY_FLEXICAST_CC_REASON_TIMEOUT) != 0;
        cc->output.rate_limit_reduction_events += (reason & QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT) != 0;
        if ((reason & (QUICLY_FLEXICAST_CC_REASON_LOSS | QUICLY_FLEXICAST_CC_REASON_RTT | QUICLY_FLEXICAST_CC_REASON_ECN |
                       QUICLY_FLEXICAST_CC_REASON_TIMEOUT | QUICLY_FLEXICAST_CC_REASON_RATE_LIMIT)) == 0)
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

    if (cc == NULL || type == NULL || type->name == NULL || !valid_cc_config(config))
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
    if (new_cc->config.feedback_timeout_msec == 0)
        new_cc->config.feedback_timeout_msec = 1000;
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
    quicly_flexicast_cc_disable_trace(cc);
    free(cc->state);
    free(cc);
}

void quicly_flexicast_cc_on_member_added(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL || member_id == 0)
        return;
    quicly_flexicast_cc_trace_event_t trace_event;
    int tracing = begin_trace(cc, &trace_event, QUICLY_FLEXICAST_CC_TRACE_MEMBER_ADDED, member_id, now);
    previous_rate = cc->output.rate_bytes_per_second;
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (cc->type->on_member_added != NULL)
        cc->type->on_member_added(cc->state, member_id, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
    if (tracing)
        finish_trace(cc, &trace_event);
}

void quicly_flexicast_cc_on_member_removed(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL || member_id == 0)
        return;
    quicly_flexicast_cc_trace_event_t trace_event;
    int tracing = begin_trace(cc, &trace_event, QUICLY_FLEXICAST_CC_TRACE_MEMBER_REMOVED, member_id, now);
    previous_rate = cc->output.rate_bytes_per_second;
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (cc->type->on_member_removed != NULL)
        cc->type->on_member_removed(cc->state, member_id, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
    if (tracing)
        finish_trace(cc, &trace_event);
}

void quicly_flexicast_cc_on_member_suspended(quicly_flexicast_cc_t *cc, uint64_t member_id, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL || member_id == 0)
        return;
    previous_rate = cc->output.rate_bytes_per_second;
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (cc->type->on_member_suspended != NULL)
        cc->type->on_member_suspended(cc->state, member_id, now, &cc->output);
    else if (cc->type->on_member_removed != NULL)
        cc->type->on_member_removed(cc->state, member_id, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
}

void quicly_flexicast_cc_on_epoch_reset(quicly_flexicast_cc_t *cc, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL)
        return;
    quicly_flexicast_cc_trace_event_t trace_event;
    int tracing = begin_trace(cc, &trace_event, QUICLY_FLEXICAST_CC_TRACE_EPOCH_RESET, 0, now);
    previous_rate = cc->output.rate_bytes_per_second;
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (cc->type->on_epoch_reset != NULL)
        cc->type->on_epoch_reset(cc->state, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
    if (tracing)
        finish_trace(cc, &trace_event);
}

void quicly_flexicast_cc_on_feedback(quicly_flexicast_cc_t *cc, const quicly_flexicast_feedback_t *feedback)
{
    uint64_t previous_rate;
    if (cc == NULL || feedback == NULL || feedback->member_id == 0)
        return;
    quicly_flexicast_cc_trace_event_t trace_event;
    int tracing = begin_trace(cc, &trace_event, QUICLY_FLEXICAST_CC_TRACE_FEEDBACK, feedback->member_id, feedback->now);
    if (tracing)
        trace_event.feedback = *feedback;
    previous_rate = cc->output.rate_bytes_per_second;
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (cc->type->on_feedback != NULL)
        cc->type->on_feedback(cc->state, feedback, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
    if (tracing)
        finish_trace(cc, &trace_event);
}

void quicly_flexicast_cc_on_timeout(quicly_flexicast_cc_t *cc, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL)
        return;
    quicly_flexicast_cc_trace_event_t trace_event;
    int tracing = begin_trace(cc, &trace_event, QUICLY_FLEXICAST_CC_TRACE_TIMEOUT, 0, now);
    previous_rate = cc->output.rate_bytes_per_second;
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    if (cc->type->on_timeout != NULL)
        cc->type->on_timeout(cc->state, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
    if (tracing)
        finish_trace(cc, &trace_event);
}

void quicly_flexicast_cc_set_hints(quicly_flexicast_cc_t *cc, const quicly_flexicast_cc_hints_t *hints, int64_t now)
{
    uint64_t previous_rate;
    if (cc == NULL || hints == NULL)
        return;
    quicly_flexicast_cc_trace_event_t trace_event;
    int tracing = begin_trace(cc, &trace_event, QUICLY_FLEXICAST_CC_TRACE_HINTS, 0, now);
    if (tracing)
        trace_event.hints = *hints;
    previous_rate = cc->output.rate_bytes_per_second;
    cc->output.reason = QUICLY_FLEXICAST_CC_REASON_NONE;
    cc->hints = *hints;
    if (cc->type->set_hints != NULL)
        cc->type->set_hints(cc->state, &cc->hints, now, &cc->output);
    normalize_output(cc);
    record_transition(cc, previous_rate);
    if (tracing)
        finish_trace(cc, &trace_event);
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

int quicly_flexicast_cc_enable_trace(quicly_flexicast_cc_t *cc, size_t capacity)
{
    if (cc == NULL || capacity == 0 || capacity > QUICLY_FLEXICAST_CC_TRACE_MAX_CAPACITY)
        return -1;
    quicly_flexicast_cc_trace_event_t *events = calloc(capacity, sizeof(*events));
    if (events == NULL)
        return -1;
    quicly_flexicast_cc_disable_trace(cc);
    cc->trace.events = events;
    cc->trace.capacity = capacity;
    return 0;
}

void quicly_flexicast_cc_disable_trace(quicly_flexicast_cc_t *cc)
{
    if (cc == NULL)
        return;
    free(cc->trace.events);
    memset(&cc->trace, 0, sizeof(cc->trace));
}

size_t quicly_flexicast_cc_read_trace(quicly_flexicast_cc_t *cc, quicly_flexicast_cc_trace_event_t *events, size_t capacity,
                                      uint64_t *overwritten)
{
    if (overwritten != NULL)
        *overwritten = cc != NULL ? cc->trace.overwritten : 0;
    if (cc == NULL || events == NULL || capacity == 0)
        return 0;
    size_t count = capacity < cc->trace.count ? capacity : cc->trace.count;
    for (size_t i = 0; i != count; ++i)
        events[i] = cc->trace.events[(cc->trace.head + i) % cc->trace.capacity];
    if (count != 0) {
        cc->trace.head = (cc->trace.head + count) % cc->trace.capacity;
        cc->trace.count -= count;
    }
    return count;
}
