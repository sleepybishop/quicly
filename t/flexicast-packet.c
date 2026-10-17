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
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/flexicast.h"
#include "quicly/frame.h"
#include "test.h"

static const uint64_t packet_flow_id = UINT64_C(0x1020304050607080);
static uint8_t packet_secret[32] = {1};

static quicly_flexicast_flow_t *packet_flow(uint64_t first_packet_number, size_t max_packet_size)
{
    quicly_flexicast_config_t config = {.flow_id = packet_flow_id,
                                       .first_packet_number = first_packet_number,
                                       .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                       .crypto_engine = &quicly_default_crypto_engine,
                                       .traffic_secret = {packet_secret, sizeof(packet_secret)},
                                       .max_packet_size = max_packet_size};
    quicly_flexicast_flow_t *flow = NULL;
    ok(quicly_flexicast_flow_create(&flow, &config) == 0);
    return flow;
}

/* Construct independent wire packets, without the Flexicast sender's fixed
 * packet-number width or DATAGRAM framing choices. */
static size_t protect_packet(uint8_t *packet, unsigned pn_length, uint64_t pn, uint8_t flags,
                             const uint8_t *plain, size_t plain_size)
{
    ptls_cipher_context_t *hp = NULL;
    ptls_aead_context_t *aead = NULL;
    int ret = quicly_default_crypto_engine.setup_cipher(&quicly_default_crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1,
                                                       &hp, &aead, ptls_openssl_aes128gcmsha256.aead,
                                                       ptls_openssl_aes128gcmsha256.hash, packet_secret);
    assert(ret == 0);
    packet[0] = QUICLY_QUIC_BIT | (pn_length - 1) | flags;
    quicly_encode64(packet + 1, packet_flow_id);
    for (unsigned i = 0; i != pn_length; ++i)
        packet[9 + i] = pn >> (8 * (pn_length - i - 1));
    size_t header_size = 9 + pn_length;
    size_t size = header_size + ptls_aead_encrypt(aead, packet + header_size, plain, plain_size, pn, packet, header_size);
    assert(size >= 13 + hp->algo->iv_size);
    uint8_t mask[5] = {0};
    ptls_cipher_init(hp, packet + 13);
    ptls_cipher_encrypt(hp, mask, mask, sizeof(mask));
    packet[0] ^= mask[0] & 0x1f;
    for (unsigned i = 0; i != pn_length; ++i)
        packet[9 + i] ^= mask[i + 1];
    ptls_cipher_free(hp);
    ptls_aead_free(aead);
    return size;
}

static void test_packet_layouts(void)
{
    static const uint8_t layouts[][16] = {
        {0x31, 4, 't', 'e', 's', 't'},
        {0x30, 't', 'e', 's', 't'},
        {0, 0x31, 4, 't', 'e', 's', 't'},
        {1, 0x31, 4, 't', 'e', 's', 't'},
        {0x31, 1, 'a', 0, 1, 0x30, 'b'},
        {0, 0x31, 0, 0x31, 0},
    };
    const size_t sizes[] = {6, 5, 7, 7, 7, 5};
    for (unsigned pn_length = 1; pn_length <= 4; ++pn_length) {
        /* Cross each truncated-number boundary with a nonzero epoch floor. */
        uint64_t first_pn = UINT64_C(1) << (pn_length * 8);
        quicly_flexicast_flow_t *flow = packet_flow(first_pn, 0);
        for (size_t i = 0; i != PTLS_ELEMENTSOF(layouts); ++i) {
            uint8_t packet[256], copy[256];
            size_t size = protect_packet(packet, pn_length, first_pn + i, 0, layouts[i], sizes[i]);
            memcpy(copy, packet, size);
            ptls_iovec_t payloads[2];
            size_t count = PTLS_ELEMENTSOF(payloads);
            uint64_t pn;
            ok(quicly_flexicast_receive_datagrams_at(flow, packet, size, payloads, &count, &pn, 10) == 0);
            ok(pn == first_pn + i);
            ok(count == (i < 4 ? 1 : 2));
            if (i < 4) {
                ok(payloads[0].len == 4 && memcmp(payloads[0].base, "test", 4) == 0);
            } else if (i == 4) {
                ok(payloads[0].len == 1 && *payloads[0].base == 'a');
                ok(payloads[1].len == 1 && *payloads[1].base == 'b');
            } else {
                ok(payloads[0].len == 0 && payloads[0].base != NULL);
                ok(payloads[1].len == 0 && payloads[1].base != NULL);
            }
            ok(payloads[0].base >= packet && payloads[0].base < packet + size);
            count = PTLS_ELEMENTSOF(payloads);
            ok(quicly_flexicast_receive_datagrams_at(flow, copy, size, payloads, &count, &pn, 11) ==
               QUICLY_FLEXICAST_ERROR_REPLAY);
        }
        quicly_flexicast_flow_free(flow);
    }
}

static void test_packet_atomicity(void)
{
    static const uint8_t two[] = {0x31, 1, 'a', 0x31, 1, 'b'};
    static const uint8_t truncated[] = {0x31, 1, 'a', 0x31, 8, 'b'};
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256];
    ptls_iovec_t payloads[2] = {{NULL, 99}, {NULL, 99}};
    uint64_t pn;
    size_t size = protect_packet(packet, 2, 0, 0, truncated, sizeof(truncated)), count = 2;
    ok(quicly_flexicast_receive_datagrams_at(flow, packet, size, payloads, &count, &pn, 10) ==
       QUICLY_FLEXICAST_ERROR_FRAME_ENCODING);
    ok(payloads[0].base == NULL && payloads[0].len == 99);
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    size = protect_packet(packet, 2, 0, 0, two, sizeof(two));
    ok(quicly_flexicast_receive_datagram_at(flow, packet, size, payloads, &pn, 10) ==
       QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL);
    ok(payloads[0].base == NULL && payloads[0].len == 99);
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    size = protect_packet(packet, 2, 0, 0, two, sizeof(two));
    count = 0;
    ok(quicly_flexicast_receive_datagrams_at(flow, packet, size, NULL, &count, &pn, 10) ==
       QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL);
    ok(count == 2);
    size = protect_packet(packet, 2, 0, 0, two, sizeof(two));
    count = 2;
    ok(quicly_flexicast_receive_datagrams_at(flow, packet, size, payloads, &count, &pn, 10) == 0);
    ok(count == 2 && pn == 0 && quicly_flexicast_ack_is_due(flow, 10));
    quicly_flexicast_flow_free(flow);
}

static void test_packet_errors(void)
{
    static const uint8_t data[] = {0x31, 4, 't', 'e', 's', 't'};
    static const uint64_t prohibited[] = {QUICLY_FRAME_TYPE_FC_ANNOUNCE, QUICLY_FRAME_TYPE_FC_STATE,
                                         QUICLY_FRAME_TYPE_FC_KEY, QUICLY_FRAME_TYPE_PATH_ACK,
                                         QUICLY_FRAME_TYPE_PATH_ACK_ECN, QUICLY_FRAME_TYPE_ACK};
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256];
    ptls_iovec_t payload;
    uint64_t pn;
    size_t size = protect_packet(packet, 2, 0, 8, data, sizeof(data));
    ok(quicly_flexicast_receive_datagram_at(flow, packet, size, &payload, &pn, 10) ==
       QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION);
    size = protect_packet(packet, 2, 0, 8, data, sizeof(data));
    packet[size - 1] ^= 1;
    ok(quicly_flexicast_receive_datagram_at(flow, packet, size, &payload, &pn, 10) == QUICLY_FLEXICAST_ERROR_CRYPTO);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(prohibited); ++i) {
        uint8_t plain[32] = {0};
        quicly_encodev(plain, prohibited[i]);
        size = protect_packet(packet, 2, 0, 0, plain, sizeof(plain));
        ok(quicly_flexicast_receive_datagram_at(flow, packet, size, &payload, &pn, 10) ==
           QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION);
    }
    size = protect_packet(packet, 4, 0, 0, data, 0);
    ok(quicly_flexicast_receive_datagram_at(flow, packet, size, &payload, &pn, 10) ==
       QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION);
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    size = protect_packet(packet, 2, 0, 0, data, sizeof(data));
    ok(quicly_flexicast_receive_datagram_at(flow, packet, size, &payload, &pn, 10) == 0);
    quicly_flexicast_flow_free(flow);
}

static void test_packet_ack_elicitation(void)
{
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256], padding[4] = {0}, ping[4] = {1};
    uint64_t pn;
    ptls_iovec_t payload;
    size_t size = protect_packet(packet, 2, 0, 0, padding, sizeof(padding));
    ok(quicly_flexicast_receive_datagram_at(flow, packet, size, &payload, &pn, 10) == 0);
    ok(payload.base == NULL && payload.len == 0);
    ok(!quicly_flexicast_ack_is_due(flow, 1000));
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    size = protect_packet(packet, 2, 1, 0, ping, sizeof(ping));
    size_t count = 0;
    ok(quicly_flexicast_receive_datagrams_at(flow, packet, size, NULL, &count, &pn, 20) == 0);
    ok(count == 0 && quicly_flexicast_ack_is_due(flow, 20));
    quicly_flexicast_flow_free(flow);
}

static void test_packet_size_limits(void)
{
    const size_t limits[] = {1200, 1500, QUICLY_FLEXICAST_MAX_PACKET_SIZE};
    uint8_t *payload = calloc(1, QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE);
    uint8_t *packet = malloc(QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE + 64);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(limits); ++i) {
        quicly_flexicast_flow_t *flow = packet_flow(0, i == 0 ? 0 : limits[i]);
        ok(quicly_flexicast_attach(flow, 1) == 0);
        size_t payload_size = limits[i] - 27 - (i == 2 ? 5 : 3), size;
        uint64_t pn;
        ok(quicly_flexicast_datagram_size(flow, payload_size) == limits[i]);
        ok(quicly_flexicast_datagram_size(flow, payload_size + 1) == 0);
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, payload_size + 1), packet,
                                         QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE + 64, &size, &pn) ==
           QUICLY_FLEXICAST_ERROR_INVALID);
        ok(quicly_flexicast_get_next_packet_number(flow) == 0);
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, payload_size), packet,
                                         QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE + 64, &size, &pn) == 0);
        ok(size == limits[i] && pn == 0);
        quicly_flexicast_flow_free(flow);
    }
    free(payload);
    free(packet);
}

static void test_padding_history_bound(void)
{
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256], plain[4] = {0}, encoded[QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE];
    uint64_t pn;
    size_t count, size, encoded_size;
    const unsigned num_padding = QUICLY_FLEXICAST_SENT_WINDOW + 8;
    int received = 1;
    for (unsigned i = 0; i != num_padding; ++i) {
        size = protect_packet(packet, 2, i * 2, 0, plain, sizeof(plain));
        count = 0;
        received &= quicly_flexicast_receive_datagrams_at(flow, packet, size, NULL, &count, &pn, i) == 0;
    }
    ok(received);
    ok(!quicly_flexicast_ack_is_due(flow, num_padding + 100));
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    plain[0] = QUICLY_FRAME_TYPE_PING;
    size = protect_packet(packet, 2, num_padding * 2, 0, plain, sizeof(plain));
    count = 0;
    ok(quicly_flexicast_receive_datagrams_at(flow, packet, size, NULL, &count, &pn, num_padding) == 0);
    size_t ranges = 0, batches = 0;
    uint64_t smallest = UINT64_MAX, largest = 0;
    while (quicly_flexicast_ack_is_due(flow, num_padding) && batches <= QUICLY_FLEXICAST_SENT_WINDOW / QUICLY_MAX_ACK_BLOCKS) {
        ok(quicly_flexicast_encode_pending_ack(flow, encoded, sizeof(encoded), num_padding, &encoded_size) == 0);
        const uint8_t *src = encoded, *end = src + encoded_size;
        ok(quicly_decodev(&src, end) == QUICLY_FRAME_TYPE_PATH_ACK);
        ok(quicly_decodev(&src, end) == packet_flow_id);
        quicly_ack_frame_t ack;
        ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
        if (batches == 0)
            smallest = ack.smallest_acknowledged;
        largest = ack.largest_acknowledged;
        ranges += ack.num_gaps + 1;
        ++batches;
        quicly_flexicast_ack_sent(flow);
    }
    ok(ranges == QUICLY_FLEXICAST_SENT_WINDOW);
    ok(smallest == 18 && largest == num_padding * 2);
    ok(!quicly_flexicast_ack_is_due(flow, num_padding));
    quicly_flexicast_flow_free(flow);
}

void test_flexicast_packets(void)
{
    subtest("packet-layouts", test_packet_layouts);
    subtest("packet-atomicity", test_packet_atomicity);
    subtest("packet-errors", test_packet_errors);
    subtest("packet-ack-elicitation", test_packet_ack_elicitation);
    subtest("packet-size-limits", test_packet_size_limits);
    subtest("padding-history-bound", test_padding_history_bound);
}
