#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/flexicast.h"
#include "quicly/frame.h"
#include "test.h"

static const uint8_t packet_flow_bytes[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
static uint8_t packet_secret[32] = {1};

static quicly_flexicast_flow_id_t default_packet_flow_id(void)
{
    return quicly_flexicast_flow_id_init(packet_flow_bytes, sizeof(packet_flow_bytes));
}

static quicly_flexicast_flow_t *packet_flow_with_id(quicly_flexicast_flow_id_t flow_id, uint64_t first_packet_number,
                                                    size_t max_packet_size)
{
    quicly_flexicast_config_t config = {.flow_id = flow_id,
                                        .first_packet_number = first_packet_number,
                                        .cipher_suite = &ptls_openssl_aes128gcmsha256,
                                        .crypto_engine = &quicly_default_crypto_engine,
                                        .traffic_secret = {packet_secret, sizeof(packet_secret)},
                                        .max_packet_size = max_packet_size};
    quicly_flexicast_flow_t *flow = NULL;
    ok(quicly_flexicast_flow_create(&flow, &config) == 0);
    return flow;
}

static quicly_flexicast_flow_t *packet_flow(uint64_t first_packet_number, size_t max_packet_size)
{
    return packet_flow_with_id(default_packet_flow_id(), first_packet_number, max_packet_size);
}

/* construct independent wire packets for arbitrary flow_id lengths */
static size_t protect_packet_id(const quicly_flexicast_flow_id_t *flow_id, uint8_t *packet, unsigned pn_length, uint64_t pn,
                                uint8_t flags, const uint8_t *plain, size_t plain_size)
{
    ptls_cipher_context_t *hp = NULL;
    ptls_aead_context_t *aead = NULL;
    int ret = quicly_default_crypto_engine.setup_cipher(&quicly_default_crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1, &hp, &aead,
                                                        ptls_openssl_aes128gcmsha256.aead, ptls_openssl_aes128gcmsha256.hash,
                                                        packet_secret);
    assert(ret == 0);
    size_t pn_offset = 1 + flow_id->len;
    packet[0] = QUICLY_QUIC_BIT | (pn_length - 1) | flags;
    memcpy(packet + 1, flow_id->bytes, flow_id->len);
    for (unsigned i = 0; i != pn_length; ++i)
        packet[pn_offset + i] = pn >> (8 * (pn_length - i - 1));
    size_t header_size = pn_offset + pn_length;
    size_t size = header_size + ptls_aead_encrypt(aead, packet + header_size, plain, plain_size, pn, packet, header_size);
    assert(size >= pn_offset + QUICLY_MAX_PN_SIZE + hp->algo->iv_size);
    uint8_t mask[5] = {0};
    ptls_cipher_init(hp, packet + pn_offset + QUICLY_MAX_PN_SIZE);
    ptls_cipher_encrypt(hp, mask, mask, sizeof(mask));
    packet[0] ^= mask[0] & 0x1f;
    for (unsigned i = 0; i != pn_length; ++i)
        packet[pn_offset + i] ^= mask[i + 1];
    ptls_cipher_free(hp);
    ptls_aead_free(aead);
    return size;
}

static size_t protect_packet(uint8_t *packet, unsigned pn_length, uint64_t pn, uint8_t flags, const uint8_t *plain,
                             size_t plain_size)
{
    quicly_flexicast_flow_id_t fid = default_packet_flow_id();
    return protect_packet_id(&fid, packet, pn_length, pn, flags, plain, plain_size);
}

static void test_wire_flow_id_lengths(void)
{
    static const uint8_t lengths[] = {1, 4, 8, 20};
    static const uint8_t payload[] = "wire-fid";
    for (size_t i = 0; i != PTLS_ELEMENTSOF(lengths); ++i) {
        uint8_t raw[QUICLY_FLEXICAST_MAX_FLOW_ID_SIZE];
        for (uint8_t b = 0; b != lengths[i]; ++b)
            raw[b] = (uint8_t)(0xc0 + b); /* exercise high bits above PTLS_QUICINT_MAX */
        quicly_flexicast_flow_id_t fid = quicly_flexicast_flow_id_init(raw, lengths[i]);
        quicly_flexicast_flow_t *tx = packet_flow_with_id(fid, 10, 0);
        quicly_flexicast_flow_t *rx = packet_flow_with_id(fid, 10, 0);
        ok(quicly_flexicast_flow_id_equal(quicly_flexicast_get_flow_id(tx), &fid));
        ok(quicly_flexicast_attach(tx, 1, 0) == 0);
        uint8_t packet[256];
        size_t size;
        uint64_t pn;
        ok(quicly_flexicast_send_datagram(tx, ptls_iovec_init(payload, sizeof(payload)), packet, sizeof(packet), &size, &pn, 0) ==
           0);
        /* verify advertised flow_id bytes sit verbatim in the short-header DCID */
        ok(memcmp(packet + 1, raw, lengths[i]) == 0);
        quicly_flexicast_decrypted_t decrypted;
        ptls_iovec_t view;
        ok(quicly_flexicast_receive_packet(rx, packet, size, &decrypted, 0, 1) == 0);
        ok(decrypted.packet_number == 10 && decrypted.num_datagrams == 1);
        ok(quicly_flexicast_next_datagram(&decrypted, &view) == 1);
        ok(view.len == sizeof(payload) && memcmp(view.base, payload, sizeof(payload)) == 0);
        ok(quicly_flexicast_next_datagram(&decrypted, &view) == 0);
        quicly_flexicast_flow_free(rx);
        quicly_flexicast_flow_free(tx);
    }
}

static void test_packet_layouts(void)
{
    static const uint8_t layouts[][16] = {
        {0x31, 4, 't', 'e', 's', 't'},    {0x30, 't', 'e', 's', 't'},      {0, 0x31, 4, 't', 'e', 's', 't'},
        {1, 0x31, 4, 't', 'e', 's', 't'}, {0x31, 1, 'a', 0, 1, 0x30, 'b'}, {0, 0x31, 0, 0x31, 0},
    };
    const size_t sizes[] = {6, 5, 7, 7, 7, 5};
    for (unsigned pn_length = 1; pn_length <= 4; ++pn_length) {
        /* cross each truncated-number boundary with a nonzero epoch floor */
        uint64_t first_pn = UINT64_C(1) << (pn_length * 8);
        quicly_flexicast_flow_t *flow = packet_flow(first_pn, 0);
        for (size_t i = 0; i != PTLS_ELEMENTSOF(layouts); ++i) {
            uint8_t packet[256], copy[256];
            size_t size = protect_packet(packet, pn_length, first_pn + i, 0, layouts[i], sizes[i]);
            memcpy(copy, packet, size);
            ptls_iovec_t payloads[2];
            size_t count = PTLS_ELEMENTSOF(payloads);
            uint64_t pn;
            ok(quicly_flexicast_receive_datagrams(flow, packet, size, payloads, &count, &pn, 0, 10) == 0);
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
            ok(quicly_flexicast_receive_datagrams(flow, copy, size, payloads, &count, &pn, 0, 11) == QUICLY_FLEXICAST_ERROR_REPLAY);
        }
        quicly_flexicast_flow_free(flow);
    }
}

static void test_packet_iterator_and_atomicity(void)
{
    static const uint8_t multi[] = {0, 0x31, 1, 'a', 1, 0x31, 1, 'b', 0x30, 'c'};
    static const uint8_t two[] = {0x31, 1, 'a', 0x31, 1, 'b'};
    static const uint8_t truncated[] = {0x31, 1, 'a', 0x31, 8, 'b'};
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256];
    ptls_iovec_t payloads[2] = {{NULL, 99}, {NULL, 99}};
    quicly_flexicast_decrypted_t decrypted;
    uint64_t pn;

    /* malformed frames are rejected before committing receive state */
    size_t size = protect_packet(packet, 2, 0, 0, truncated, sizeof(truncated)), count = 2;
    ok(quicly_flexicast_receive_packet(flow, packet, size, &decrypted, 0, 10) == QUICLY_FLEXICAST_ERROR_FRAME_ENCODING);
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);

    /* receive_packet + next_datagram enumerates arbitrary frame counts in one pass without pre-sizing or re-protecting */
    size = protect_packet(packet, 2, 0, 0, multi, sizeof(multi));
    ok(quicly_flexicast_receive_packet(flow, packet, size, &decrypted, 0, 10) == 0);
    ok(decrypted.packet_number == 0 && decrypted.num_datagrams == 3);
    ptls_iovec_t *dynamic = calloc(decrypted.num_datagrams, sizeof(*dynamic));
    size_t seen = 0;
    ptls_iovec_t view;
    int step;
    while ((step = quicly_flexicast_next_datagram(&decrypted, &view)) > 0)
        dynamic[seen++] = view;
    ok(step == 0 && seen == 3 && decrypted.num_datagrams == 0);
    ok(dynamic[0].len == 1 && *dynamic[0].base == 'a');
    ok(dynamic[1].len == 1 && *dynamic[1].base == 'b');
    ok(dynamic[2].len == 1 && *dynamic[2].base == 'c');
    free(dynamic);
    ok(quicly_flexicast_ack_is_due(flow, 10) && quicly_flexicast_get_ack_deadline(flow) == 10);

    /* fixed-array convenience wrapper still preserves replay atomicity when BUFFER_TOO_SMALL occurs */
    size = protect_packet(packet, 2, 1, 0, two, sizeof(two));
    ok(quicly_flexicast_receive_datagram(flow, packet, size, payloads, &pn, 0, 20) == QUICLY_FLEXICAST_ERROR_BUFFER_TOO_SMALL);
    ok(payloads[0].base == NULL && payloads[0].len == 99);
    size = protect_packet(packet, 2, 1, 0, two, sizeof(two));
    count = 2;
    ok(quicly_flexicast_receive_datagrams(flow, packet, size, payloads, &count, &pn, 0, 20) == 0);
    ok(count == 2 && pn == 1);
    size = protect_packet(packet, 2, 1, 0, two, sizeof(two));
    payloads[0] = ptls_iovec_init(NULL, 99);
    count = 1;
    ok(quicly_flexicast_receive_datagrams(flow, packet, size, payloads, &count, &pn, 0, 21) == QUICLY_FLEXICAST_ERROR_REPLAY);
    ok(count == 1 && payloads[0].base == NULL && payloads[0].len == 99);
    quicly_flexicast_flow_free(flow);
}

static void test_packet_errors(void)
{
    static const uint8_t data[] = {0x31, 4, 't', 'e', 's', 't'};
    static const uint64_t prohibited[] = {QUICLY_FRAME_TYPE_FC_ANNOUNCE, QUICLY_FRAME_TYPE_FC_STATE,     QUICLY_FRAME_TYPE_FC_KEY,
                                          QUICLY_FRAME_TYPE_PATH_ACK,    QUICLY_FRAME_TYPE_PATH_ACK_ECN, QUICLY_FRAME_TYPE_ACK};
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256];
    ptls_iovec_t payload;
    uint64_t pn;
    size_t size = protect_packet(packet, 2, 0, 8, data, sizeof(data));
    ok(quicly_flexicast_receive_datagram(flow, packet, size, &payload, &pn, 0, 10) == QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION);
    size = protect_packet(packet, 2, 0, 8, data, sizeof(data));
    packet[size - 1] ^= 1;
    ok(quicly_flexicast_receive_datagram(flow, packet, size, &payload, &pn, 0, 10) == QUICLY_FLEXICAST_ERROR_CRYPTO);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(prohibited); ++i) {
        uint8_t plain[32] = {0};
        quicly_encodev(plain, prohibited[i]);
        size = protect_packet(packet, 2, 0, 0, plain, sizeof(plain));
        ok(quicly_flexicast_receive_datagram(flow, packet, size, &payload, &pn, 0, 10) ==
           QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION);
    }
    size = protect_packet(packet, 4, 0, 0, data, 0);
    ok(quicly_flexicast_receive_datagram(flow, packet, size, &payload, &pn, 0, 10) == QUICLY_FLEXICAST_ERROR_PROTOCOL_VIOLATION);
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    size = protect_packet(packet, 2, 0, 0, data, sizeof(data));
    ok(quicly_flexicast_receive_datagram(flow, packet, size, &payload, &pn, 0, 10) == 0);
    quicly_flexicast_flow_free(flow);
}

static void test_packet_ack_elicitation(void)
{
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256], padding[4] = {0}, ping[4] = {1};
    uint64_t pn;
    ptls_iovec_t payload;
    size_t size = protect_packet(packet, 2, 0, 0, padding, sizeof(padding));
    ok(quicly_flexicast_receive_datagram(flow, packet, size, &payload, &pn, 0, 10) == 0);
    ok(payload.base == NULL && payload.len == 0);
    ok(!quicly_flexicast_ack_is_due(flow, 1000));
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    size = protect_packet(packet, 2, 1, 0, ping, sizeof(ping));
    size_t count = 0;
    ok(quicly_flexicast_receive_datagrams(flow, packet, size, NULL, &count, &pn, 0, 20) == 0);
    ok(count == 0 && quicly_flexicast_ack_is_due(flow, 20) && quicly_flexicast_get_ack_deadline(flow) == 20);
    quicly_flexicast_flow_free(flow);
}

static void test_packet_size_limits(void)
{
    const size_t limits[] = {1200, 1500, QUICLY_FLEXICAST_MAX_PACKET_SIZE};
    uint8_t *payload = calloc(1, QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE);
    uint8_t *packet = malloc(QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE + 64);
    for (size_t i = 0; i != PTLS_ELEMENTSOF(limits); ++i) {
        quicly_flexicast_flow_t *flow = packet_flow(0, i == 0 ? 0 : limits[i]);
        ok(quicly_flexicast_attach(flow, 1, 0) == 0);
        size_t payload_size = limits[i] - 27 - (i == 2 ? 5 : 3), size;
        uint64_t pn;
        ok(quicly_flexicast_datagram_size(flow, payload_size) == limits[i]);
        ok(quicly_flexicast_datagram_size(flow, payload_size + 1) == 0);
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, payload_size + 1), packet,
                                          QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE + 64, &size, &pn,
                                          0) == QUICLY_FLEXICAST_ERROR_INVALID);
        ok(quicly_flexicast_get_next_packet_number(flow) == 0);
        ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(payload, payload_size), packet,
                                          QUICLY_FLEXICAST_MAX_DATAGRAM_SIZE + 64, &size, &pn, 0) == 0);
        ok(size == limits[i] && pn == 0);
        quicly_flexicast_flow_free(flow);
    }
    free(payload);
    free(packet);
}

static void test_datagram_packet_encoder(void)
{
    quicly_flexicast_flow_id_t flow_id = default_packet_flow_id();
    quicly_flexicast_egress_t egress = {.crypto_engine = &quicly_default_crypto_engine};
    int ret = egress.crypto_engine->setup_cipher(egress.crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1, &egress.header_protection,
                                                 &egress.aead, ptls_openssl_aes128gcmsha256.aead, ptls_openssl_aes128gcmsha256.hash,
                                                 packet_secret);
    ok(ret == 0);
    if (ret != 0)
        return;

    ptls_iovec_t payload = ptls_iovec_init("packet", 6);
    uint8_t packet[128], untouched[sizeof(packet)];
    size_t size = SIZE_MAX, expected = quicly_flexicast_datagram_packet_size(&egress, &flow_id, 4, payload.len);
    ok(expected == 1 + flow_id.len + 4 + 2 + payload.len + egress.aead->algo->tag_size);
    ok(quicly_flexicast_datagram_packet_size(&egress, &flow_id, 3, payload.len) == 0);
    ok(quicly_flexicast_datagram_packet_size(&egress, &flow_id, 4, SIZE_MAX) == 0);
    ok(quicly_flexicast_datagram_packet_size(&egress, &flow_id, 4, QUICLY_FLEXICAST_MAX_PACKET_SIZE) == 0);
    ptls_aead_algorithm_t short_tag = {.tag_size = 8, .iv_size = 12, .ctr_cipher = egress.aead->algo->ctr_cipher};
    ptls_aead_algorithm_t short_iv = {.tag_size = QUICLY_AEAD_TAG_SIZE, .iv_size = 8, .ctr_cipher = egress.aead->algo->ctr_cipher};
    ptls_aead_context_t unsupported_aead = {.algo = &short_tag};
    quicly_flexicast_egress_t unsupported_egress = egress;
    unsupported_egress.aead = &unsupported_aead;
    ok(quicly_flexicast_datagram_packet_size(&unsupported_egress, &flow_id, 4, payload.len) == 0);
    unsupported_aead.algo = &short_iv;
    ok(quicly_flexicast_datagram_packet_size(&unsupported_egress, &flow_id, 4, payload.len) == 0);
    ptls_cipher_algorithm_t other_ctr = *egress.header_protection->algo;
    ptls_cipher_context_t unsupported_hp = {.algo = &ptls_openssl_aes128ecb};
    unsupported_egress = egress;
    unsupported_egress.header_protection = &unsupported_hp;
    ok(quicly_flexicast_datagram_packet_size(&unsupported_egress, &flow_id, 4, payload.len) == 0);
    unsupported_hp.algo = &other_ctr;
    ok(quicly_flexicast_datagram_packet_size(&unsupported_egress, &flow_id, 4, payload.len) == 0);
    memset(packet, 0xa5, sizeof(packet));
    memcpy(untouched, packet, sizeof(packet));
    ok(quicly_flexicast_encode_datagram_packet(&egress, &flow_id, 0, 3, payload, packet, sizeof(packet), &size) ==
       QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_encode_datagram_packet(&egress, &flow_id, PTLS_QUICINT_MAX + 1, 4, payload, packet, sizeof(packet),
                                               &size) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_encode_datagram_packet(&egress, &flow_id, 0, 4, payload, packet, expected - 1, &size) ==
       QUICLY_FLEXICAST_ERROR_INVALID);
    ok(size == SIZE_MAX && memcmp(packet, untouched, sizeof(packet)) == 0);

    /* wide PN crosses both a durable reservation gap and the 32-bit wire wrap */
    uint64_t first = UINT32_MAX - UINT64_C(100), later = first + 65536;
    quicly_flexicast_flow_t *rx = packet_flow(first, 0), *late_rx = packet_flow(first, 0);
    ok(quicly_flexicast_encode_datagram_packet(&egress, &flow_id, first, 4, payload, packet, expected, &size) == 0);
    ok(size == expected);
    ptls_iovec_t received;
    uint64_t pn;
    ok(quicly_flexicast_receive_datagram(rx, packet, size, &received, &pn, 0, 1) == 0);
    ok(pn == first && received.len == payload.len && memcmp(received.base, payload.base, payload.len) == 0);
    ok(quicly_flexicast_encode_datagram_packet(&egress, &flow_id, later, 4, payload, packet, expected, &size) == 0);
    uint8_t late_packet[sizeof(packet)];
    memcpy(late_packet, packet, size);
    ok(quicly_flexicast_receive_datagram(rx, packet, size, &received, &pn, 0, 2) == 0 && pn == later);
    ok(quicly_flexicast_receive_datagram(late_rx, late_packet, size, &received, &pn, 0, 2) == 0);
    ok(pn == later && received.len == payload.len && memcmp(received.base, payload.base, payload.len) == 0);
    quicly_flexicast_flow_free(late_rx);
    quicly_flexicast_flow_free(rx);

    /* default two-byte width also supports a minimum-sized packet and header protection sample */
    rx = packet_flow(0, 0);
    ok(quicly_flexicast_encode_datagram_packet(&egress, &flow_id, 0, QUICLY_SEND_PN_SIZE, ptls_iovec_init(NULL, 0), packet,
                                               sizeof(packet), &size) == 0);
    ok(size == quicly_flexicast_datagram_size(rx, 0));
    ok(quicly_flexicast_receive_datagram(rx, packet, size, &received, &pn, 0, 1) == 0 && pn == 0 && received.len == 0);
    ok((packet[0] & 0x3) + 1 == QUICLY_SEND_PN_SIZE);
    quicly_flexicast_flow_free(rx);
    ptls_cipher_free(egress.header_protection);
    ptls_aead_free(egress.aead);
}

static void test_send_requires_members(void)
{
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    ptls_iovec_t payload = ptls_iovec_init("packet", 6);
    uint8_t packet[128];
    size_t size = SIZE_MAX, pending;
    uint64_t pn = UINT64_MAX;
    quicly_flexicast_crypto_usage_t usage;
    ok(quicly_flexicast_send_datagram(flow, payload, packet, sizeof(packet), &size, &pn, 1) == QUICLY_FLEXICAST_ERROR_NO_MEMBERS);
    ok(!quicly_flexicast_flow_has_sender_state(flow));
    ok(quicly_flexicast_get_next_packet_number(flow) == 0 && size == SIZE_MAX && pn == UINT64_MAX);
    ok(quicly_flexicast_get_crypto_usage(flow, &usage) == 0 && usage.encrypted_packets == 0);

    ok(quicly_flexicast_attach(flow, 1, 2) == 0);
    ok(quicly_flexicast_send_datagram(flow, payload, packet, sizeof(packet), &size, &pn, 3) == 0 && pn == 0);
    ok(quicly_flexicast_get_pending_members(flow, pn, &pending) == 0 && pending == 1);
    int complete = 0;
    ok(quicly_flexicast_ack_packet(flow, 1, pn, &complete, 4) == 0 && complete);
    ok(quicly_flexicast_detach(flow, 1, 5) == 0);
    ok(quicly_flexicast_send_datagram(flow, payload, packet, sizeof(packet), &size, &pn, 6) == QUICLY_FLEXICAST_ERROR_NO_MEMBERS);
    ok(quicly_flexicast_get_next_packet_number(flow) == 1);
    ok(quicly_flexicast_get_crypto_usage(flow, &usage) == 0 && usage.encrypted_packets == 1);
    quicly_flexicast_flow_free(flow);
}

static void test_padding_history_bound(void)
{
    quicly_flexicast_flow_t *flow = packet_flow(0, 0);
    uint8_t packet[256], plain[4] = {0}, encoded[QUICLY_FLEXICAST_MAX_ACK_ENCODED_SIZE];
    uint64_t pn, ack_path_id = 777;
    size_t count, size, encoded_size;
    const unsigned num_padding = QUICLY_FLEXICAST_SENT_WINDOW + 8;
    int received = 1;
    for (unsigned i = 0; i != num_padding; ++i) {
        size = protect_packet(packet, 2, i * 2, 0, plain, sizeof(plain));
        count = 0;
        received &= quicly_flexicast_receive_datagrams(flow, packet, size, NULL, &count, &pn, 0, i) == 0;
    }
    ok(received);
    ok(!quicly_flexicast_ack_is_due(flow, num_padding + 100));
    ok(quicly_flexicast_get_ack_deadline(flow) == INT64_MAX);
    plain[0] = QUICLY_FRAME_TYPE_PING;
    size = protect_packet(packet, 2, num_padding * 2, 0, plain, sizeof(plain));
    count = 0;
    ok(quicly_flexicast_receive_datagrams(flow, packet, size, NULL, &count, &pn, 0, num_padding) == 0);
    ok(quicly_flexicast_ack_is_due(flow, num_padding));
    ok(quicly_flexicast_encode_pending_ack(flow, ack_path_id, encoded, sizeof(encoded), num_padding, &encoded_size) == 0);
    const uint8_t *src = encoded, *end = src + encoded_size;
    ok(quicly_decodev(&src, end) == QUICLY_FRAME_TYPE_PATH_ACK);
    ok(quicly_decodev(&src, end) == ack_path_id);
    quicly_ack_frame_t ack;
    ok(quicly_decode_ack_frame(&src, end, &ack, 0) == 0);
    ok(ack.num_gaps + 1 == QUICLY_MAX_ACK_BLOCKS);
    ok(ack.smallest_acknowledged == (num_padding - QUICLY_MAX_ACK_BLOCKS + 1) * 2 && ack.largest_acknowledged == num_padding * 2);
    quicly_flexicast_ack_sent(flow);
    ok(!quicly_flexicast_ack_is_due(flow, num_padding));
    quicly_flexicast_flow_free(flow);
}

void test_flexicast_packets(void)
{
    subtest("wire-flow-id-lengths", test_wire_flow_id_lengths);
    subtest("packet-layouts", test_packet_layouts);
    subtest("packet-iterator-and-atomicity", test_packet_iterator_and_atomicity);
    subtest("packet-errors", test_packet_errors);
    subtest("packet-ack-elicitation", test_packet_ack_elicitation);
    subtest("packet-size-limits", test_packet_size_limits);
    subtest("datagram-packet-encoder", test_datagram_packet_encoder);
    subtest("send-requires-members", test_send_requires_members);
    subtest("padding-history-bound", test_padding_history_bound);
}
