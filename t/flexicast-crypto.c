/*
 * Copyright (c) 2026 Joseph Calderon
 * SPDX-License-Identifier: MIT
 */
#include "picotest.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/flexicast.h"

static quicly_flexicast_config_t crypto_config(const uint8_t *secret)
{
    return (quicly_flexicast_config_t){
        .flow_id = UINT64_C(0x100000001),
        .cipher_suite = &ptls_openssl_aes128gcmsha256,
        .crypto_engine = &quicly_default_crypto_engine,
        .traffic_secret = ptls_iovec_init(secret, ptls_openssl_aes128gcmsha256.hash->digest_size),
        .max_members = 1,
    };
}

static void send_and_release(quicly_flexicast_flow_t *flow, uint64_t expected_pn)
{
    uint8_t packet[128];
    size_t size;
    uint64_t pn;
    int complete;
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn) == QUICLY_FLEXICAST_OK);
    ok(pn == expected_pn);
    /* Protection consumes the budget even if local submission is abandoned. */
    ok(quicly_flexicast_abandon_datagram(flow, 1, pn, &complete) == QUICLY_FLEXICAST_OK && complete);
}

static void test_encryption_budget_history(void)
{
    uint8_t secrets[3][32] = {{1}, {2}, {3}}, packet[128];
    quicly_flexicast_config_t config = crypto_config(secrets[0]);
    config.max_packets_per_key = 3;
    config.first_packet_number = 60000;
    quicly_flexicast_flow_t *flow;
    uint64_t pn;
    size_t size;
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, 1, &size, &pn) == QUICLY_FLEXICAST_ERROR_INVALID);
    send_and_release(flow, 60000);

    /* Reinstalling the current secret cannot replenish its budget. */
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[0], 32), 60001, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 60001);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[1], 32), 60002, 2) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 60002);

    /* A -> B -> A must restore A's existing count, not a fresh budget. */
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[0], 32), 60003, 3) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 60003);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn) ==
       QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    ok(quicly_flexicast_get_next_packet_number(flow) == 60004);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[0], 32), 60004, 4) == QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    ok(quicly_flexicast_num_members(flow) == 1);

    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[1], 32), 60004, 4) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 60004);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[0], 32), 60005, 5) == QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    send_and_release(flow, 60005); /* A rejected rekey leaves B usable. */
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn) ==
       QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[2], 32), 60006, 6) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 60006);
    quicly_flexicast_flow_free(flow);
}

static void test_authentication_budget(void)
{
    uint8_t secrets[3][32] = {{1}, {2}, {3}}, packet[128], copy[128], data[32] = {0};
    quicly_flexicast_config_t config = crypto_config(secrets[0]);
    quicly_flexicast_flow_t *source, *receiver;
    size_t size;
    uint64_t pn, received_pn;
    ptls_iovec_t received;
    ok(quicly_flexicast_flow_create(&source, &config) == QUICLY_FLEXICAST_OK);
    config.max_authentication_failures = 2;
    ok(quicly_flexicast_flow_create(&receiver, &config) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(data, sizeof(data)), packet, sizeof(packet), &size, &pn) ==
       QUICLY_FLEXICAST_OK);
    memcpy(copy, packet, size);
    copy[1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn) == QUICLY_FLEXICAST_ERROR_WRONG_FLOW);
    ok(quicly_flexicast_receive_datagram(receiver, copy, 1, &received, &received_pn) == QUICLY_FLEXICAST_ERROR_INVALID);
    memcpy(copy, packet, size);
    copy[size - 1] ^= 1; /* tag outside the header-protection sample */
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn) == QUICLY_FLEXICAST_ERROR_CRYPTO);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn) == QUICLY_FLEXICAST_OK);

    /* Successful authentication and a new key cannot erase earlier failures. */
    ok(quicly_flexicast_flow_rekey(source, ptls_iovec_init(secrets[1], 32), 1, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_flow_rekey(receiver, ptls_iovec_init(secrets[1], 32), 1, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(data, sizeof(data)), packet, sizeof(packet), &size, &pn) ==
       QUICLY_FLEXICAST_OK);
    memcpy(copy, packet, size);
    copy[size - 1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn) ==
       QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn) ==
       QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    ok(quicly_flexicast_flow_rekey(receiver, ptls_iovec_init(secrets[2], 32), 2, 2) == QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    ok(quicly_flexicast_send_datagram(receiver, ptls_iovec_init(NULL, 0), copy, sizeof(copy), &size, &pn) ==
       QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    quicly_flexicast_flow_free(receiver);
    quicly_flexicast_flow_free(source);
}

static void test_crypto_limit_configuration(void)
{
    uint8_t secret[PTLS_MAX_DIGEST_SIZE] = {0};
    quicly_flexicast_config_t config = crypto_config(secret);
    quicly_flexicast_flow_t *flow;
    ptls_cipher_suite_t *suites[] = {&ptls_openssl_aes128gcmsha256, &ptls_openssl_aes256gcmsha384};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(suites); ++i) {
        config.cipher_suite = suites[i];
        config.traffic_secret.len = suites[i]->hash->digest_size;
        config.max_packets_per_key = UINT64_C(1) << 23;
        config.max_authentication_failures = UINT64_C(1) << 52;
        ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
        quicly_flexicast_flow_free(flow);
        ++config.max_packets_per_key;
        ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
        --config.max_packets_per_key;
        ++config.max_authentication_failures;
        ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
    }
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    config = crypto_config(secret);
    config.cipher_suite = &ptls_openssl_chacha20poly1305sha256;
    config.max_packets_per_key = PTLS_QUICINT_MAX + UINT64_C(1);
    config.max_authentication_failures = UINT64_C(1) << 36;
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    quicly_flexicast_flow_free(flow);
    ++config.max_authentication_failures;
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
    --config.max_authentication_failures;
    ++config.max_packets_per_key;
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
#endif
    ptls_cipher_suite_t unknown_suite = {.id = 0xffff, .aead = &ptls_openssl_aes128gcm, .hash = &ptls_openssl_sha256};
    ptls_cipher_suite_t short_tag_suite = {.id = 0x1305, .aead = &ptls_openssl_aes128gcm, .hash = &ptls_openssl_sha256};
    config = crypto_config(secret);
    config.cipher_suite = &unknown_suite;
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
    config.cipher_suite = &short_tag_suite;
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
}

static int fail_ingress_setup;

static int test_setup_cipher(quicly_crypto_engine_t *engine, quicly_conn_t *conn, size_t epoch, int is_enc,
                             ptls_cipher_context_t **hp, ptls_aead_context_t **aead, ptls_aead_algorithm_t *algo,
                             ptls_hash_algorithm_t *hash, const void *secret)
{
    if (fail_ingress_setup && !is_enc)
        return PTLS_ERROR_LIBRARY;
    return quicly_default_crypto_engine.setup_cipher(engine, conn, epoch, is_enc, hp, aead, algo, hash, secret);
}

static void test_rekey_setup_failure(void)
{
    uint8_t secrets[2][32] = {{1}, {2}}, packet[128];
    quicly_crypto_engine_t engine = {.setup_cipher = test_setup_cipher,
                                     .encrypt_packet = quicly_default_crypto_engine.encrypt_packet};
    quicly_flexicast_config_t config = crypto_config(secrets[0]);
    quicly_flexicast_flow_t *flow;
    size_t size;
    uint64_t pn;
    config.crypto_engine = &engine;
    config.max_packets_per_key = 2;
    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 0);
    /* Egress setup succeeds before ingress setup fails. The old key, its
     * count, and membership must survive this partially constructed rekey. */
    fail_ingress_setup = 1;
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[1], 32), 1, 1) == QUICLY_FLEXICAST_ERROR_CRYPTO);
    fail_ingress_setup = 0;
    ok(quicly_flexicast_num_members(flow) == 1 && quicly_flexicast_get_next_packet_number(flow) == 1);
    send_and_release(flow, 1);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn) ==
       QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[1], 32), 2, 2) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 2);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[0], 32), 3, 3) == QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    quicly_flexicast_flow_free(flow);
}

void test_flexicast_crypto(void)
{
    test_encryption_budget_history();
    test_authentication_budget();
    test_crypto_limit_configuration();
    test_rekey_setup_failure();
}
