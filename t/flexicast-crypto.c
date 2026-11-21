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
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 0) ==
       QUICLY_FLEXICAST_OK);
    ok(pn == expected_pn);
    /* protection consumes the budget even if local submission is abandoned */
    ok(quicly_flexicast_abandon_datagram(flow, 1, pn, &complete) == QUICLY_FLEXICAST_OK && complete);
}

static void test_encryption_budget_and_rekey(void)
{
    uint8_t secrets[2][32] = {{1}, {2}}, new_secret[32] = {0}, packet[128];
    quicly_flexicast_config_t config = crypto_config(secrets[0]);
    config.max_packets_per_key = 3;
    config.first_packet_number = 60000;
    quicly_flexicast_flow_t *flow;
    quicly_flexicast_crypto_usage_t usage;
    uint64_t pn;
    size_t size;

    ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, 1, &size, &pn, 0) == QUICLY_FLEXICAST_ERROR_INVALID);
    send_and_release(flow, 60000);

    /* reinstalling the active secret preserves its remaining packet budget */
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[0], 32), 60001, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_crypto_usage(flow, &usage) == QUICLY_FLEXICAST_OK && usage.encrypted_packets == 1);
    ok(quicly_flexicast_attach(flow, 1, 1) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 60001);
    send_and_release(flow, 60002);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 1) ==
       QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    ok(quicly_flexicast_get_next_packet_number(flow) == 60003);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[0], 32), 60003, 2) == QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    ok(quicly_flexicast_num_members(flow) == 1);

    /* rekeying to fresh secrets resets per-key encryption budget in O(1) space */
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[1], 32), 60003, 3) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_crypto_usage(flow, &usage) == QUICLY_FLEXICAST_OK && usage.encrypted_packets == 0);
    uint64_t next_pn = 60003;
    for (size_t i = 3; i != 130; ++i) {
        new_secret[0] = (uint8_t)i;
        ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(new_secret, sizeof(new_secret)), next_pn, (int64_t)i) ==
           QUICLY_FLEXICAST_OK);
        ok(quicly_flexicast_attach(flow, 1, (int64_t)i) == QUICLY_FLEXICAST_OK);
        send_and_release(flow, next_pn++);
    }
    send_and_release(flow, next_pn++);
    send_and_release(flow, next_pn++);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 200) ==
       QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
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
    ok(quicly_flexicast_attach(source, 1, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(data, sizeof(data)), packet, sizeof(packet), &size, &pn, 0) ==
       QUICLY_FLEXICAST_OK);
    memcpy(copy, packet, size);
    copy[1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_ERROR_WRONG_FLOW);
    ok(quicly_flexicast_receive_datagram(receiver, copy, 1, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_ERROR_INVALID);
    memcpy(copy, packet, size);
    copy[size - 1] ^= 1; /* tag outside the header-protection sample */
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_ERROR_CRYPTO);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_OK);

    /* successful authentication and a new key do not reset earlier failures */
    ok(quicly_flexicast_flow_rekey(source, ptls_iovec_init(secrets[1], 32), 1, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_flow_rekey(receiver, ptls_iovec_init(secrets[1], 32), 1, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(source, 1, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(data, sizeof(data)), packet, sizeof(packet), &size, &pn, 1) ==
       QUICLY_FLEXICAST_OK);
    memcpy(copy, packet, size);
    copy[size - 1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 1) ==
       QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 1) ==
       QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    ok(quicly_flexicast_flow_rekey(receiver, ptls_iovec_init(secrets[2], 32), 2, 2) == QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    ok(quicly_flexicast_send_datagram(receiver, ptls_iovec_init(NULL, 0), copy, sizeof(copy), &size, &pn, 2) ==
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
        config.max_decryption_attempts = UINT64_C(1) << 52;
        ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_OK);
        quicly_flexicast_flow_free(flow);
        ++config.max_packets_per_key;
        ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
        --config.max_packets_per_key;
        ++config.max_authentication_failures;
        ok(quicly_flexicast_flow_create(&flow, &config) == QUICLY_FLEXICAST_ERROR_INVALID);
        --config.max_authentication_failures;
        ++config.max_decryption_attempts;
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

static void test_authenticated_epoch_floor(void)
{
    uint8_t secret[32] = {1}, packet[128], copy[128], data[32] = {0};
    quicly_flexicast_config_t config = crypto_config(secret);
    quicly_flexicast_flow_t *source, *receiver;
    size_t size;
    uint64_t pn, received_pn;
    ptls_iovec_t received;
    config.first_packet_number = 60000;
    ok(quicly_flexicast_flow_create(&source, &config) == 0);
    ++config.first_packet_number;
    config.max_authentication_failures = 2;
    ok(quicly_flexicast_flow_create(&receiver, &config) == 0);
    ok(quicly_flexicast_attach(source, 1, 0) == 0);
    ok(quicly_flexicast_send_datagram(source, ptls_iovec_init(data, sizeof(data)), packet, sizeof(packet), &size, &pn, 0) == 0);

    /* valid packets below the join floor are replay-filtered without spending the forgery budget */
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_ERROR_REPLAY);
    memcpy(copy, packet, size);
    copy[size - 1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_ERROR_CRYPTO);
    memcpy(copy, packet, size);
    copy[size - 1] ^= 1;
    ok(quicly_flexicast_receive_datagram(receiver, copy, size, &received, &received_pn, 0, 0) ==
       QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    ok(quicly_flexicast_get_ack_deadline(receiver) == INT64_MAX);
    quicly_flexicast_flow_free(receiver);
    quicly_flexicast_flow_free(source);
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
    ok(quicly_flexicast_attach(flow, 1, 0) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 0);
    /* failed ingress setup preserves the previous key, count, and membership */
    fail_ingress_setup = 1;
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[1], 32), 1, 1) == QUICLY_FLEXICAST_ERROR_CRYPTO);
    fail_ingress_setup = 0;
    ok(quicly_flexicast_num_members(flow) == 1 && quicly_flexicast_get_next_packet_number(flow) == 1);
    send_and_release(flow, 1);
    ok(quicly_flexicast_send_datagram(flow, ptls_iovec_init(NULL, 0), packet, sizeof(packet), &size, &pn, 1) ==
       QUICLY_FLEXICAST_ERROR_KEY_UPDATE_REQUIRED);
    ok(quicly_flexicast_flow_rekey(flow, ptls_iovec_init(secrets[1], 32), 2, 2) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_attach(flow, 1, 2) == QUICLY_FLEXICAST_OK);
    send_and_release(flow, 2);
    quicly_flexicast_flow_free(flow);
}

static void test_decryption_budget_and_receive_floor(void)
{
    uint8_t secrets[2][32] = {{11}, {22}}, packet[128], copy[128], data[16] = {0};
    quicly_flexicast_config_t tx_cfg = crypto_config(secrets[0]);
    quicly_flexicast_config_t rx_cfg = crypto_config(secrets[0]);
    quicly_flexicast_flow_t *tx, *rx;
    quicly_flexicast_crypto_usage_t usage;
    const quicly_range_t *ranges;
    size_t size, num_ranges;
    uint64_t pn, received_pn, floor_bound, ecn_counts[3];
    int64_t largest_at;
    ptls_iovec_t received;

    tx_cfg.first_packet_number = 70000;
    rx_cfg.first_packet_number = 10;
    rx_cfg.max_decryption_attempts = 4;
    rx_cfg.max_authentication_failures = 4;
    ok(quicly_flexicast_flow_create(&tx, &tx_cfg) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_flow_create(&rx, &rx_cfg) == QUICLY_FLEXICAST_OK);
    ok(!quicly_flexicast_flow_has_sender_state(rx));
    ok(quicly_flexicast_attach(tx, 1, 0) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_flow_has_sender_state(tx));

    ok(quicly_flexicast_get_crypto_usage(NULL, &usage) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_get_crypto_usage(rx, NULL) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_get_crypto_usage(rx, &usage) == QUICLY_FLEXICAST_OK);
    ok(usage.decryption_attempts == 0 && usage.max_decryption_attempts == 4);
    ok(quicly_flexicast_set_decryption_attempts(rx, 1) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_set_decryption_attempts(rx, 0) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_set_decryption_attempts(rx, 5) == QUICLY_FLEXICAST_ERROR_INVALID);

    /* validate and install receive floor across a 16-bit PN boundary */
    ok(quicly_flexicast_check_receive_floor(rx, 9) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_check_receive_floor(rx, PTLS_QUICINT_MAX + 1) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_install_receive_floor(rx, 70001) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_check_receive_floor(rx, 70000) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_get_receive_state(rx, &ranges, &num_ranges, &floor_bound, &largest_at, ecn_counts) == QUICLY_FLEXICAST_OK);
    ok(num_ranges == 0 && floor_bound == 70001);
    ok(quicly_flexicast_flow_rekey(rx, ptls_iovec_init(secrets[1], 32), 70000, 1) == QUICLY_FLEXICAST_ERROR_INVALID);

    /* packet 70000 is below floor: decrypted and replay-rejected while charging attempts */
    ok(quicly_flexicast_send_datagram(tx, ptls_iovec_init(data, sizeof(data)), packet, sizeof(packet), &size, &pn, 0) ==
       QUICLY_FLEXICAST_OK);
    ok(pn == 70000);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(rx, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_ERROR_REPLAY);
    ok(quicly_flexicast_get_crypto_usage(rx, &usage) == QUICLY_FLEXICAST_OK && usage.decryption_attempts == 2);

    /* packet 70001 succeeds and locks out further floor installation */
    ok(quicly_flexicast_send_datagram(tx, ptls_iovec_init(data, sizeof(data)), packet, sizeof(packet), &size, &pn, 0) ==
       QUICLY_FLEXICAST_OK);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(rx, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_OK &&
       received_pn == 70001);
    ok(quicly_flexicast_install_receive_floor(rx, 70002) == QUICLY_FLEXICAST_ERROR_INVALID);

    /* replay of 70001 consumes the 4th and final decryption attempt for secrets[0] */
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(rx, copy, size, &received, &received_pn, 0, 0) == QUICLY_FLEXICAST_ERROR_REPLAY);
    memcpy(copy, packet, size);
    ok(quicly_flexicast_receive_datagram(rx, copy, size, &received, &received_pn, 0, 0) ==
       QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);
    ok(quicly_flexicast_flow_rekey(rx, ptls_iovec_init(secrets[0], 32), 70002, 2) == QUICLY_FLEXICAST_ERROR_AEAD_LIMIT_REACHED);

    /* rekeying to a fresh secret resets per-key decryption attempts without allocating sender tables */
    ok(quicly_flexicast_flow_rekey(rx, ptls_iovec_init(secrets[1], 32), 70002, 2) == QUICLY_FLEXICAST_OK);
    ok(quicly_flexicast_get_crypto_usage(rx, &usage) == QUICLY_FLEXICAST_OK && usage.decryption_attempts == 0);
    ok(!quicly_flexicast_flow_has_sender_state(rx));

    quicly_flexicast_flow_free(rx);
    quicly_flexicast_flow_free(tx);
}

static void test_invalid_pn_before_aead(void)
{
    /* truncated PN reconstructing past PTLS_QUICINT_MAX must fail before spending AEAD budget */
    uint8_t secret[32] = {0x99}, packet[64] = {0};
    quicly_flexicast_config_t cfg = crypto_config(secret);
    cfg.first_packet_number = PTLS_QUICINT_MAX;
    cfg.max_decryption_attempts = 2;
    cfg.max_authentication_failures = 2;
    quicly_flexicast_flow_t *rx;
    quicly_flexicast_crypto_usage_t usage;
    ptls_iovec_t payload;
    uint64_t pn;

    ok(quicly_flexicast_flow_create(&rx, &cfg) == QUICLY_FLEXICAST_OK);
    ptls_cipher_context_t *hp = NULL;
    ptls_aead_context_t *aead = NULL;
    ok(quicly_default_crypto_engine.setup_cipher(&quicly_default_crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1, &hp, &aead,
                                                 ptls_openssl_aes128gcmsha256.aead, ptls_openssl_aes128gcmsha256.hash,
                                                 secret) == 0);
    packet[0] = QUICLY_QUIC_BIT | 1; /* 2-byte PN */
    quicly_encode64(packet + 1, cfg.flow_id);
    /* PTLS_QUICINT_MAX has low 16 bits 0xffff; 0x0000 reconstructs to PTLS_QUICINT_MAX + 1 */
    packet[9] = 0;
    packet[10] = 0;
    memset(packet + 11, 0x55, 20);
    uint8_t mask[5] = {0};
    ptls_cipher_init(hp, packet + 13);
    ptls_cipher_encrypt(hp, mask, mask, sizeof(mask));
    packet[0] ^= mask[0] & 0x1f;
    packet[9] ^= mask[1];
    packet[10] ^= mask[2];
    ptls_cipher_free(hp);
    ptls_aead_free(aead);

    ok(quicly_flexicast_receive_datagram(rx, packet, 31, &payload, &pn, 0, 0) == QUICLY_FLEXICAST_ERROR_INVALID);
    ok(quicly_flexicast_get_crypto_usage(rx, &usage) == QUICLY_FLEXICAST_OK);
    ok(usage.decryption_attempts == 0 && usage.authentication_failures == 0);
    quicly_flexicast_flow_free(rx);
}

void test_flexicast_crypto(void)
{
    test_encryption_budget_and_rekey();
    test_authentication_budget();
    test_authenticated_epoch_floor();
    test_crypto_limit_configuration();
    test_rekey_setup_failure();
    test_decryption_budget_and_receive_floor();
    test_invalid_pn_before_aead();
}
