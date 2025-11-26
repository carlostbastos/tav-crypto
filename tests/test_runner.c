/*
 * TAV Clock Cryptography v9.1
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/caterencio/tav-crypto
 */

/*
 * TAV TEST RUNNER - Executa testes com vetores determinísticos
 * ============================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../c/tav.h"
#include "test_vectors.h"

/* ============================================================================
 * MODO DETERMINÍSTICO - Override das funções de timing
 * ============================================================================ */

static size_t fake_timing_index = 0;

/* Substitui tav_get_time_ns em modo determinístico */
uint64_t tav_get_time_ns_deterministic(void) {
    uint64_t value = FAKE_TIMING_SEQUENCE[fake_timing_index % FAKE_TIMING_COUNT];
    fake_timing_index++;
    return value;
}

/* Reset do índice de timing */
void reset_deterministic_timing(void) {
    fake_timing_index = 0;
}

/* ============================================================================
 * TESTES
 * ============================================================================ */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        printf("  [PASS] %s\n", msg); \
        tests_passed++; \
    } else { \
        printf("  [FAIL] %s\n", msg); \
        tests_failed++; \
    } \
} while(0)

/* Teste de hash */
int test_hash(void) {
    printf("\n=== HASH TESTS ===\n");
    
    /* Teste básico: mesmo input = mesmo output */
    uint8_t hash1[32], hash2[32];
    const uint8_t data[] = "test data";
    
    tav_hash(data, sizeof(data) - 1, hash1);
    tav_hash(data, sizeof(data) - 1, hash2);
    
    TEST_ASSERT(memcmp(hash1, hash2, 32) == 0, "Hash determinism");
    
    /* Teste: inputs diferentes = outputs diferentes */
    const uint8_t data2[] = "test data!";
    uint8_t hash3[32];
    tav_hash(data2, sizeof(data2) - 1, hash3);
    
    TEST_ASSERT(memcmp(hash1, hash3, 32) != 0, "Hash uniqueness");
    
    /* Teste avalanche: 1 bit de diferença muda ~50% do output */
    uint8_t data_a[] = "AAAAAAAAAAAAAAAA";
    uint8_t data_b[] = "AAAAAAAAAAAAAAAB";
    uint8_t hash_a[32], hash_b[32];
    
    tav_hash(data_a, 16, hash_a);
    tav_hash(data_b, 16, hash_b);
    
    int diff_bits = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t xor = hash_a[i] ^ hash_b[i];
        while (xor) {
            diff_bits += xor & 1;
            xor >>= 1;
        }
    }
    
    /* Esperamos ~128 bits diferentes (50% de 256) */
    TEST_ASSERT(diff_bits > 80 && diff_bits < 176, 
                "Hash avalanche effect (>80, <176 bits)");
    
    printf("  Avalanche: %d/256 bits changed (%.1f%%)\n", 
           diff_bits, diff_bits * 100.0 / 256);
    
    return tests_failed == 0;
}

/* Teste de encrypt/decrypt */
int test_encrypt_decrypt(void) {
    printf("\n=== ENCRYPT/DECRYPT TESTS ===\n");
    
    tav_ctx_t ctx;
    const char* seed = "test_seed_12345";
    
    tav_result_t res = tav_init(&ctx, (const uint8_t*)seed, strlen(seed), 
                                 TAV_LEVEL_CONSUMER);
    TEST_ASSERT(res == TAV_OK, "Context initialization");
    
    /* Teste básico */
    const uint8_t plaintext[] = "Hello, TAV Crypto!";
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    size_t ct_len, pt_len;
    
    res = tav_encrypt(&ctx, plaintext, sizeof(plaintext) - 1, 
                      ciphertext, &ct_len, false);
    TEST_ASSERT(res == TAV_OK, "Encryption");
    
    res = tav_decrypt(&ctx, ciphertext, ct_len, decrypted, &pt_len);
    TEST_ASSERT(res == TAV_OK, "Decryption");
    
    TEST_ASSERT(pt_len == sizeof(plaintext) - 1, "Plaintext length match");
    TEST_ASSERT(memcmp(plaintext, decrypted, pt_len) == 0, "Plaintext content match");
    
    /* Teste de integridade: adultera ciphertext */
    ciphertext[ct_len / 2] ^= 0xFF;
    res = tav_decrypt(&ctx, ciphertext, ct_len, decrypted, &pt_len);
    TEST_ASSERT(res == TAV_ERROR_MAC_MISMATCH, "Tamper detection");
    
    tav_cleanup(&ctx);
    
    return tests_failed == 0;
}

/* Teste de sincronização */
int test_sync(void) {
    printf("\n=== SYNC TESTS ===\n");
    
    tav_ctx_t alice, bob;
    const char* shared_seed = "shared_secret_seed";
    
    tav_init(&alice, (const uint8_t*)shared_seed, strlen(shared_seed), 
             TAV_LEVEL_CONSUMER);
    tav_init(&bob, (const uint8_t*)shared_seed, strlen(shared_seed), 
             TAV_LEVEL_CONSUMER);
    
    /* Mensagem 1: Alice -> Bob */
    const uint8_t msg1[] = "Message from Alice";
    uint8_t ct1[256], pt1[256];
    size_t ct1_len, pt1_len;
    
    tav_encrypt(&alice, msg1, sizeof(msg1) - 1, ct1, &ct1_len, true);
    tav_result_t res = tav_decrypt(&bob, ct1, ct1_len, pt1, &pt1_len);
    tav_tick(&bob, 1);
    
    TEST_ASSERT(res == TAV_OK, "Alice->Bob msg1");
    
    /* Mensagem 2: Bob -> Alice */
    const uint8_t msg2[] = "Reply from Bob";
    uint8_t ct2[256], pt2[256];
    size_t ct2_len, pt2_len;
    
    tav_encrypt(&bob, msg2, sizeof(msg2) - 1, ct2, &ct2_len, true);
    res = tav_decrypt(&alice, ct2, ct2_len, pt2, &pt2_len);
    tav_tick(&alice, 1);
    
    TEST_ASSERT(res == TAV_OK, "Bob->Alice msg2");
    
    /* Múltiplas mensagens */
    for (int i = 0; i < 100; i++) {
        uint8_t msg[32], ct[128], pt[128];
        size_t ct_len, pt_len;
        
        snprintf((char*)msg, 32, "Message %d", i);
        
        tav_encrypt(&alice, msg, strlen((char*)msg), ct, &ct_len, true);
        res = tav_decrypt(&bob, ct, ct_len, pt, &pt_len);
        tav_tick(&bob, 1);
        
        if (res != TAV_OK) {
            printf("  [FAIL] Sync lost at message %d\n", i);
            tests_failed++;
            break;
        }
    }
    
    TEST_ASSERT(res == TAV_OK, "100 messages sync maintained");
    
    tav_cleanup(&alice);
    tav_cleanup(&bob);
    
    return tests_failed == 0;
}

/* Teste de assinatura hash-chain */
int test_sign_chain(void) {
    printf("\n=== SIGN CHAIN TESTS ===\n");
    
    tav_sign_chain_t keys;
    const char* seed = "sign_test_seed";
    
    tav_result_t res = tav_sign_chain_keygen(&keys, (const uint8_t*)seed, 
                                              strlen(seed));
    TEST_ASSERT(res == TAV_OK, "Key generation");
    
    /* Assina mensagem */
    const uint8_t message[] = "Document to sign";
    uint8_t signature[128];
    size_t sig_len;
    
    res = tav_sign_chain_sign(&keys, message, sizeof(message) - 1, 
                               signature, &sig_len);
    TEST_ASSERT(res == TAV_OK, "Signing");
    
    /* Verifica assinatura */
    res = tav_sign_chain_verify(keys.public_key, message, sizeof(message) - 1,
                                 signature, sig_len);
    TEST_ASSERT(res == TAV_OK, "Signature verification");
    
    /* Adultera mensagem */
    uint8_t tampered[] = "Document to sign!";
    res = tav_sign_chain_verify(keys.public_key, tampered, sizeof(tampered) - 1,
                                 signature, sig_len);
    TEST_ASSERT(res == TAV_ERROR_MAC_MISMATCH, "Tampered message detection");
    
    /* Adultera assinatura */
    signature[10] ^= 0xFF;
    res = tav_sign_chain_verify(keys.public_key, message, sizeof(message) - 1,
                                 signature, sig_len);
    TEST_ASSERT(res == TAV_ERROR_MAC_MISMATCH, "Tampered signature detection");
    
    /* Testa múltiplas assinaturas (chain avança) */
    for (int i = 1; i < 10; i++) {
        char msg[32];
        snprintf(msg, 32, "Message %d", i);
        
        res = tav_sign_chain_sign(&keys, (uint8_t*)msg, strlen(msg), 
                                   signature, &sig_len);
        if (res != TAV_OK) break;
        
        res = tav_sign_chain_verify(keys.public_key, (uint8_t*)msg, strlen(msg),
                                     signature, sig_len);
        if (res != TAV_OK) break;
    }
    TEST_ASSERT(res == TAV_OK, "Multiple signatures");
    
    return tests_failed == 0;
}

/* Teste de assinatura commitment */
int test_sign_commit(void) {
    printf("\n=== SIGN COMMIT TESTS ===\n");
    
    tav_sign_commit_t keys;
    const char* seed = "commit_test_seed";
    
    tav_result_t res = tav_sign_commit_keygen(&keys, (const uint8_t*)seed,
                                               strlen(seed), TAV_LEVEL_CONSUMER);
    TEST_ASSERT(res == TAV_OK, "Key generation");
    
    /* Assina */
    const uint8_t message[] = "Important document";
    uint8_t signature[128];
    size_t sig_len;
    
    res = tav_sign_commit_sign(&keys, message, sizeof(message) - 1,
                                signature, &sig_len);
    TEST_ASSERT(res == TAV_OK, "Signing");
    
    /* Verifica */
    res = tav_sign_commit_verify(keys.public_commitment, message, 
                                  sizeof(message) - 1, signature, sig_len);
    TEST_ASSERT(res == TAV_OK, "Verification");
    
    /* Testa múltiplas assinaturas */
    for (int i = 0; i < 50; i++) {
        char msg[32];
        snprintf(msg, 32, "Doc %d", i);
        
        res = tav_sign_commit_sign(&keys, (uint8_t*)msg, strlen(msg),
                                    signature, &sig_len);
        if (res != TAV_OK) break;
    }
    TEST_ASSERT(res == TAV_OK, "50 signatures (no chain limit)");
    
    return tests_failed == 0;
}

/* Teste de níveis de segurança */
int test_security_levels(void) {
    printf("\n=== SECURITY LEVEL TESTS ===\n");
    
    const tav_level_t levels[] = {
        TAV_LEVEL_IOT, TAV_LEVEL_CONSUMER, 
        TAV_LEVEL_ENTERPRISE, TAV_LEVEL_MILITARY
    };
    const char* level_names[] = {"IoT", "Consumer", "Enterprise", "Military"};
    
    for (int i = 0; i < 4; i++) {
        tav_ctx_t ctx;
        tav_init(&ctx, (uint8_t*)"test", 4, levels[i]);
        
        const uint8_t pt[] = "Test message for level";
        uint8_t ct[256], dec[256];
        size_t ct_len, pt_len;
        
        tav_encrypt(&ctx, pt, sizeof(pt) - 1, ct, &ct_len, false);
        tav_result_t res = tav_decrypt(&ctx, ct, ct_len, dec, &pt_len);
        
        char msg[64];
        snprintf(msg, 64, "Level %s encrypt/decrypt", level_names[i]);
        TEST_ASSERT(res == TAV_OK && memcmp(pt, dec, pt_len) == 0, msg);
        
        printf("  %s: overhead=%zu bytes\n", level_names[i], tav_overhead(levels[i]));
        
        tav_cleanup(&ctx);
    }
    
    return tests_failed == 0;
}

/* Teste de performance */
int test_performance(void) {
    printf("\n=== PERFORMANCE TESTS ===\n");
    
    tav_ctx_t ctx;
    tav_init(&ctx, (uint8_t*)"perf_seed", 9, TAV_LEVEL_CONSUMER);
    
    /* Mede encrypt */
    uint8_t data[1024];
    uint8_t ct[2048];
    size_t ct_len;
    
    memset(data, 0x55, 1024);
    
    /* Warm up */
    for (int i = 0; i < 10; i++) {
        tav_encrypt(&ctx, data, 1024, ct, &ct_len, true);
    }
    
    /* Measure */
    uint64_t start = tav_get_time_ns();
    int iterations = 1000;
    
    for (int i = 0; i < iterations; i++) {
        tav_encrypt(&ctx, data, 1024, ct, &ct_len, true);
    }
    
    uint64_t end = tav_get_time_ns();
    double elapsed_ms = (end - start) / 1000000.0;
    double throughput = (iterations * 1024.0) / (elapsed_ms / 1000.0) / (1024 * 1024);
    
    printf("  Encrypt 1KB x %d: %.2f ms (%.2f MB/s)\n", 
           iterations, elapsed_ms, throughput);
    
    /* Hash performance */
    start = tav_get_time_ns();
    uint8_t hash[32];
    
    for (int i = 0; i < iterations; i++) {
        tav_hash(data, 1024, hash);
    }
    
    end = tav_get_time_ns();
    elapsed_ms = (end - start) / 1000000.0;
    throughput = (iterations * 1024.0) / (elapsed_ms / 1000.0) / (1024 * 1024);
    
    printf("  Hash 1KB x %d: %.2f ms (%.2f MB/s)\n",
           iterations, elapsed_ms, throughput);
    
    tav_cleanup(&ctx);
    
    return 1; /* Performance tests always "pass" */
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char* argv[]) {
    printf("TAV CLOCK CRYPTOGRAPHY V9.1 - TEST SUITE\n");
    printf("========================================\n");
    
    test_hash();
    test_encrypt_decrypt();
    test_sync();
    test_sign_chain();
    test_sign_commit();
    test_security_levels();
    test_performance();
    
    printf("\n========================================\n");
    printf("RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");
    
    return tests_failed > 0 ? 1 : 0;
}
