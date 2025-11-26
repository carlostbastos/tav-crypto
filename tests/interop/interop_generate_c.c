/*
 * TAV INTEROP TEST - Gerador de Vetores (C)
 * ==========================================
 * 
 * Gera vetores de teste em modo determinístico para validação
 * cross-platform entre C, Rust e JavaScript.
 * 
 * Compilar: gcc -O2 -I../c interop_generate_c.c ../c/tav.c ../c/tav_sign.c -o interop_c -lm
 * Executar: ./interop_c > vectors_from_c.json
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "tav.h"

/* ============================================================================
 * MODO DETERMINÍSTICO
 * ============================================================================
 * 
 * Para interoperabilidade, precisamos que todas as implementações produzam
 * EXATAMENTE os mesmos resultados. Isso significa:
 * 
 * 1. Desabilitar entropia física (usar valores fixos)
 * 2. Usar nonce baseado apenas em contador
 * 3. Mesma sequência de operações
 */

/* Helpers */
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("    \"%s\": \"", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\"");
}

static void print_hex_array(const char* label, const uint8_t* data, size_t len) {
    printf("    \"%s\": [", label);
    for (size_t i = 0; i < len; i++) {
        printf("%d", data[i]);
        if (i < len - 1) printf(", ");
    }
    printf("]");
}

/* ============================================================================
 * TESTES DE HASH
 * ============================================================================ */

static void test_hash_vectors(void) {
    printf("  \"hash_tests\": [\n");
    
    /* Vetor 1: String vazia */
    {
        uint8_t hash[32];
        tav_hash((uint8_t*)"", 0, hash);
        
        printf("    {\n");
        printf("      \"name\": \"empty_string\",\n");
        printf("      \"input_utf8\": \"\",\n");
        printf("      \"input_hex\": \"\",\n");
        print_hex("output_hex", hash, 32);
        printf("\n    }");
    }
    
    printf(",\n");
    
    /* Vetor 2: "TAV" */
    {
        uint8_t hash[32];
        const char* input = "TAV";
        tav_hash((uint8_t*)input, 3, hash);
        
        printf("    {\n");
        printf("      \"name\": \"tav_string\",\n");
        printf("      \"input_utf8\": \"TAV\",\n");
        printf("      \"input_hex\": \"544156\",\n");
        print_hex("output_hex", hash, 32);
        printf("\n    }");
    }
    
    printf(",\n");
    
    /* Vetor 3: "Hello, World!" */
    {
        uint8_t hash[32];
        const char* input = "Hello, World!";
        tav_hash((uint8_t*)input, strlen(input), hash);
        
        printf("    {\n");
        printf("      \"name\": \"hello_world\",\n");
        printf("      \"input_utf8\": \"Hello, World!\",\n");
        printf("      \"input_hex\": \"48656c6c6f2c20576f726c6421\",\n");
        print_hex("output_hex", hash, 32);
        printf("\n    }");
    }
    
    printf(",\n");
    
    /* Vetor 4: Bytes sequenciais 0-31 */
    {
        uint8_t input[32];
        uint8_t hash[32];
        for (int i = 0; i < 32; i++) input[i] = i;
        tav_hash(input, 32, hash);
        
        printf("    {\n");
        printf("      \"name\": \"sequential_32\",\n");
        printf("      \"input_hex\": \"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\n");
        print_hex("output_hex", hash, 32);
        printf("\n    }");
    }
    
    printf(",\n");
    
    /* Vetor 5: Todos 0xFF */
    {
        uint8_t input[32];
        uint8_t hash[32];
        memset(input, 0xFF, 32);
        tav_hash(input, 32, hash);
        
        printf("    {\n");
        printf("      \"name\": \"all_ff\",\n");
        printf("      \"input_hex\": \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\n");
        print_hex("output_hex", hash, 32);
        printf("\n    }");
    }
    
    printf(",\n");
    
    /* Vetor 6: String longa (para testar múltiplos blocos) */
    {
        uint8_t hash[32];
        const char* input = "The quick brown fox jumps over the lazy dog. TAV Clock Cryptography V9.1";
        tav_hash((uint8_t*)input, strlen(input), hash);
        
        printf("    {\n");
        printf("      \"name\": \"long_string\",\n");
        printf("      \"input_utf8\": \"The quick brown fox jumps over the lazy dog. TAV Clock Cryptography V9.1\",\n");
        print_hex("output_hex", hash, 32);
        printf("\n    }");
    }
    
    printf("\n  ]");
}

/* ============================================================================
 * TESTES DE DERIVAÇÃO DE CHAVE
 * ============================================================================ */

static void test_key_derivation(void) {
    printf("  \"key_derivation_tests\": [\n");
    
    const char* seeds[] = {"test", "password123", "TAV_SEED_2025"};
    const int levels[] = {TAV_LEVEL_IOT, TAV_LEVEL_CONSUMER, TAV_LEVEL_ENTERPRISE};
    const char* level_names[] = {"iot", "consumer", "enterprise"};
    
    int first = 1;
    
    for (int s = 0; s < 3; s++) {
        for (int l = 0; l < 3; l++) {
            if (!first) printf(",\n");
            first = 0;
            
            tav_ctx_t ctx;
            tav_init(&ctx, (uint8_t*)seeds[s], strlen(seeds[s]), levels[l]);
            
            /* Extrai chave derivada (via encrypt de dados conhecidos) */
            uint8_t pt[1] = {0x42};
            uint8_t ct[64];
            size_t ct_len;
            
            /* Força nonce determinístico */
            ctx.entropy.nonce_counter = 1;
            
            tav_encrypt(&ctx, pt, 1, ct, &ct_len, false);
            
            printf("    {\n");
            printf("      \"name\": \"seed_%s_level_%s\",\n", seeds[s], level_names[l]);
            printf("      \"seed_utf8\": \"%s\",\n", seeds[s]);
            printf("      \"level\": %d,\n", levels[l]);
            printf("      \"tx_count\": 0,\n");
            print_hex("master_entropy_first16", ctx.master_entropy, 16);
            printf(",\n");
            printf("      \"ciphertext_len\": %zu,\n", ct_len);
            print_hex("ciphertext_hex", ct, ct_len);
            printf("\n    }");
            
            tav_cleanup(&ctx);
        }
    }
    
    printf("\n  ]");
}

/* ============================================================================
 * TESTES DE ENCRYPT/DECRYPT
 * ============================================================================ */

static void test_encrypt_decrypt(void) {
    printf("  \"encrypt_decrypt_tests\": [\n");
    
    struct {
        const char* name;
        const char* seed;
        int level;
        const char* plaintext;
    } tests[] = {
        {"simple_iot", "seed1", TAV_LEVEL_IOT, "A"},
        {"simple_consumer", "seed1", TAV_LEVEL_CONSUMER, "A"},
        {"hello_consumer", "test_key", TAV_LEVEL_CONSUMER, "Hello, TAV!"},
        {"empty_enterprise", "enterprise_key", TAV_LEVEL_ENTERPRISE, ""},
        {"long_military", "military_key_2025", TAV_LEVEL_MILITARY, 
         "This is a longer message to test block processing in TAV encryption."},
    };
    
    int n_tests = sizeof(tests) / sizeof(tests[0]);
    
    for (int i = 0; i < n_tests; i++) {
        if (i > 0) printf(",\n");
        
        tav_ctx_t ctx;
        tav_init(&ctx, (uint8_t*)tests[i].seed, strlen(tests[i].seed), tests[i].level);
        
        /* Força estado determinístico */
        ctx.entropy.nonce_counter = 1;
        
        const uint8_t* pt = (uint8_t*)tests[i].plaintext;
        size_t pt_len = strlen(tests[i].plaintext);
        
        uint8_t ct[256];
        size_t ct_len;
        
        tav_encrypt(&ctx, pt, pt_len, ct, &ct_len, false);
        
        printf("    {\n");
        printf("      \"name\": \"%s\",\n", tests[i].name);
        printf("      \"seed_utf8\": \"%s\",\n", tests[i].seed);
        printf("      \"level\": %d,\n", tests[i].level);
        printf("      \"plaintext_utf8\": \"%s\",\n", tests[i].plaintext);
        printf("      \"plaintext_len\": %zu,\n", pt_len);
        printf("      \"ciphertext_len\": %zu,\n", ct_len);
        print_hex("ciphertext_hex", ct, ct_len);
        printf(",\n");
        
        /* Decripta para verificar */
        uint8_t dec[256];
        size_t dec_len;
        tav_result_t res = tav_decrypt(&ctx, ct, ct_len, dec, &dec_len);
        
        printf("      \"decrypt_ok\": %s,\n", res == TAV_OK ? "true" : "false");
        printf("      \"roundtrip_ok\": %s\n", 
               (res == TAV_OK && dec_len == pt_len && memcmp(pt, dec, pt_len) == 0) ? "true" : "false");
        printf("    }");
        
        tav_cleanup(&ctx);
    }
    
    printf("\n  ]");
}

/* ============================================================================
 * TESTES DE ASSINATURA HASH-CHAIN
 * ============================================================================ */

static void test_sign_chain(void) {
    printf("  \"sign_chain_tests\": [\n");
    
    struct {
        const char* name;
        const char* seed;
        uint16_t chain_len;
        const char* message;
    } tests[] = {
        {"basic_100", "sign_seed", 100, "test message"},
        {"short_chain", "abc", 10, "hello"},
        {"long_message", "key123", 50, "This is a much longer message that needs to be signed securely."},
    };
    
    int n_tests = sizeof(tests) / sizeof(tests[0]);
    
    for (int i = 0; i < n_tests; i++) {
        if (i > 0) printf(",\n");
        
        tav_sign_chain_t keys;
        tav_sign_chain_keygen(&keys, (uint8_t*)tests[i].seed, strlen(tests[i].seed));
        keys.chain_length = tests[i].chain_len;
        
        /* Regenera public key com novo chain_length */
        uint8_t current[32];
        memcpy(current, keys.private_seed, 32);
        for (uint16_t j = 0; j < tests[i].chain_len; j++) {
            uint8_t next[32];
            tav_hash(current, 32, next);
            memcpy(current, next, 32);
        }
        memcpy(keys.public_key, current, 32);
        keys.current_index = 0;
        
        uint8_t sig[128];
        size_t sig_len;
        
        tav_sign_chain_sign(&keys, (uint8_t*)tests[i].message, strlen(tests[i].message),
                           sig, &sig_len);
        
        printf("    {\n");
        printf("      \"name\": \"%s\",\n", tests[i].name);
        printf("      \"seed_utf8\": \"%s\",\n", tests[i].seed);
        printf("      \"chain_length\": %d,\n", tests[i].chain_len);
        printf("      \"message_utf8\": \"%s\",\n", tests[i].message);
        print_hex("public_key_hex", keys.public_key, 32);
        printf(",\n");
        print_hex("private_seed_hex", keys.private_seed, 32);
        printf(",\n");
        printf("      \"signature_len\": %zu,\n", sig_len);
        print_hex("signature_hex", sig, sig_len);
        printf(",\n");
        
        /* Verifica */
        tav_result_t res = tav_sign_chain_verify(keys.public_key, 
                                                  (uint8_t*)tests[i].message, 
                                                  strlen(tests[i].message),
                                                  sig, sig_len);
        printf("      \"verify_ok\": %s\n", res == TAV_OK ? "true" : "false");
        printf("    }");
    }
    
    printf("\n  ]");
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(void) {
    printf("{\n");
    printf("  \"generator\": \"C\",\n");
    printf("  \"version\": \"9.1.0\",\n");
    printf("  \"description\": \"TAV interoperability test vectors generated by C implementation\",\n");
    printf("\n");
    
    test_hash_vectors();
    printf(",\n\n");
    
    test_key_derivation();
    printf(",\n\n");
    
    test_encrypt_decrypt();
    printf(",\n\n");
    
    test_sign_chain();
    printf("\n");
    
    printf("}\n");
    
    return 0;
}
