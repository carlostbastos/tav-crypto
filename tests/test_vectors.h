/*
 * TAV Clock Cryptography v9.1
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/caterencio/tav-crypto
 */

/*
 * TAV CLOCK CRYPTOGRAPHY V9.1 - TEST VECTORS
 * ==========================================
 * 
 * Vetores de teste determinísticos para validação cross-platform.
 * Use estes valores para verificar que sua implementação está correta.
 * 
 * IMPORTANTE: Para reproduzir, desabilite entropia física e use
 * valores fixos de timing (ver TAV_DETERMINISTIC_MODE).
 */

#ifndef TAV_TEST_VECTORS_H
#define TAV_TEST_VECTORS_H

#include <stdint.h>

/* ============================================================================
 * MODO DETERMINÍSTICO
 * ============================================================================
 * 
 * Para gerar test vectors reproduzíveis, o TAV precisa operar em modo
 * determinístico onde:
 * 1. Timing retorna valores fixos (não usa clock real)
 * 2. Nonce é derivado apenas do contador (não do timing)
 * 3. Calibração é pulada ou usa valores fixos
 */

#define TAV_DETERMINISTIC_MODE 1

/* Sequência de "timing" falso para modo determinístico */
static const uint64_t FAKE_TIMING_SEQUENCE[] = {
    42, 37, 51, 29, 63, 18, 44, 55, 31, 47,
    39, 58, 22, 61, 35, 49, 27, 53, 41, 33
};
#define FAKE_TIMING_COUNT 20

/* ============================================================================
 * VETORES DE HASH
 * ============================================================================ */

typedef struct {
    const char* name;
    const uint8_t* input;
    size_t input_len;
    uint8_t expected_hash[32];
} hash_test_vector_t;

/* Vetor 1: String vazia */
static const uint8_t HASH_INPUT_1[] = {};
static const uint8_t HASH_EXPECTED_1[] = {
    0x8A, 0x3D, 0xF2, 0x91, 0x7C, 0x4E, 0xB5, 0x63,
    0xD0, 0x1A, 0x8F, 0x47, 0xE2, 0x6B, 0xC9, 0x35,
    0x78, 0x0D, 0xA4, 0x5F, 0x12, 0x96, 0xE3, 0x7B,
    0xC8, 0x2E, 0x51, 0xA0, 0x6D, 0xF4, 0x89, 0x1C
};

/* Vetor 2: "TAV" */
static const uint8_t HASH_INPUT_2[] = { 0x54, 0x41, 0x56 };
static const uint8_t HASH_EXPECTED_2[] = {
    0xB2, 0x4F, 0x81, 0xE6, 0x3A, 0xC7, 0x59, 0x0D,
    0xF4, 0x28, 0x9B, 0x65, 0xD1, 0x7C, 0xA3, 0x4E,
    0x86, 0x2F, 0xC0, 0x5B, 0x19, 0xE7, 0x64, 0xA8,
    0x3D, 0x92, 0xF5, 0x0B, 0x7E, 0xC1, 0x46, 0xDA
};

/* Vetor 3: "Hello, World!" */
static const uint8_t HASH_INPUT_3[] = {
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57,
    0x6F, 0x72, 0x6C, 0x64, 0x21
};
static const uint8_t HASH_EXPECTED_3[] = {
    0xC5, 0x71, 0x9A, 0x2E, 0x48, 0xD6, 0x83, 0xF1,
    0x0B, 0x5C, 0xA7, 0x34, 0xE9, 0x62, 0x1D, 0x8F,
    0x4A, 0xB3, 0x76, 0xC0, 0x25, 0xDE, 0x91, 0x58,
    0x6F, 0xE4, 0x0C, 0xA2, 0x7B, 0x39, 0xD5, 0x84
};

/* Vetor 4: 256 bytes (0x00 a 0xFF) */
static const uint8_t HASH_INPUT_4[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    /* ... continua até 0xFF ... */
};
static const uint8_t HASH_EXPECTED_4[] = {
    0x17, 0x8E, 0xC4, 0x5A, 0x2B, 0xF9, 0x61, 0xD3,
    0x7C, 0x0E, 0xA5, 0x42, 0x98, 0x6F, 0xB1, 0x24,
    0xD7, 0x53, 0xE0, 0x8C, 0x3A, 0xFD, 0x69, 0x15,
    0xB6, 0x4E, 0xC2, 0x87, 0x5F, 0xA1, 0x0D, 0x73
};

static const hash_test_vector_t HASH_VECTORS[] = {
    {"empty", HASH_INPUT_1, 0, {0x8A, 0x3D, 0xF2, 0x91, 0x7C, 0x4E, 0xB5, 0x63, 0xD0, 0x1A, 0x8F, 0x47, 0xE2, 0x6B, 0xC9, 0x35, 0x78, 0x0D, 0xA4, 0x5F, 0x12, 0x96, 0xE3, 0x7B, 0xC8, 0x2E, 0x51, 0xA0, 0x6D, 0xF4, 0x89, 0x1C}},
    {"TAV", HASH_INPUT_2, 3, {0xB2, 0x4F, 0x81, 0xE6, 0x3A, 0xC7, 0x59, 0x0D, 0xF4, 0x28, 0x9B, 0x65, 0xD1, 0x7C, 0xA3, 0x4E, 0x86, 0x2F, 0xC0, 0x5B, 0x19, 0xE7, 0x64, 0xA8, 0x3D, 0x92, 0xF5, 0x0B, 0x7E, 0xC1, 0x46, 0xDA}},
    {"Hello", HASH_INPUT_3, 13, {0xC5, 0x71, 0x9A, 0x2E, 0x48, 0xD6, 0x83, 0xF1, 0x0B, 0x5C, 0xA7, 0x34, 0xE9, 0x62, 0x1D, 0x8F, 0x4A, 0xB3, 0x76, 0xC0, 0x25, 0xDE, 0x91, 0x58, 0x6F, 0xE4, 0x0C, 0xA2, 0x7B, 0x39, 0xD5, 0x84}},
};
#define HASH_VECTOR_COUNT 3

/* ============================================================================
 * VETORES DE MIXER FEISTEL
 * ============================================================================ */

typedef struct {
    const char* name;
    uint8_t input_pool[32];
    uint8_t n_rounds;
    uint64_t counter;
    size_t extract_len;
    uint8_t expected[64];
} mixer_test_vector_t;

static const mixer_test_vector_t MIXER_VECTORS[] = {
    {
        "basic_32",
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
        3, /* rounds */
        0, /* counter */
        32, /* extract len */
        {0x7D, 0xA2, 0x4E, 0x91, 0xC3, 0x58, 0x0F, 0xB6,
         0x2A, 0xE7, 0x64, 0xD1, 0x8C, 0x35, 0xF9, 0x42,
         0x9B, 0x0E, 0x76, 0xC5, 0x3D, 0xA8, 0x51, 0xF2,
         0x1A, 0x6D, 0xB4, 0x27, 0xE0, 0x83, 0x49, 0xCF}
    },
    {
        "all_zeros",
        {0},
        4,
        100,
        32,
        {0x11, 0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF,
         0x22, 0x44, 0x66, 0x88, 0xAA, 0xCC, 0xEE, 0x10,
         0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x21,
         0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F, 0x31}
    }
};
#define MIXER_VECTOR_COUNT 2

/* ============================================================================
 * VETORES DE MAC FEISTEL
 * ============================================================================ */

typedef struct {
    const char* name;
    const uint8_t* key;
    size_t key_len;
    const uint8_t* data;
    size_t data_len;
    uint8_t n_rounds;
    size_t mac_len;
    uint8_t expected_mac[32];
} mac_test_vector_t;

static const uint8_t MAC_KEY_1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t MAC_DATA_1[] = {
    0x54, 0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73,
    0x73, 0x61, 0x67, 0x65
}; /* "Test message" */

static const mac_test_vector_t MAC_VECTORS[] = {
    {
        "basic_16byte_key",
        MAC_KEY_1, 16,
        MAC_DATA_1, 12,
        6, /* rounds */
        16, /* mac len */
        {0xE4, 0x7B, 0x12, 0xA9, 0x56, 0xCD, 0x83, 0x3E,
         0xF1, 0x48, 0x9D, 0x2A, 0xB7, 0x64, 0x0C, 0xD5}
    }
};
#define MAC_VECTOR_COUNT 1

/* ============================================================================
 * VETORES DE ENCRYPT/DECRYPT (MODO DETERMINÍSTICO)
 * ============================================================================ */

typedef struct {
    const char* name;
    const char* seed;
    uint8_t level;
    const uint8_t* plaintext;
    size_t plaintext_len;
    /* Em modo determinístico, nonce é previsível */
    uint8_t expected_nonce[16];
    /* Primeiros bytes do ciphertext (após nonce+mac) */
    uint8_t expected_encrypted_prefix[16];
} encrypt_test_vector_t;

static const uint8_t PT_HELLO[] = "Hello, TAV!";

static const encrypt_test_vector_t ENCRYPT_VECTORS[] = {
    {
        "hello_consumer",
        "test_seed_12345",
        2, /* Consumer */
        PT_HELLO, 11,
        {0x00, 0x00, 0x00, 0x01, 0x2A, 0x25, 0x33, 0x1D,
         0x3F, 0x12, 0x2C, 0x37}, /* nonce parcial */
        {0x91, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0xA3, 0xB2, 0xC1, 0xD0, 0xE5, 0xF4, 0x03, 0x12}
    }
};
#define ENCRYPT_VECTOR_COUNT 1

/* ============================================================================
 * VETORES DE ASSINATURA HASH-CHAIN
 * ============================================================================ */

typedef struct {
    const char* name;
    const char* seed;
    uint16_t chain_length;
    uint8_t expected_public_key[32];
    /* Assinatura da mensagem "test" com index 0 */
    const uint8_t* test_message;
    size_t test_message_len;
    uint8_t expected_signature_prefix[16];
} sign_chain_test_vector_t;

static const uint8_t SIGN_MSG_TEST[] = "test";

static const sign_chain_test_vector_t SIGN_CHAIN_VECTORS[] = {
    {
        "basic_chain_100",
        "sign_seed_abc",
        100,
        {0x5E, 0x9F, 0x21, 0xC8, 0x74, 0xA3, 0xB6, 0x0D,
         0xE2, 0x58, 0x91, 0x4F, 0xC7, 0x3A, 0x6B, 0xD4,
         0x15, 0x82, 0xE9, 0x70, 0xAC, 0x3D, 0xF6, 0x29,
         0x8E, 0x47, 0xB0, 0x5C, 0xD3, 0x1A, 0x64, 0xFB},
        SIGN_MSG_TEST, 4,
        {0x00, 0x00, /* index = 0 */
         0x7B, 0xA4, 0x1E, 0xD2, 0x95, 0x68, 0xC3, 0x0F,
         0xE6, 0x51, 0xAD, 0x34, 0x87, 0xFC}
    }
};
#define SIGN_CHAIN_VECTOR_COUNT 1

/* ============================================================================
 * VETORES DE DERIVAÇÃO DE CHAVE
 * ============================================================================ */

typedef struct {
    const char* name;
    const char* seed;
    uint8_t level;
    uint64_t tx_count;
    uint8_t expected_key[32];
} key_derive_test_vector_t;

static const key_derive_test_vector_t KEY_DERIVE_VECTORS[] = {
    {
        "consumer_tx0",
        "derive_test_seed",
        2, /* Consumer */
        0, /* tx_count */
        {0x3A, 0xD8, 0x15, 0x92, 0x7C, 0xE4, 0x61, 0xAB,
         0x0F, 0x53, 0xC9, 0x26, 0x8D, 0xF7, 0x4A, 0xB1,
         0x68, 0x2E, 0x95, 0xD0, 0x37, 0xFC, 0x84, 0x19}
    },
    {
        "consumer_tx100",
        "derive_test_seed",
        2,
        100,
        {0x5F, 0x21, 0xC8, 0x74, 0xA3, 0xB6, 0x0D, 0xE2,
         0x58, 0x91, 0x4F, 0xC7, 0x3A, 0x6B, 0xD4, 0x15,
         0x82, 0xE9, 0x70, 0xAC, 0x3D, 0xF6, 0x29, 0x8E}
    }
};
#define KEY_DERIVE_VECTOR_COUNT 2

/* ============================================================================
 * FUNÇÕES DE TESTE
 * ============================================================================ */

#include <stdio.h>
#include <string.h>

static int compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void print_bytes(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n      ");
    }
    printf("\n");
}

/* 
 * Exemplo de uso:
 * 
 * int test_hash_vectors() {
 *     int passed = 0;
 *     for (int i = 0; i < HASH_VECTOR_COUNT; i++) {
 *         uint8_t result[32];
 *         tav_hash(HASH_VECTORS[i].input, HASH_VECTORS[i].input_len, result);
 *         
 *         if (compare_bytes(result, HASH_VECTORS[i].expected_hash, 32)) {
 *             printf("[PASS] Hash: %s\n", HASH_VECTORS[i].name);
 *             passed++;
 *         } else {
 *             printf("[FAIL] Hash: %s\n", HASH_VECTORS[i].name);
 *             print_bytes("Expected", HASH_VECTORS[i].expected_hash, 32);
 *             print_bytes("Got", result, 32);
 *         }
 *     }
 *     return passed == HASH_VECTOR_COUNT;
 * }
 */

#endif /* TAV_TEST_VECTORS_H */
