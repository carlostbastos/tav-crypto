/*
 * TAV CLOCK CRYPTOGRAPHY V9.1 - ARDUINO/ESP32
 * ============================================
 * 
 * Versão otimizada para microcontroladores:
 * - Zero alocação dinâmica (no malloc)
 * - Tamanhos fixos em tempo de compilação
 * - Mínimo uso de RAM
 * - Usa timer do hardware para entropia
 * 
 * Suportado:
 * - Arduino (AVR, ARM)
 * - ESP32/ESP8266
 * - STM32
 * - Qualquer plataforma com timer de alta resolução
 * 
 * Uso de memória (aprox):
 * - IoT: ~200 bytes RAM
 * - Consumer: ~300 bytes RAM
 * - Enterprise: ~400 bytes RAM
 */

#ifndef TAV_ARDUINO_H
#define TAV_ARDUINO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURAÇÃO - Ajuste para sua plataforma
 * ============================================================================ */

/* Nível de segurança (escolha UM) */
#define TAV_LEVEL_IOT         1
#define TAV_LEVEL_CONSUMER    2
#define TAV_LEVEL_ENTERPRISE  3

/* Define o nível padrão */
#ifndef TAV_SECURITY_LEVEL
#define TAV_SECURITY_LEVEL TAV_LEVEL_CONSUMER
#endif

/* Configuração baseada no nível */
#if TAV_SECURITY_LEVEL == TAV_LEVEL_IOT
    #define TAV_KEY_BYTES       16
    #define TAV_MAC_BYTES       8
    #define TAV_NONCE_BYTES     8
    #define TAV_MASTER_SIZE     32
    #define TAV_N_XOR           2
    #define TAV_N_ROUNDS_MIXER  2
    #define TAV_N_ROUNDS_MAC    4
    #define TAV_N_BOXES         2
#elif TAV_SECURITY_LEVEL == TAV_LEVEL_CONSUMER
    #define TAV_KEY_BYTES       24
    #define TAV_MAC_BYTES       12
    #define TAV_NONCE_BYTES     12
    #define TAV_MASTER_SIZE     48
    #define TAV_N_XOR           2
    #define TAV_N_ROUNDS_MIXER  3
    #define TAV_N_ROUNDS_MAC    6
    #define TAV_N_BOXES         3
#elif TAV_SECURITY_LEVEL == TAV_LEVEL_ENTERPRISE
    #define TAV_KEY_BYTES       32
    #define TAV_MAC_BYTES       16
    #define TAV_NONCE_BYTES     16
    #define TAV_MASTER_SIZE     64
    #define TAV_N_XOR           3
    #define TAV_N_ROUNDS_MIXER  4
    #define TAV_N_ROUNDS_MAC    8
    #define TAV_N_BOXES         4
#endif

#define TAV_POOL_SIZE       32
#define TAV_OVERHEAD        (TAV_NONCE_BYTES + TAV_MAC_BYTES + 8)
#define TAV_HASH_SIZE       32

/* ============================================================================
 * CONSTANTES (em PROGMEM para AVR)
 * ============================================================================ */

#ifdef __AVR__
#include <avr/pgmspace.h>
#define TAV_CONST PROGMEM
#define TAV_READ_CONST(addr) pgm_read_byte(addr)
#else
#define TAV_CONST
#define TAV_READ_CONST(addr) (*(addr))
#endif

static const uint8_t TAV_CONST_AND[32] TAV_CONST = {
    0xB7, 0x5D, 0xA3, 0xE1, 0x97, 0x4F, 0xC5, 0x2B,
    0x8D, 0x61, 0xF3, 0x1F, 0xD9, 0x73, 0x3D, 0xAF,
    0x17, 0x89, 0xCB, 0x53, 0xE7, 0x2D, 0x9B, 0x41,
    0xBB, 0x6D, 0xF1, 0x23, 0xDD, 0x7F, 0x35, 0xA9
};

static const uint8_t TAV_CONST_OR[32] TAV_CONST = {
    0x11, 0x22, 0x44, 0x08, 0x10, 0x21, 0x42, 0x04,
    0x12, 0x24, 0x48, 0x09, 0x14, 0x28, 0x41, 0x02,
    0x18, 0x30, 0x60, 0x05, 0x0A, 0x15, 0x2A, 0x54,
    0x19, 0x32, 0x64, 0x06, 0x0C, 0x19, 0x33, 0x66
};

/* Primos compactos (apenas valores, não índices) */
static const uint16_t TAV_PRIMES_1[16] TAV_CONST = {
    11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71
};
static const uint16_t TAV_PRIMES_2[16] TAV_CONST = {
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179
};
static const uint16_t TAV_PRIMES_3[16] TAV_CONST = {
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097
};
static const uint16_t TAV_PRIMES_4[16] TAV_CONST = {
    10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133, 10139, 10141
};

/* ============================================================================
 * ESTRUTURAS (tamanho fixo)
 * ============================================================================ */

typedef struct {
    uint8_t pool[TAV_POOL_SIZE];
    uint32_t counter;
} tav_mixer_t;

typedef struct {
    uint8_t index[TAV_N_BOXES];
} tav_boxes_t;

typedef struct {
    uint16_t tick_count[4];
    uint8_t tx_count[4];
} tav_clocks_t;

typedef struct {
    tav_mixer_t mixer;
    tav_boxes_t boxes;
    tav_clocks_t clocks;
    uint8_t master_entropy[TAV_MASTER_SIZE];
    uint32_t tx_global;
    uint32_t nonce_counter;
    uint8_t work_index;
    uint8_t initialized;
} tav_ctx_t;

/* Assinatura hash-chain (compacta) */
typedef struct {
    uint8_t public_key[TAV_HASH_SIZE];
    uint8_t private_seed[TAV_HASH_SIZE];
    uint16_t current_index;
    uint16_t chain_length;
} tav_sign_t;

/* Resultados */
typedef enum {
    TAV_OK = 0,
    TAV_ERROR_MAC = 1,
    TAV_ERROR_DATA = 2,
    TAV_ERROR_CHAIN = 3
} tav_result_t;

/* ============================================================================
 * FUNÇÕES DE PLATAFORMA - IMPLEMENTE PARA SUA PLATAFORMA
 * ============================================================================ */

/* 
 * Retorna microssegundos desde boot.
 * Implemente para sua plataforma:
 * 
 * Arduino: return micros();
 * ESP32: return esp_timer_get_time();
 * STM32: return HAL_GetTick() * 1000 + (TIM2->CNT);
 */
extern uint32_t tav_platform_micros(void);

/* Implementação padrão para Arduino */
#ifdef ARDUINO
#include <Arduino.h>
static inline uint32_t tav_platform_micros(void) {
    return micros();
}
#endif

/* Implementação para ESP32 */
#ifdef ESP32
#include "esp_timer.h"
static inline uint32_t tav_platform_micros(void) {
    return (uint32_t)esp_timer_get_time();
}
#endif

/* ============================================================================
 * FUNÇÕES INLINE
 * ============================================================================ */

static inline uint8_t tav_rot_left(uint8_t b, uint8_t n) {
    n &= 7;
    return (b << n) | (b >> (8 - n));
}

static inline uint8_t tav_const_and(uint8_t idx) {
    return TAV_READ_CONST(&TAV_CONST_AND[idx & 31]);
}

static inline uint8_t tav_const_or(uint8_t idx) {
    return TAV_READ_CONST(&TAV_CONST_OR[idx & 31]);
}

/* ============================================================================
 * MIXER FEISTEL
 * ============================================================================ */

static void tav_mixer_round(uint8_t* data, uint8_t round) {
    uint8_t f_out[TAV_POOL_SIZE / 2];
    uint8_t half = TAV_POOL_SIZE / 2;
    
    /* F(R) */
    for (uint8_t i = 0; i < half; i++) {
        uint8_t x = data[half + i];
        x = tav_rot_left(x, (round + i) & 7);
        x = x & tav_const_and(i + round * 7);
        x = x | tav_const_or(i + round * 11);
        x = x ^ data[half + ((i + round + 1) % half)];
        f_out[i] = x;
    }
    
    /* Novo R = L XOR F(R) */
    uint8_t new_r[TAV_POOL_SIZE / 2];
    for (uint8_t i = 0; i < half; i++) {
        new_r[i] = data[i] ^ f_out[i];
    }
    
    /* Swap */
    memcpy(data, data + half, half);
    memcpy(data + half, new_r, half);
}

static void tav_mixer_update(tav_mixer_t* m, uint32_t entropy) {
    uint8_t pos = m->counter & (TAV_POOL_SIZE - 1);
    m->pool[pos] ^= entropy & 0xFF;
    m->pool[(pos + 1) & (TAV_POOL_SIZE - 1)] ^= (entropy >> 8) & 0xFF;
    m->counter++;
}

static void tav_mixer_extract(tav_mixer_t* m, uint8_t* out, uint8_t len) {
    uint8_t mixed[TAV_POOL_SIZE];
    memcpy(mixed, m->pool, TAV_POOL_SIZE);
    
    for (uint8_t r = 0; r < TAV_N_ROUNDS_MIXER; r++) {
        tav_mixer_round(mixed, r + (uint8_t)m->counter);
    }
    
    uint8_t offset = 0;
    while (offset < len) {
        uint8_t chunk = (len - offset < TAV_POOL_SIZE) ? (len - offset) : TAV_POOL_SIZE;
        memcpy(out + offset, mixed, chunk);
        offset += chunk;
        
        if (offset < len) {
            m->counter++;
            for (uint8_t r = 0; r < TAV_N_ROUNDS_MIXER; r++) {
                tav_mixer_round(mixed, r + (uint8_t)m->counter);
            }
        }
    }
}

/* ============================================================================
 * MAC FEISTEL
 * ============================================================================ */

static void tav_mac_round(uint8_t* state, uint8_t round, const uint8_t* key) {
    uint8_t f_out[16];
    
    for (uint8_t i = 0; i < 16; i++) {
        uint8_t x = state[16 + i];
        uint8_t k = key[i % TAV_KEY_BYTES];
        x = tav_rot_left(x ^ k, (round + i) & 7);
        x = x & tav_const_and(i + round * 7);
        x = x | tav_const_or(i + round * 11);
        x = x ^ state[16 + ((i + round + 1) & 15)];
        f_out[i] = x ^ k;
    }
    
    uint8_t new_r[16];
    for (uint8_t i = 0; i < 16; i++) {
        new_r[i] = state[i] ^ f_out[i];
    }
    
    memcpy(state, state + 16, 16);
    memcpy(state + 16, new_r, 16);
}

static void tav_mac_calc(const uint8_t* key, const uint8_t* data, uint16_t len, 
                         uint8_t* out) {
    uint8_t state[32];
    
    /* Init com chave */
    for (uint8_t i = 0; i < 32; i++) {
        state[i] = key[i % TAV_KEY_BYTES];
    }
    
    /* Processa dados */
    uint16_t offset = 0;
    while (offset < len) {
        uint8_t chunk = (len - offset < 32) ? (len - offset) : 32;
        for (uint8_t i = 0; i < chunk; i++) {
            state[i] ^= data[offset + i];
        }
        for (uint8_t r = 0; r < TAV_N_ROUNDS_MAC; r++) {
            tav_mac_round(state, r, key);
        }
        offset += chunk;
    }
    
    /* Finaliza com tamanho */
    state[0] ^= (len >> 8) & 0xFF;
    state[1] ^= len & 0xFF;
    
    for (uint8_t r = 0; r < TAV_N_ROUNDS_MAC; r++) {
        tav_mac_round(state, r + TAV_N_ROUNDS_MAC, key);
    }
    
    memcpy(out, state, TAV_MAC_BYTES);
}

/* ============================================================================
 * HASH
 * ============================================================================ */

static const uint8_t TAV_HASH_KEY[32] TAV_CONST = {
    0x54, 0x41, 0x56, 0x2D, 0x48, 0x41, 0x53, 0x48,
    0x56, 0x39, 0x2E, 0x31, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void tav_hash(const uint8_t* data, uint16_t len, uint8_t* out) {
    uint8_t state[32];
    uint8_t key[32];
    
    /* Copia chave (de PROGMEM se AVR) */
    for (uint8_t i = 0; i < 32; i++) {
        key[i] = TAV_READ_CONST(&TAV_HASH_KEY[i]);
        state[i] = key[i];
    }
    
    /* Processa */
    uint16_t offset = 0;
    while (offset < len) {
        uint8_t chunk = (len - offset < 32) ? (len - offset) : 32;
        for (uint8_t i = 0; i < chunk; i++) {
            state[i] ^= data[offset + i];
        }
        for (uint8_t r = 0; r < 8; r++) {
            tav_mac_round(state, r, key);
        }
        offset += chunk;
    }
    
    /* Finaliza */
    state[0] ^= (len >> 8) & 0xFF;
    state[1] ^= len & 0xFF;
    
    for (uint8_t r = 0; r < 8; r++) {
        tav_mac_round(state, r + 8, key);
    }
    
    memcpy(out, state, TAV_HASH_SIZE);
}

/* ============================================================================
 * ENTROPIA
 * ============================================================================ */

static uint32_t tav_collect_timing(tav_ctx_t* ctx) {
    volatile uint32_t x = 0;
    uint32_t t1 = tav_platform_micros();
    
    switch (ctx->work_index & 3) {
        case 0: for (uint8_t i = 0; i < 10; i++) x += i; break;
        case 1: for (uint8_t i = 0; i < 8; i++) x += i; break;
        case 2: for (uint8_t i = 0; i < 12; i++) x += i; break;
        default: for (uint8_t i = 0; i < 5; i++) x += i * i; break;
    }
    ctx->work_index++;
    
    uint32_t t2 = tav_platform_micros();
    (void)x;
    return t2 - t1;
}

static uint32_t tav_collect_xor(tav_ctx_t* ctx) {
    uint32_t result = 0;
    for (uint8_t i = 0; i < TAV_N_XOR; i++) {
        result ^= tav_collect_timing(ctx);
    }
    return result;
}

static void tav_generate_nonce(tav_ctx_t* ctx, uint8_t* out) {
    ctx->nonce_counter++;
    
    uint32_t t1 = tav_collect_xor(ctx);
    uint32_t t2 = tav_collect_xor(ctx);
    
    memset(out, 0, TAV_NONCE_BYTES);
    
    out[0] = (ctx->nonce_counter >> 24) & 0xFF;
    out[1] = (ctx->nonce_counter >> 16) & 0xFF;
    out[2] = (ctx->nonce_counter >> 8) & 0xFF;
    out[3] = ctx->nonce_counter & 0xFF;
    
    if (TAV_NONCE_BYTES >= 8) {
        out[4] = (t1 >> 24) & 0xFF;
        out[5] = (t1 >> 16) & 0xFF;
        out[6] = (t1 >> 8) & 0xFF;
        out[7] = t1 & 0xFF;
    }
    
    if (TAV_NONCE_BYTES >= 12) {
        out[8] = (t2 >> 24) & 0xFF;
        out[9] = (t2 >> 16) & 0xFF;
        out[10] = (t2 >> 8) & 0xFF;
        out[11] = t2 & 0xFF;
    }
}

/* ============================================================================
 * PRIMOS
 * ============================================================================ */

static uint16_t tav_get_prime(uint8_t box, uint8_t index) {
    const uint16_t* primes;
    switch (box) {
        case 0: primes = TAV_PRIMES_1; break;
        case 1: primes = TAV_PRIMES_2; break;
        case 2: primes = TAV_PRIMES_3; break;
        case 3: primes = TAV_PRIMES_4; break;
        default: return 1;
    }
    
#ifdef __AVR__
    return pgm_read_word(&primes[index & 15]);
#else
    return primes[index & 15];
#endif
}

/* ============================================================================
 * DERIVAÇÃO DE CHAVE
 * ============================================================================ */

static void tav_derive_key(tav_ctx_t* ctx, uint8_t* key) {
    uint32_t state_sum = 0;
    for (uint8_t c = 0; c < 4; c++) {
        state_sum += ctx->clocks.tick_count[c] * 100 + ctx->clocks.tx_count[c];
    }
    
    uint8_t offset = (state_sum * 7) % (TAV_MASTER_SIZE > TAV_KEY_BYTES ? 
                                         TAV_MASTER_SIZE - TAV_KEY_BYTES : 1);
    
    for (uint8_t i = 0; i < TAV_KEY_BYTES; i++) {
        key[i] = ctx->master_entropy[(offset + i) % TAV_MASTER_SIZE];
    }
    
    /* Mistura primos */
    for (uint8_t b = 0; b < TAV_N_BOXES; b++) {
        uint16_t prime = tav_get_prime(b, ctx->boxes.index[b]);
        key[(b * 2) % TAV_KEY_BYTES] ^= (prime >> 8) & 0xFF;
        key[(b * 2 + 1) % TAV_KEY_BYTES] ^= prime & 0xFF;
    }
}

/* ============================================================================
 * KEYSTREAM
 * ============================================================================ */

static void tav_keystream(const uint8_t* key, const uint8_t* nonce,
                          uint8_t* out, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        uint8_t k = key[i % TAV_KEY_BYTES];
        uint8_t n = nonce[i % TAV_NONCE_BYTES];
        uint8_t rotated = tav_rot_left(k, i & 7);
        out[i] = rotated ^ n ^ (i & 0xFF);
    }
}

/* ============================================================================
 * TICK
 * ============================================================================ */

static const uint8_t CLOCK_PRIMES[4] = {17, 23, 31, 47};

void tav_tick(tav_ctx_t* ctx, uint8_t n) {
    ctx->tx_global += n;
    
    for (uint8_t t = 0; t < n; t++) {
        for (uint8_t c = 0; c < 4; c++) {
            ctx->clocks.tx_count[c]++;
            if (ctx->clocks.tx_count[c] >= CLOCK_PRIMES[c]) {
                ctx->clocks.tick_count[c]++;
                ctx->clocks.tx_count[c] = 0;
                
                /* Avança caixas */
                if (c < TAV_N_BOXES) {
                    ctx->boxes.index[c] = (ctx->boxes.index[c] + 1) & 15;
                }
            }
        }
    }
}

/* ============================================================================
 * API PRINCIPAL
 * ============================================================================ */

tav_result_t tav_init(tav_ctx_t* ctx, const uint8_t* seed, uint8_t seed_len) {
    memset(ctx, 0, sizeof(tav_ctx_t));
    
    /* Calibra */
    for (uint8_t i = 0; i < 50; i++) {
        uint32_t t = tav_collect_xor(ctx);
        tav_mixer_update(&ctx->mixer, t);
    }
    
    /* Normaliza seed */
    uint8_t seed_norm[TAV_MASTER_SIZE];
    memset(seed_norm, 0, TAV_MASTER_SIZE);
    for (uint8_t i = 0; i < seed_len; i++) {
        seed_norm[i % TAV_MASTER_SIZE] ^= seed[i];
    }
    
    /* Gera entropia */
    for (uint8_t i = 0; i < TAV_MASTER_SIZE; i++) {
        uint32_t t = tav_collect_xor(ctx);
        tav_mixer_update(&ctx->mixer, t);
    }
    
    uint8_t clock_entropy[TAV_MASTER_SIZE];
    tav_mixer_extract(&ctx->mixer, clock_entropy, TAV_MASTER_SIZE);
    
    /* Combina */
    for (uint8_t i = 0; i < TAV_MASTER_SIZE; i++) {
        ctx->master_entropy[i] = seed_norm[i] ^ clock_entropy[i];
    }
    
    ctx->initialized = 1;
    return TAV_OK;
}

tav_result_t tav_encrypt(tav_ctx_t* ctx, 
                         const uint8_t* plaintext, uint16_t pt_len,
                         uint8_t* ciphertext, uint16_t* ct_len,
                         uint8_t auto_tick) {
    if (!ctx->initialized) return TAV_ERROR_DATA;
    
    *ct_len = TAV_OVERHEAD + pt_len;
    
    /* Deriva chave */
    uint8_t key[TAV_KEY_BYTES];
    tav_derive_key(ctx, key);
    
    /* Nonce */
    uint8_t nonce[TAV_NONCE_BYTES];
    tav_generate_nonce(ctx, nonce);
    
    /* Metadata */
    uint8_t metadata[8];
    metadata[0] = 0x91;
    metadata[1] = TAV_SECURITY_LEVEL;
    metadata[2] = (ctx->tx_global >> 24) & 0xFF;
    metadata[3] = (ctx->tx_global >> 16) & 0xFF;
    metadata[4] = (ctx->tx_global >> 8) & 0xFF;
    metadata[5] = ctx->tx_global & 0xFF;
    metadata[6] = 0;
    metadata[7] = 0;
    
    /* Posições */
    uint8_t* enc_out = ciphertext + TAV_NONCE_BYTES + TAV_MAC_BYTES;
    
    /* Cifra metadata */
    uint8_t ks[8];
    tav_keystream(key, nonce, ks, 8);
    for (uint8_t i = 0; i < 8; i++) {
        enc_out[i] = metadata[i] ^ ks[i];
    }
    
    /* Cifra plaintext */
    for (uint16_t offset = 0; offset < pt_len; offset += 32) {
        uint8_t chunk = (pt_len - offset < 32) ? (pt_len - offset) : 32;
        uint8_t ks_chunk[32];
        tav_keystream(key, nonce, ks_chunk, chunk);
        
        /* Ajusta offset do keystream */
        for (uint8_t i = 0; i < chunk; i++) {
            ks_chunk[i] ^= ((offset + 8 + i) & 0xFF);
        }
        
        for (uint8_t i = 0; i < chunk; i++) {
            enc_out[8 + offset + i] = plaintext[offset + i] ^ ks_chunk[i];
        }
    }
    
    /* MAC */
    uint8_t mac_input[TAV_NONCE_BYTES + 8 + 256]; /* Buffer estático */
    memcpy(mac_input, nonce, TAV_NONCE_BYTES);
    memcpy(mac_input + TAV_NONCE_BYTES, enc_out, 8 + pt_len);
    
    uint8_t mac[TAV_MAC_BYTES];
    tav_mac_calc(key, mac_input, TAV_NONCE_BYTES + 8 + pt_len, mac);
    
    /* Monta output */
    memcpy(ciphertext, nonce, TAV_NONCE_BYTES);
    memcpy(ciphertext + TAV_NONCE_BYTES, mac, TAV_MAC_BYTES);
    
    if (auto_tick) {
        tav_tick(ctx, 1);
    }
    
    return TAV_OK;
}

tav_result_t tav_decrypt(tav_ctx_t* ctx,
                         const uint8_t* ciphertext, uint16_t ct_len,
                         uint8_t* plaintext, uint16_t* pt_len) {
    if (!ctx->initialized) return TAV_ERROR_DATA;
    if (ct_len < TAV_OVERHEAD) return TAV_ERROR_DATA;
    
    const uint8_t* nonce = ciphertext;
    const uint8_t* mac_recv = ciphertext + TAV_NONCE_BYTES;
    const uint8_t* encrypted = ciphertext + TAV_NONCE_BYTES + TAV_MAC_BYTES;
    uint16_t enc_len = ct_len - TAV_NONCE_BYTES - TAV_MAC_BYTES;
    
    /* Deriva chave */
    uint8_t key[TAV_KEY_BYTES];
    tav_derive_key(ctx, key);
    
    /* Verifica MAC */
    uint8_t mac_input[TAV_NONCE_BYTES + 8 + 256];
    memcpy(mac_input, nonce, TAV_NONCE_BYTES);
    memcpy(mac_input + TAV_NONCE_BYTES, encrypted, enc_len);
    
    uint8_t mac_exp[TAV_MAC_BYTES];
    tav_mac_calc(key, mac_input, TAV_NONCE_BYTES + enc_len, mac_exp);
    
    /* Constant-time compare */
    uint8_t diff = 0;
    for (uint8_t i = 0; i < TAV_MAC_BYTES; i++) {
        diff |= mac_recv[i] ^ mac_exp[i];
    }
    if (diff != 0) return TAV_ERROR_MAC;
    
    /* Decifra */
    uint8_t ks[8];
    tav_keystream(key, nonce, ks, 8);
    
    /* Pula metadata */
    *pt_len = enc_len - 8;
    
    for (uint16_t offset = 0; offset < *pt_len; offset += 32) {
        uint8_t chunk = (*pt_len - offset < 32) ? (*pt_len - offset) : 32;
        uint8_t ks_chunk[32];
        tav_keystream(key, nonce, ks_chunk, chunk);
        
        for (uint8_t i = 0; i < chunk; i++) {
            ks_chunk[i] ^= ((offset + 8 + i) & 0xFF);
        }
        
        for (uint8_t i = 0; i < chunk; i++) {
            plaintext[offset + i] = encrypted[8 + offset + i] ^ ks_chunk[i];
        }
    }
    
    return TAV_OK;
}

/* ============================================================================
 * ASSINATURA HASH-CHAIN (versão compacta)
 * ============================================================================ */

tav_result_t tav_sign_init(tav_sign_t* s, const uint8_t* seed, uint8_t seed_len,
                           uint16_t chain_len) {
    s->chain_length = chain_len;
    s->current_index = 0;
    
    tav_hash(seed, seed_len, s->private_seed);
    
    /* Gera public key */
    uint8_t current[TAV_HASH_SIZE];
    memcpy(current, s->private_seed, TAV_HASH_SIZE);
    
    for (uint16_t i = 0; i < chain_len; i++) {
        uint8_t next[TAV_HASH_SIZE];
        tav_hash(current, TAV_HASH_SIZE, next);
        memcpy(current, next, TAV_HASH_SIZE);
    }
    
    memcpy(s->public_key, current, TAV_HASH_SIZE);
    return TAV_OK;
}

tav_result_t tav_sign_sign(tav_sign_t* s, const uint8_t* msg, uint16_t msg_len,
                           uint8_t* sig, uint8_t* sig_len) {
    if (s->current_index >= s->chain_length) return TAV_ERROR_CHAIN;
    
    /* Calcula reveal */
    uint16_t steps = s->chain_length - s->current_index - 1;
    uint8_t reveal[TAV_HASH_SIZE];
    memcpy(reveal, s->private_seed, TAV_HASH_SIZE);
    
    for (uint16_t i = 0; i < steps; i++) {
        uint8_t next[TAV_HASH_SIZE];
        tav_hash(reveal, TAV_HASH_SIZE, next);
        memcpy(reveal, next, TAV_HASH_SIZE);
    }
    
    /* MAC */
    uint8_t mac_input[256 + TAV_HASH_SIZE];
    memcpy(mac_input, msg, msg_len);
    memcpy(mac_input + msg_len, reveal, TAV_HASH_SIZE);
    
    uint8_t mac[TAV_HASH_SIZE];
    tav_hash(mac_input, msg_len + TAV_HASH_SIZE, mac);
    
    /* Assinatura */
    sig[0] = (s->current_index >> 8) & 0xFF;
    sig[1] = s->current_index & 0xFF;
    memcpy(sig + 2, reveal, TAV_HASH_SIZE);
    memcpy(sig + 2 + TAV_HASH_SIZE, mac, TAV_HASH_SIZE);
    
    *sig_len = 2 + TAV_HASH_SIZE * 2;
    s->current_index++;
    
    return TAV_OK;
}

tav_result_t tav_sign_verify(const uint8_t* pub_key, 
                              const uint8_t* msg, uint16_t msg_len,
                              const uint8_t* sig, uint8_t sig_len) {
    if (sig_len < 2 + TAV_HASH_SIZE * 2) return TAV_ERROR_DATA;
    
    uint16_t index = ((uint16_t)sig[0] << 8) | sig[1];
    const uint8_t* reveal = sig + 2;
    const uint8_t* mac = sig + 2 + TAV_HASH_SIZE;
    
    /* Verifica MAC */
    uint8_t mac_input[256 + TAV_HASH_SIZE];
    memcpy(mac_input, msg, msg_len);
    memcpy(mac_input + msg_len, reveal, TAV_HASH_SIZE);
    
    uint8_t mac_exp[TAV_HASH_SIZE];
    tav_hash(mac_input, msg_len + TAV_HASH_SIZE, mac_exp);
    
    uint8_t diff = 0;
    for (uint8_t i = 0; i < TAV_HASH_SIZE; i++) {
        diff |= mac[i] ^ mac_exp[i];
    }
    if (diff != 0) return TAV_ERROR_MAC;
    
    /* Verifica chain */
    uint8_t current[TAV_HASH_SIZE];
    memcpy(current, reveal, TAV_HASH_SIZE);
    
    for (uint16_t i = 0; i <= index; i++) {
        uint8_t next[TAV_HASH_SIZE];
        tav_hash(current, TAV_HASH_SIZE, next);
        memcpy(current, next, TAV_HASH_SIZE);
    }
    
    diff = 0;
    for (uint8_t i = 0; i < TAV_HASH_SIZE; i++) {
        diff |= current[i] ^ pub_key[i];
    }
    if (diff != 0) return TAV_ERROR_MAC;
    
    return TAV_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* TAV_ARDUINO_H */
