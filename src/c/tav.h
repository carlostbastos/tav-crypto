/*
 * TAV Clock Cryptography v0.9
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
 *
 * TAV CLOCK CRYPTOGRAPHY v0.9 - C Implementation
 * ===============================================
 * 
 * A stateful cryptographic system based on ephemeral structure
 * and continuous physical entropy.
 * 
 * Features:
 * - Lookup tables ROT_LEFT pre-computed
 * - Automatic checkpoint every 10,000 transactions
 * - Encrypted checkpoint (self-protecting)
 * - Hardware change detection
 * - Threat management with dynamic escalation
 * - Dead-man switch protection
 */

#ifndef TAV_H
#define TAV_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTES
 * ============================================================================ */

#define TAV_VERSION "0.9"
#define TAV_VERSION_BYTE 0x09

#define TAV_POOL_SIZE 64
#define TAV_CONST_SIZE 32
#define TAV_MAX_KEY_BYTES 32
#define TAV_MAX_NONCE_BYTES 24
#define TAV_MAX_MAC_BYTES 24
#define TAV_MAX_MASTER_ENTROPY 128
#define TAV_MAX_BOXES 6
#define TAV_MAX_CLOCKS 4
#define TAV_CHECKPOINT_INTERVAL 10000
#define TAV_POOL_TTL 1000

/* CÃ³digos de resultado */
typedef enum {
    TAV_OK = 0,
    TAV_ERROR_NULL_POINTER = -1,
    TAV_ERROR_NOT_INITIALIZED = -2,
    TAV_ERROR_INVALID_LEVEL = -3,
    TAV_ERROR_MAC_MISMATCH = -4,
    TAV_ERROR_INVALID_DATA = -5,
    TAV_ERROR_CHECKPOINT_FAILED = -6,
    TAV_ERROR_HARDWARE_CHANGED = -7
} tav_result_t;

/* NÃ­veis de seguranÃ§a */
typedef enum {
    TAV_LEVEL_IOT = 1,
    TAV_LEVEL_CONSUMER = 2,
    TAV_LEVEL_ENTERPRISE = 3,
    TAV_LEVEL_MILITARY = 4
} tav_level_t;

/* ============================================================================
 * ESTRUTURAS
 * ============================================================================ */

/* ConfiguraÃ§Ã£o por nÃ­vel */
typedef struct {
    uint8_t master_entropy_size;
    uint8_t key_bytes;
    uint8_t nonce_bytes;
    uint8_t mac_bytes;
    uint8_t n_xor;
    uint8_t n_rounds_mixer;
    uint8_t n_rounds_mac;
    uint8_t initial_boxes[6];
    uint8_t n_initial_boxes;
} tav_config_t;

/* Mixer Feistel */
typedef struct {
    uint8_t pool[TAV_POOL_SIZE];
    uint32_t counter;
    uint8_t n_rounds;
} tav_mixer_t;

/* Entropia com TTL */
typedef struct {
    uint8_t data[TAV_POOL_SIZE];
    uint8_t size;
    uint64_t tx_created;
} tav_entropy_entry_t;

/* Gerador de entropia */
typedef struct {
    tav_mixer_t mixer;
    uint8_t n_xor;
    uint64_t nonce_counter;
    uint8_t work_index;
    /* Pool quente com TTL */
    tav_entropy_entry_t hot_pool[4];
    uint8_t hot_pool_count;
    uint64_t current_tx;
} tav_entropy_t;

/* MAC Feistel */
typedef struct {
    uint8_t n_rounds;
} tav_mac_t;

/* Caixa de primos */
typedef struct {
    const uint32_t* primes;
    uint16_t count;
    uint16_t index;
    bool active;
} tav_prime_box_t;

/* RelÃ³gio transacional */
typedef struct {
    uint8_t tick_prime;
    uint8_t boxes[3];
    uint8_t n_boxes;
    uint32_t tick_count;
    uint32_t tx_count;
    bool active;
} tav_clock_t;

/* Perfil de hardware */
typedef struct {
    float bias_bits[8];
    float timing_mean;
    float timing_std;
} tav_hw_profile_t;

/* Checkpoint */
typedef struct {
    uint64_t tx_count_global;
    uint32_t boot_count;
    uint8_t level;
    uint8_t master_entropy[TAV_MAX_MASTER_ENTROPY];
    uint8_t master_entropy_size;
    uint32_t clock_tick_counts[TAV_MAX_CLOCKS];
    uint32_t clock_tx_counts[TAV_MAX_CLOCKS];
    uint16_t box_indices[TAV_MAX_BOXES];
    tav_hw_profile_t hw_profile;
    uint64_t nonce_counter;
} tav_checkpoint_data_t;

/* Contexto principal */
typedef struct {
    bool initialized;
    tav_level_t level;
    tav_config_t config;
    
    tav_entropy_t entropy;
    tav_mac_t mac;
    tav_prime_box_t boxes[TAV_MAX_BOXES];
    tav_clock_t clocks[TAV_MAX_CLOCKS];
    tav_hw_profile_t baseline;
    
    uint8_t master_entropy[TAV_MAX_MASTER_ENTROPY];
    uint8_t master_entropy_size;
    uint8_t checkpoint_key[32];
    
    uint64_t tx_count_global;
    uint64_t last_tx;
    uint64_t last_checkpoint_tx;
    uint32_t boot_count;
    bool hardware_changed;
    
    /* Callback para salvar/carregar checkpoint */
    int (*checkpoint_save)(const uint8_t* data, size_t len, void* user_data);
    int (*checkpoint_load)(uint8_t* data, size_t* len, void* user_data);
    void* checkpoint_user_data;
} tav_ctx_t;

/* ============================================================================
 * LOOKUP TABLES
 * ============================================================================ */

/* RotaÃ§Ã£o Ã  esquerda prÃ©-computada: ROT_LEFT[rot][byte] */
extern const uint8_t TAV_ROT_LEFT[8][256];

/* Constantes do Mixer */
extern const uint8_t TAV_CONST_AND[TAV_CONST_SIZE];
extern const uint8_t TAV_CONST_OR[TAV_CONST_SIZE];

/* ============================================================================
 * API PRINCIPAL
 * ============================================================================ */

/**
 * Inicializa contexto TAV
 * @param ctx Contexto a ser inicializado
 * @param seed Seed/senha
 * @param seed_len Tamanho da seed
 * @param level NÃ­vel de seguranÃ§a
 * @return TAV_OK em sucesso
 */
tav_result_t tav_init(tav_ctx_t* ctx, const uint8_t* seed, size_t seed_len, tav_level_t level);

/**
 * Configura callbacks de checkpoint
 */
void tav_set_checkpoint_callbacks(tav_ctx_t* ctx,
    int (*save)(const uint8_t* data, size_t len, void* user_data),
    int (*load)(uint8_t* data, size_t* len, void* user_data),
    void* user_data);

/**
 * Limpa contexto
 */
void tav_cleanup(tav_ctx_t* ctx);

/**
 * Retorna overhead de criptografia
 */
size_t tav_overhead(tav_level_t level);

/**
 * AvanÃ§a estado manualmente
 */
void tav_tick(tav_ctx_t* ctx, uint32_t n);

/**
 * Encripta dados
 */
tav_result_t tav_encrypt(tav_ctx_t* ctx,
                         const uint8_t* plaintext, size_t pt_len,
                         uint8_t* ciphertext, size_t* ct_len,
                         bool auto_tick);

/**
 * Decripta dados
 */
tav_result_t tav_decrypt(tav_ctx_t* ctx,
                         const uint8_t* ciphertext, size_t ct_len,
                         uint8_t* plaintext, size_t* pt_len);

/**
 * Verifica se hardware Ã© o mesmo
 */
bool tav_verify_hardware(tav_ctx_t* ctx, float* similarity);

/**
 * ForÃ§a salvamento de checkpoint
 */
tav_result_t tav_force_checkpoint(tav_ctx_t* ctx);

/**
 * Retorna estatÃ­sticas
 */
void tav_get_stats(tav_ctx_t* ctx, uint64_t* tx_count, uint32_t* boot_count, 
                   uint64_t* last_checkpoint_tx, bool* hw_changed);

/* ============================================================================
 * FUNÃ‡Ã•ES AUXILIARES
 * ============================================================================ */

uint64_t tav_get_time_ns(void);
bool tav_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);

/* RotaÃ§Ã£o inline usando lookup table */
static inline uint8_t tav_rot_left(uint8_t b, uint8_t n) {
    return TAV_ROT_LEFT[n & 7][b];
}

#ifdef __cplusplus
}
#endif

#endif /* TAV_H */
