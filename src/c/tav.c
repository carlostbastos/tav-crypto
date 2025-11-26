/*
 * TAV CLOCK CRYPTOGRAPHY V9.1 - Implementação C
 * ==============================================
 * 
 * Licença: MIT
 * Data: Novembro 2025
 */

#include "tav.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#include <math.h>

/* ============================================================================
 * CONSTANTES
 * ============================================================================ */

const uint8_t TAV_CONST_AND[TAV_CONST_SIZE] = {
    0xB7, 0x5D, 0xA3, 0xE1, 0x97, 0x4F, 0xC5, 0x2B,
    0x8D, 0x61, 0xF3, 0x1F, 0xD9, 0x73, 0x3D, 0xAF,
    0x17, 0x89, 0xCB, 0x53, 0xE7, 0x2D, 0x9B, 0x41,
    0xBB, 0x6D, 0xF1, 0x23, 0xDD, 0x7F, 0x35, 0xA9
};

const uint8_t TAV_CONST_OR[TAV_CONST_SIZE] = {
    0x11, 0x22, 0x44, 0x08, 0x10, 0x21, 0x42, 0x04,
    0x12, 0x24, 0x48, 0x09, 0x14, 0x28, 0x41, 0x02,
    0x18, 0x30, 0x60, 0x05, 0x0A, 0x15, 0x2A, 0x54,
    0x19, 0x32, 0x64, 0x06, 0x0C, 0x19, 0x33, 0x66
};

/* Primos Caixa 1 (2 dígitos) */
static const uint32_t PRIMES_BOX_1[] = {
    11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97
};
#define PRIMES_BOX_1_COUNT 21

/* Primos Caixa 2 (3 dígitos) - primeiros 50 */
static const uint32_t PRIMES_BOX_2[] = {
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
    199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379
};
#define PRIMES_BOX_2_COUNT 50

/* Primos Caixa 3 (4 dígitos) - primeiros 50 */
static const uint32_t PRIMES_BOX_3[] = {
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061,
    1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123,
    1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
    1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
    1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361
};
#define PRIMES_BOX_3_COUNT 50

/* Primos Caixa 4 (5 dígitos) - primeiros 50 */
static const uint32_t PRIMES_BOX_4[] = {
    10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093,
    10099, 10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163, 10169,
    10177, 10181, 10193, 10211, 10223, 10243, 10247, 10253, 10259, 10267,
    10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331, 10333, 10337,
    10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433, 10453, 10457
};
#define PRIMES_BOX_4_COUNT 50

/* Primos Caixa 5 (7 dígitos) - primeiros 30 */
static const uint32_t PRIMES_BOX_5[] = {
    1000003, 1000033, 1000037, 1000039, 1000081, 1000099, 1000117, 1000121,
    1000133, 1000151, 1000159, 1000171, 1000183, 1000187, 1000193, 1000199,
    1000211, 1000213, 1000231, 1000249, 1000253, 1000273, 1000289, 1000291,
    1000303, 1000313, 1000333, 1000357, 1000367, 1000381
};
#define PRIMES_BOX_5_COUNT 30

/* Primos Caixa 6 (9 dígitos) - primeiros 20 */
static const uint32_t PRIMES_BOX_6[] = {
    100000007, 100000037, 100000039, 100000049, 100000073, 100000081,
    100000123, 100000127, 100000193, 100000213, 100000217, 100000223,
    100000231, 100000237, 100000259, 100000267, 100000279, 100000357,
    100000379, 100000393
};
#define PRIMES_BOX_6_COUNT 20

/* Configurações por nível */
static const tav_config_t CONFIGS[] = {
    {0}, /* Placeholder for index 0 */
    /* IOT (1) */
    {32, 16, 8, 8, 2, 2, 4, {1, 2, 0, 0, 0, 0}, 2},
    /* CONSUMER (2) */
    {48, 24, 12, 12, 2, 3, 6, {1, 2, 3, 0, 0, 0}, 3},
    /* ENTERPRISE (3) */
    {64, 32, 16, 16, 3, 4, 8, {1, 2, 3, 4, 0, 0}, 4},
    /* MILITARY (4) */
    {64, 32, 16, 16, 4, 6, 8, {1, 2, 3, 4, 5, 0}, 5}
};

/* Configuração dos relógios */
static const uint8_t CLOCK_PRIMES[] = {17, 23, 31, 47};
static const uint8_t CLOCK_BOXES[][3] = {
    {1, 2, 3},
    {1, 3, 4},
    {2, 3, 4},
    {2, 4, 5}
};

/* ============================================================================
 * FUNÇÕES AUXILIARES
 * ============================================================================ */

uint64_t tav_get_time_ns(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

bool tav_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/* ============================================================================
 * MIXER FEISTEL
 * ============================================================================ */

static void mixer_function_f(const uint8_t* data, size_t len, 
                             uint8_t round, uint8_t* out) {
    for (size_t i = 0; i < len; i++) {
        uint8_t x = data[i];
        x = tav_rot_left(x, (round + i) & 7);
        x = x & TAV_CONST_AND[(i + round * 7) & 31];
        x = x | TAV_CONST_OR[(i + round * 11) & 31];
        x = x ^ data[(i + round + 1) % len];
        out[i] = x;
    }
}

static void mixer_feistel_round(uint8_t* data, size_t len, uint8_t round) {
    size_t half = len / 2;
    uint8_t f_out[TAV_POOL_SIZE / 2];
    
    /* F(R) */
    mixer_function_f(data + half, half, round, f_out);
    
    /* Novo R = L XOR F(R) */
    uint8_t new_r[TAV_POOL_SIZE / 2];
    for (size_t i = 0; i < half; i++) {
        new_r[i] = data[i] ^ f_out[i];
    }
    
    /* Swap: novo L = R antigo, novo R calculado */
    memmove(data, data + half, half);
    memcpy(data + half, new_r, half);
}

static void mixer_update(tav_mixer_t* mixer, uint64_t entropy) {
    size_t pos = mixer->counter % TAV_POOL_SIZE;
    mixer->pool[pos] ^= entropy & 0xFF;
    mixer->pool[(pos + 1) % TAV_POOL_SIZE] ^= (entropy >> 8) & 0xFF;
    mixer->counter++;
}

static void mixer_extract(tav_mixer_t* mixer, uint8_t* out, size_t len) {
    uint8_t mixed[TAV_POOL_SIZE];
    memcpy(mixed, mixer->pool, TAV_POOL_SIZE);
    
    /* Aplica rodadas Feistel */
    for (uint8_t r = 0; r < mixer->n_rounds; r++) {
        mixer_feistel_round(mixed, TAV_POOL_SIZE, r + (uint8_t)mixer->counter);
    }
    
    /* Expande se necessário */
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = (len - offset < TAV_POOL_SIZE) ? (len - offset) : TAV_POOL_SIZE;
        memcpy(out + offset, mixed, chunk);
        offset += chunk;
        
        if (offset < len) {
            mixer->counter++;
            for (uint8_t r = 0; r < mixer->n_rounds; r++) {
                mixer_feistel_round(mixed, TAV_POOL_SIZE, r + (uint8_t)mixer->counter);
            }
        }
    }
}

/* ============================================================================
 * MAC FEISTEL
 * ============================================================================ */

static void mac_function_f(const uint8_t* data, size_t len,
                          uint8_t round, const uint8_t* key, size_t key_len,
                          uint8_t* out) {
    for (size_t i = 0; i < len; i++) {
        uint8_t x = data[i];
        uint8_t k = key[i % key_len];
        x = tav_rot_left(x ^ k, (round + i) & 7);
        x = x & TAV_CONST_AND[(i + round * 7) & 31];
        x = x | TAV_CONST_OR[(i + round * 11) & 31];
        x = x ^ data[(i + round + 1) % len];
        x = x ^ k;
        out[i] = x;
    }
}

static void mac_feistel_round(uint8_t* state, uint8_t round,
                              const uint8_t* key, size_t key_len) {
    uint8_t f_out[16];
    
    mac_function_f(state + 16, 16, round, key, key_len, f_out);
    
    uint8_t new_r[16];
    for (size_t i = 0; i < 16; i++) {
        new_r[i] = state[i] ^ f_out[i];
    }
    
    memmove(state, state + 16, 16);
    memcpy(state + 16, new_r, 16);
}

static void mac_calculate(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t n_rounds,
                         uint8_t* out, size_t out_len) {
    uint8_t state[32];
    
    /* Inicializa estado com chave */
    for (size_t i = 0; i < 32; i++) {
        state[i] = key[i % key_len];
    }
    
    /* Processa dados em blocos de 32 */
    for (size_t offset = 0; offset < data_len; offset += 32) {
        size_t chunk = (data_len - offset < 32) ? (data_len - offset) : 32;
        
        for (size_t i = 0; i < chunk; i++) {
            state[i] ^= data[offset + i];
        }
        
        for (uint8_t r = 0; r < n_rounds; r++) {
            mac_feistel_round(state, r, key, key_len);
        }
    }
    
    /* Finalização: inclui tamanho */
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++) {
        len_bytes[i] = (data_len >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 8; i++) {
        state[i] ^= len_bytes[i];
    }
    
    for (uint8_t r = 0; r < n_rounds; r++) {
        mac_feistel_round(state, r + n_rounds, key, key_len);
    }
    
    memcpy(out, state, out_len);
}

/* ============================================================================
 * HASH (baseado em Feistel - para assinaturas)
 * ============================================================================ */

void tav_hash(const uint8_t* data, size_t len, uint8_t* out) {
    /* Usa MAC-Feistel com chave fixa como hash */
    static const uint8_t HASH_KEY[32] = {
        0x54, 0x41, 0x56, 0x2D, 0x48, 0x41, 0x53, 0x48, /* "TAV-HASH" */
        0x56, 0x39, 0x2E, 0x31, 0x2D, 0x32, 0x30, 0x32, /* "V9.1-202" */
        0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* "5" + padding */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    mac_calculate(HASH_KEY, 32, data, len, 8, out, TAV_SIGN_HASH_SIZE);
}

/* ============================================================================
 * GERADOR DE ENTROPIA
 * ============================================================================ */

static uint64_t entropy_collect_timing(tav_entropy_t* ent) {
    volatile uint32_t x = 0;
    uint64_t t1 = tav_get_time_ns();
    
    /* Trabalho variável */
    switch (ent->work_index & 3) {
        case 0: for (int i = 0; i < 10; i++) x += i; break;
        case 1: for (int i = 0; i < 8; i++) x += i; break;
        case 2: for (int i = 0; i < 12; i++) x += i; break;
        case 3: for (int i = 0; i < 5; i++) x += i * i; break;
    }
    ent->work_index++;
    
    uint64_t t2 = tav_get_time_ns();
    (void)x; /* Evita warning de variável não usada */
    return t2 - t1;
}

static uint64_t entropy_collect_xor(tav_entropy_t* ent) {
    uint64_t result = 0;
    for (uint8_t i = 0; i < ent->n_xor; i++) {
        result ^= entropy_collect_timing(ent);
    }
    return result;
}

static void entropy_generate(tav_entropy_t* ent, uint8_t* out, size_t len) {
    /* Alimenta mixer */
    size_t feeds = (len / 2 > 16) ? (len / 2) : 16;
    for (size_t i = 0; i < feeds; i++) {
        uint64_t timing = entropy_collect_xor(ent);
        mixer_update(&ent->mixer, timing);
    }
    
    /* Extrai */
    mixer_extract(&ent->mixer, out, len);
}

static void entropy_generate_nonce(tav_entropy_t* ent, uint8_t* out, size_t len) {
    ent->nonce_counter++;
    
    uint64_t timing1 = entropy_collect_xor(ent);
    uint64_t timing2 = entropy_collect_xor(ent);
    
    memset(out, 0, len);
    
    if (len >= 16) {
        for (int i = 0; i < 8 && i < (int)len; i++) {
            out[i] = (timing1 >> (i * 8)) & 0xFF;
        }
        for (int i = 0; i < 4 && (8 + i) < (int)len; i++) {
            out[8 + i] = (ent->nonce_counter >> (24 - i * 8)) & 0xFF;
        }
        for (int i = 0; i < 4 && (12 + i) < (int)len; i++) {
            out[12 + i] = (timing2 >> (i * 8)) & 0xFF;
        }
    } else {
        for (int i = 0; i < 4 && i < (int)len; i++) {
            out[i] = (ent->nonce_counter >> (24 - i * 8)) & 0xFF;
        }
        for (int i = 0; i < 4 && (4 + i) < (int)len; i++) {
            out[4 + i] = (timing1 >> (i * 8)) & 0xFF;
        }
    }
}

/* ============================================================================
 * CAIXAS DE PRIMOS
 * ============================================================================ */

static void init_prime_boxes(tav_prime_box_t boxes[6]) {
    boxes[0].primes = PRIMES_BOX_1; boxes[0].count = PRIMES_BOX_1_COUNT;
    boxes[1].primes = PRIMES_BOX_2; boxes[1].count = PRIMES_BOX_2_COUNT;
    boxes[2].primes = PRIMES_BOX_3; boxes[2].count = PRIMES_BOX_3_COUNT;
    boxes[3].primes = PRIMES_BOX_4; boxes[3].count = PRIMES_BOX_4_COUNT;
    boxes[4].primes = PRIMES_BOX_5; boxes[4].count = PRIMES_BOX_5_COUNT;
    boxes[5].primes = PRIMES_BOX_6; boxes[5].count = PRIMES_BOX_6_COUNT;
    
    for (int i = 0; i < 6; i++) {
        boxes[i].index = 0;
        boxes[i].active = false;
    }
}

static uint32_t box_get_prime(tav_prime_box_t* box) {
    if (!box->active || box->count == 0) return 1;
    return box->primes[box->index % box->count];
}

static void box_advance(tav_prime_box_t* box) {
    if (box->active && box->count > 0) {
        box->index = (box->index + 1) % box->count;
    }
}

/* ============================================================================
 * RELÓGIOS
 * ============================================================================ */

static void init_clocks(tav_clock_t clocks[4], tav_level_t level) {
    for (int i = 0; i < 4; i++) {
        clocks[i].id = i;
        clocks[i].tick_prime = CLOCK_PRIMES[i];
        memcpy(clocks[i].boxes, CLOCK_BOXES[i], 3);
        clocks[i].n_boxes = 3;
        clocks[i].tick_count = 0;
        clocks[i].tx_count = 0;
        clocks[i].active = (i < (int)level);
    }
}

static bool clock_tick(tav_clock_t* clock) {
    if (!clock->active) return false;
    
    clock->tx_count++;
    if (clock->tx_count >= clock->tick_prime) {
        clock->tick_count++;
        clock->tx_count = clock->tx_count % clock->tick_prime;
        return true;
    }
    return false;
}

/* ============================================================================
 * DERIVAÇÃO DE CHAVE
 * ============================================================================ */

static void derive_key(tav_ctx_t* ctx, uint8_t* key_out) {
    uint64_t state_sum = 0;
    for (int i = 0; i < 4; i++) {
        if (ctx->clocks[i].active) {
            state_sum += ctx->clocks[i].tick_count * 1000 + ctx->clocks[i].tx_count;
        }
    }
    
    size_t key_len = ctx->config.key_bytes;
    size_t master_len = ctx->master_entropy_size;
    
    size_t offset = (state_sum * 7) % (master_len > key_len ? master_len - key_len : 1);
    
    /* Base da chave */
    for (size_t i = 0; i < key_len; i++) {
        key_out[i] = ctx->master_entropy[(offset + i) % master_len];
    }
    
    /* Mistura com primos */
    for (int c = 0; c < 4; c++) {
        if (!ctx->clocks[c].active) continue;
        
        for (int b = 0; b < ctx->clocks[c].n_boxes; b++) {
            int box_idx = ctx->clocks[c].boxes[b] - 1;
            if (box_idx < 0 || box_idx >= 6) continue;
            if (!ctx->boxes[box_idx].active) continue;
            
            uint32_t prime = box_get_prime(&ctx->boxes[box_idx]);
            uint8_t prime_bytes[8];
            for (int i = 0; i < 8; i++) {
                prime_bytes[i] = (prime >> (56 - i * 8)) & 0xFF;
            }
            
            for (int j = 0; j < 8; j++) {
                size_t pos = (ctx->clocks[c].id * 8 + j) % key_len;
                key_out[pos] ^= prime_bytes[j];
            }
        }
    }
}

/* ============================================================================
 * KEYSTREAM
 * ============================================================================ */

static void generate_keystream(const uint8_t* key, size_t key_len,
                              const uint8_t* nonce, size_t nonce_len,
                              uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t k = key[i % key_len];
        uint8_t n = nonce[i % nonce_len];
        uint8_t rot = i & 7;
        uint8_t rotated = tav_rot_left(k, rot);
        out[i] = rotated ^ n ^ (i & 0xFF);
    }
}

/* ============================================================================
 * API PRINCIPAL
 * ============================================================================ */

tav_result_t tav_init(tav_ctx_t* ctx, 
                      const uint8_t* seed, 
                      size_t seed_len,
                      tav_level_t level) {
    if (!ctx || !seed) return TAV_ERROR_NULL_POINTER;
    if (level < TAV_LEVEL_IOT || level > TAV_LEVEL_MILITARY) {
        return TAV_ERROR_INVALID_LEVEL;
    }
    
    memset(ctx, 0, sizeof(tav_ctx_t));
    
    ctx->level = level;
    ctx->config = CONFIGS[level];
    
    /* Inicializa entropia */
    ctx->entropy.n_xor = ctx->config.n_xor;
    ctx->entropy.mixer.n_rounds = ctx->config.n_rounds_mixer;
    ctx->entropy.nonce_counter = 0;
    ctx->entropy.work_index = 0;
    memset(ctx->entropy.mixer.pool, 0, TAV_POOL_SIZE);
    
    /* Calibra (pré-aquece) */
    for (int i = 0; i < 100; i++) {
        uint64_t timing = entropy_collect_xor(&ctx->entropy);
        mixer_update(&ctx->entropy.mixer, timing);
    }
    
    /* Inicializa MAC */
    ctx->mac.n_rounds = ctx->config.n_rounds_mac;
    
    /* Inicializa caixas */
    init_prime_boxes(ctx->boxes);
    for (int i = 0; i < ctx->config.n_initial_boxes; i++) {
        int box_idx = ctx->config.initial_boxes[i] - 1;
        if (box_idx >= 0 && box_idx < 6) {
            ctx->boxes[box_idx].active = true;
        }
    }
    
    /* Inicializa relógios */
    init_clocks(ctx->clocks, level);
    
    /* Gera master entropy */
    ctx->master_entropy_size = ctx->config.master_entropy_size;
    
    /* Normaliza seed com XOR cíclico */
    uint8_t seed_normalized[TAV_MAX_MASTER_ENTROPY];
    memset(seed_normalized, 0, ctx->master_entropy_size);
    for (size_t i = 0; i < seed_len; i++) {
        seed_normalized[i % ctx->master_entropy_size] ^= seed[i];
    }
    
    /* Gera entropia física */
    uint8_t clock_entropy[TAV_MAX_MASTER_ENTROPY * 2];
    entropy_generate(&ctx->entropy, clock_entropy, ctx->master_entropy_size * 2);
    
    /* Combina */
    for (size_t i = 0; i < ctx->master_entropy_size; i++) {
        ctx->master_entropy[i] = seed_normalized[i] ^ clock_entropy[i];
    }
    for (size_t i = ctx->master_entropy_size; i < ctx->master_entropy_size * 2 && 
         i < TAV_MAX_MASTER_ENTROPY; i++) {
        ctx->master_entropy[i] = clock_entropy[i];
    }
    
    ctx->tx_count_global = 0;
    ctx->last_tx = 0;
    ctx->initialized = true;
    
    return TAV_OK;
}

void tav_cleanup(tav_ctx_t* ctx) {
    if (ctx) {
        /* Zera dados sensíveis */
        memset(ctx->master_entropy, 0, sizeof(ctx->master_entropy));
        memset(ctx->entropy.mixer.pool, 0, TAV_POOL_SIZE);
        ctx->initialized = false;
    }
}

size_t tav_overhead(tav_level_t level) {
    if (level < TAV_LEVEL_IOT || level > TAV_LEVEL_MILITARY) return 0;
    const tav_config_t* cfg = &CONFIGS[level];
    return cfg->nonce_bytes + cfg->mac_bytes + 8; /* 8 = metadata */
}

void tav_tick(tav_ctx_t* ctx, uint32_t n) {
    if (!ctx || !ctx->initialized) return;
    
    ctx->tx_count_global += n;
    ctx->last_tx = ctx->tx_count_global;
    
    for (uint32_t t = 0; t < n; t++) {
        for (int c = 0; c < 4; c++) {
            if (clock_tick(&ctx->clocks[c])) {
                for (int b = 0; b < ctx->clocks[c].n_boxes; b++) {
                    int box_idx = ctx->clocks[c].boxes[b] - 1;
                    if (box_idx >= 0 && box_idx < 6) {
                        box_advance(&ctx->boxes[box_idx]);
                    }
                }
            }
        }
    }
    
    /* Relógios lentos */
    if (ctx->tx_count_global % 100 == 0 && ctx->boxes[4].active) {
        box_advance(&ctx->boxes[4]);
    }
    if (ctx->tx_count_global % 1000 == 0 && ctx->boxes[5].active) {
        box_advance(&ctx->boxes[5]);
    }
}

tav_result_t tav_encrypt(tav_ctx_t* ctx,
                         const uint8_t* plaintext,
                         size_t pt_len,
                         uint8_t* ciphertext,
                         size_t* ct_len,
                         bool auto_tick) {
    if (!ctx || !ciphertext || !ct_len) return TAV_ERROR_NULL_POINTER;
    if (!ctx->initialized) return TAV_ERROR_NOT_INITIALIZED;
    
    size_t nonce_len = ctx->config.nonce_bytes;
    size_t mac_len = ctx->config.mac_bytes;
    size_t key_len = ctx->config.key_bytes;
    size_t metadata_len = 8;
    
    *ct_len = nonce_len + mac_len + metadata_len + pt_len;
    
    /* Deriva chave */
    uint8_t key[TAV_MAX_KEY_BYTES];
    derive_key(ctx, key);
    
    /* Gera nonce */
    uint8_t nonce[TAV_MAX_NONCE_BYTES];
    entropy_generate_nonce(&ctx->entropy, nonce, nonce_len);
    
    /* Metadata */
    uint8_t metadata[8];
    metadata[0] = 0x91; /* Versão */
    metadata[1] = ctx->level;
    for (int i = 0; i < 6; i++) {
        metadata[2 + i] = (ctx->tx_count_global >> (40 - i * 8)) & 0xFF;
    }
    
    /* Dados = metadata + plaintext */
    size_t data_len = metadata_len + pt_len;
    uint8_t* data = (uint8_t*)malloc(data_len);
    if (!data) return TAV_ERROR_NULL_POINTER;
    
    memcpy(data, metadata, metadata_len);
    if (pt_len > 0 && plaintext) {
        memcpy(data + metadata_len, plaintext, pt_len);
    }
    
    /* Cifra */
    uint8_t* keystream = (uint8_t*)malloc(data_len);
    if (!keystream) { free(data); return TAV_ERROR_NULL_POINTER; }
    
    generate_keystream(key, key_len, nonce, nonce_len, keystream, data_len);
    
    uint8_t* encrypted = ciphertext + nonce_len + mac_len;
    for (size_t i = 0; i < data_len; i++) {
        encrypted[i] = data[i] ^ keystream[i];
    }
    
    /* MAC */
    uint8_t* mac_input = (uint8_t*)malloc(nonce_len + data_len);
    if (!mac_input) { free(data); free(keystream); return TAV_ERROR_NULL_POINTER; }
    
    memcpy(mac_input, nonce, nonce_len);
    memcpy(mac_input + nonce_len, encrypted, data_len);
    
    uint8_t mac[TAV_MAX_MAC_BYTES];
    mac_calculate(key, key_len, mac_input, nonce_len + data_len, 
                  ctx->mac.n_rounds, mac, mac_len);
    
    /* Monta ciphertext: nonce + mac + encrypted */
    memcpy(ciphertext, nonce, nonce_len);
    memcpy(ciphertext + nonce_len, mac, mac_len);
    
    free(data);
    free(keystream);
    free(mac_input);
    
    if (auto_tick) {
        tav_tick(ctx, 1);
    }
    
    return TAV_OK;
}

tav_result_t tav_decrypt(tav_ctx_t* ctx,
                         const uint8_t* ciphertext,
                         size_t ct_len,
                         uint8_t* plaintext,
                         size_t* pt_len) {
    if (!ctx || !ciphertext || !plaintext || !pt_len) return TAV_ERROR_NULL_POINTER;
    if (!ctx->initialized) return TAV_ERROR_NOT_INITIALIZED;
    
    size_t nonce_len = ctx->config.nonce_bytes;
    size_t mac_len = ctx->config.mac_bytes;
    size_t key_len = ctx->config.key_bytes;
    size_t metadata_len = 8;
    size_t overhead = nonce_len + mac_len + metadata_len;
    
    if (ct_len < overhead) return TAV_ERROR_INVALID_DATA;
    
    const uint8_t* nonce = ciphertext;
    const uint8_t* mac_received = ciphertext + nonce_len;
    const uint8_t* encrypted = ciphertext + nonce_len + mac_len;
    size_t encrypted_len = ct_len - nonce_len - mac_len;
    
    /* Deriva chave */
    uint8_t key[TAV_MAX_KEY_BYTES];
    derive_key(ctx, key);
    
    /* Verifica MAC */
    uint8_t* mac_input = (uint8_t*)malloc(nonce_len + encrypted_len);
    if (!mac_input) return TAV_ERROR_NULL_POINTER;
    
    memcpy(mac_input, nonce, nonce_len);
    memcpy(mac_input + nonce_len, encrypted, encrypted_len);
    
    uint8_t mac_expected[TAV_MAX_MAC_BYTES];
    mac_calculate(key, key_len, mac_input, nonce_len + encrypted_len,
                  ctx->mac.n_rounds, mac_expected, mac_len);
    
    free(mac_input);
    
    if (!tav_constant_time_compare(mac_received, mac_expected, mac_len)) {
        return TAV_ERROR_MAC_MISMATCH;
    }
    
    /* Decifra */
    uint8_t* keystream = (uint8_t*)malloc(encrypted_len);
    if (!keystream) return TAV_ERROR_NULL_POINTER;
    
    generate_keystream(key, key_len, nonce, nonce_len, keystream, encrypted_len);
    
    uint8_t* decrypted = (uint8_t*)malloc(encrypted_len);
    if (!decrypted) { free(keystream); return TAV_ERROR_NULL_POINTER; }
    
    for (size_t i = 0; i < encrypted_len; i++) {
        decrypted[i] = encrypted[i] ^ keystream[i];
    }
    
    /* Remove metadata */
    *pt_len = encrypted_len - metadata_len;
    memcpy(plaintext, decrypted + metadata_len, *pt_len);
    
    free(keystream);
    free(decrypted);
    
    return TAV_OK;
}

/* ============================================================================
 * VERIFICAÇÃO DE HARDWARE
 * ============================================================================ */

bool tav_verify_hardware(tav_ctx_t* ctx, float* similarity) {
    if (!ctx || !ctx->initialized) {
        if (similarity) *similarity = 0.0f;
        return false;
    }
    
    /* Coleta perfil atual */
    uint64_t samples[100];
    for (int i = 0; i < 100; i++) {
        samples[i] = entropy_collect_xor(&ctx->entropy);
    }
    
    /* Calcula viés de bits */
    float bias_bits[8];
    for (int bit = 0; bit < 8; bit++) {
        int count = 0;
        for (int i = 0; i < 100; i++) {
            if ((samples[i] >> bit) & 1) count++;
        }
        bias_bits[bit] = (float)count / 100.0f;
    }
    
    /* Calcula média e desvio */
    float sum = 0, sum_sq = 0;
    for (int i = 0; i < 100; i++) {
        sum += (float)samples[i];
        sum_sq += (float)samples[i] * (float)samples[i];
    }
    float mean = sum / 100.0f;
    float variance = (sum_sq / 100.0f) - (mean * mean);
    float std = (variance > 0) ? sqrtf(variance) : 0;
    
    /* Se é primeira vez, salva como baseline */
    if (ctx->baseline.timing_mean == 0) {
        memcpy(ctx->baseline.bias_bits, bias_bits, sizeof(bias_bits));
        ctx->baseline.timing_mean = mean;
        ctx->baseline.timing_std = std;
        if (similarity) *similarity = 1.0f;
        return true;
    }
    
    /* Compara com baseline */
    float diff_bias = 0;
    for (int i = 0; i < 8; i++) {
        float d = ctx->baseline.bias_bits[i] - bias_bits[i];
        diff_bias += (d < 0 ? -d : d);
    }
    float sim_bias = 1.0f - (diff_bias / 8.0f);
    
    float diff_timing = ctx->baseline.timing_mean - mean;
    diff_timing = diff_timing < 0 ? -diff_timing : diff_timing;
    float sim_timing = (ctx->baseline.timing_mean > 0) ? 
        (1.0f - diff_timing / ctx->baseline.timing_mean) : 0.5f;
    if (sim_timing < 0) sim_timing = 0;
    
    float diff_std = ctx->baseline.timing_std - std;
    diff_std = diff_std < 0 ? -diff_std : diff_std;
    float sim_std = (ctx->baseline.timing_std > 0) ?
        (1.0f - diff_std / ctx->baseline.timing_std) : 0.5f;
    if (sim_std < 0) sim_std = 0;
    
    float total_sim = sim_bias * 0.4f + sim_timing * 0.3f + sim_std * 0.3f;
    
    if (similarity) *similarity = total_sim;
    return total_sim > 0.7f;
}
