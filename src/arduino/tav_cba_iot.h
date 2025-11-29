/*
 * TAV Clock Cryptography v0.9
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
 
 * TAV CAPABILITY-BASED AUTHENTICATION (CBA) - Arduino/ESP32
 * ===============================================================
 
 * Ultra-optimized version for microcontrollers:
 * - Zero dynamic allocation (no malloc)
 * - Fixed sizes at compile time
 * - Minimal RAM usage (~400-600 bytes)
 * - Uses hardware timer for entropy

 * Supported platforms:
 * - Arduino (AVR, ARM)
 * - ESP32/ESP8266
 * - STM32
 * - Raspberry Pi Pico
 
 * Approximate memory usage:
 * - CBA context: ~300 bytes
 * - Capability: ~150 bytes
 * - Proof: ~120 bytes

 * License: AGPL-3.0 | Free commercial use until May 2027
 * Date: November 2025

 */

#ifndef TAV_CBA_IOT_H
#define TAV_CBA_IOT_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURAÇÃO - Ajuste para sua plataforma
 * ============================================================================ */

/* Tamanho da cadeia de identidade (menor = menos RAM, menos assinaturas) */
#ifndef CBA_IOT_CHAIN_LENGTH
#define CBA_IOT_CHAIN_LENGTH    50
#endif

/* Número máximo de recursos por capability */
#ifndef CBA_IOT_MAX_RESOURCES
#define CBA_IOT_MAX_RESOURCES   4
#endif

/* Tamanho máximo do ID de recurso */
#ifndef CBA_IOT_RESOURCE_LEN
#define CBA_IOT_RESOURCE_LEN    24
#endif

/* Tamanho da lista de revogação */
#ifndef CBA_IOT_REVOKE_LIST
#define CBA_IOT_REVOKE_LIST     8
#endif

/* Duração padrão de sessão (segundos) */
#ifndef CBA_IOT_SESSION_DURATION
#define CBA_IOT_SESSION_DURATION 3600
#endif

/* ============================================================================
 * CONSTANTES (NÃO ALTERAR)
 * ============================================================================ */

#define CBA_HASH_SIZE       32
#define CBA_ID_SIZE         16
#define CBA_NONCE_SIZE      8       /* Reduzido para IoT */
#define CBA_SIGNATURE_SIZE  66
#define CBA_SESSION_SIZE    32      /* Reduzido para IoT */
#define CBA_MAC_SIZE        16

/* ============================================================================
 * CONSTANTES CRIPTOGRÁFICAS (em PROGMEM para AVR)
 * ============================================================================ */

#ifdef __AVR__
#include <avr/pgmspace.h>
#define CBA_CONST PROGMEM
#define CBA_READ_BYTE(addr) pgm_read_byte(addr)
#else
#define CBA_CONST
#define CBA_READ_BYTE(addr) (*(addr))
#endif

static const uint8_t CBA_CONST_AND[32] CBA_CONST = {
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF
};

static const uint8_t CBA_CONST_OR[32] CBA_CONST = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
};

/* ============================================================================
 * PERMISSÕES (FLAGS COMPACTAS - 16 bits)
 * ============================================================================ */

#define CBA_PERM_NONE       0x0000
#define CBA_PERM_READ       0x0001
#define CBA_PERM_WRITE      0x0002
#define CBA_PERM_DELETE     0x0004
#define CBA_PERM_ENCRYPT    0x0008
#define CBA_PERM_DECRYPT    0x0010
#define CBA_PERM_SIGN       0x0020
#define CBA_PERM_VERIFY     0x0040
#define CBA_PERM_DELEGATE   0x0080
#define CBA_PERM_REVOKE     0x0100
#define CBA_PERM_ADMIN      0x0200

/* Combinações comuns */
#define CBA_PERM_READ_ONLY      (CBA_PERM_READ | CBA_PERM_VERIFY)
#define CBA_PERM_SENSOR         (CBA_PERM_READ | CBA_PERM_ENCRYPT)
#define CBA_PERM_ACTUATOR       (CBA_PERM_WRITE | CBA_PERM_DECRYPT)
#define CBA_PERM_GATEWAY        (CBA_PERM_READ | CBA_PERM_WRITE | CBA_PERM_DELEGATE)
#define CBA_PERM_FULL           0x03FF

/* ============================================================================
 * CÓDIGOS DE RESULTADO
 * ============================================================================ */

typedef enum {
    CBA_OK = 0,
    CBA_ERR_CHAIN = 1,      /* Cadeia de identidade esgotada */
    CBA_ERR_SESSION = 2,    /* Sessão expirada ou inválida */
    CBA_ERR_EXPIRED = 3,    /* Capability expirada */
    CBA_ERR_REVOKED = 4,    /* Capability revogada */
    CBA_ERR_PERM = 5,       /* Permissão negada */
    CBA_ERR_RESOURCE = 6,   /* Recurso não autorizado */
    CBA_ERR_USES = 7,       /* Máximo de usos atingido */
    CBA_ERR_DELEG = 8,      /* Máximo de delegação atingido */
    CBA_ERR_SIG = 9,        /* Assinatura inválida */
    CBA_ERR_PROOF = 10,     /* Prova inválida */
    CBA_ERR_DATA = 11       /* Dados inválidos */
} cba_result_t;

/* ============================================================================
 * ESTRUTURAS COMPACTAS
 * ============================================================================ */

/* Recurso (compacto) */
typedef struct {
    char id[CBA_IOT_RESOURCE_LEN];
    uint8_t len;
} cba_resource_t;

/* Identidade (Hash-Chain) */
typedef struct {
    uint8_t public_key[CBA_HASH_SIZE];
    uint8_t private_seed[CBA_HASH_SIZE];
    uint16_t chain_length;
    uint16_t current_index;
} cba_identity_t;

/* Sessão (Commitment-Reveal) */
typedef struct {
    uint8_t commitment[CBA_HASH_SIZE];
    uint8_t entropy[CBA_SESSION_SIZE];
    uint32_t created_at;
    uint32_t expires_at;
    uint16_t tx_count;
    uint8_t active;
} cba_session_t;

/* Capability (compacta - ~120 bytes) */
typedef struct {
    uint8_t id[CBA_ID_SIZE];
    uint8_t issuer_id[CBA_ID_SIZE];
    uint8_t holder_id[CBA_ID_SIZE];
    
    uint16_t permissions;
    cba_resource_t resources[CBA_IOT_MAX_RESOURCES];
    uint8_t n_resources;
    
    uint32_t created_at;
    uint32_t expires_at;
    int16_t max_uses;       /* -1 = ilimitado */
    uint16_t uses_count;
    
    uint8_t delegation_depth;
    uint8_t max_delegation_depth;
    uint8_t parent_id[CBA_ID_SIZE];
    uint8_t has_parent;
    
    uint8_t signature[CBA_SIGNATURE_SIZE];
    uint8_t sig_len;
    
    uint8_t revoked;
} cba_cap_t;

/* Prova CBA (compacta - ~100 bytes) */
typedef struct {
    uint8_t cap_id[CBA_ID_SIZE];
    uint8_t session_proof[CBA_HASH_SIZE];
    
    uint8_t operation;      /* Código da operação (não string) */
    uint8_t resource_idx;   /* Índice do recurso na capability */
    
    uint32_t timestamp;
    uint8_t nonce[CBA_NONCE_SIZE];
    uint8_t proof_sig[CBA_MAC_SIZE];
    
    /* Prova de identidade (opcional) */
    uint8_t has_identity;
    uint8_t identity_proof[CBA_SIGNATURE_SIZE];
    uint16_t chain_index;
} cba_proof_t;

/* Lista de revogação (compacta) */
typedef struct {
    uint8_t ids[CBA_IOT_REVOKE_LIST][CBA_ID_SIZE];
    uint8_t count;
} cba_revoke_list_t;

/* Contexto principal (~300 bytes) */
typedef struct {
    cba_identity_t identity;
    cba_session_t session;
    cba_revoke_list_t revoked;
    uint16_t id_counter;
    uint8_t initialized;
} cba_ctx_t;

/* ============================================================================
 * FUNÇÃO DE PLATAFORMA - IMPLEMENTE PARA SUA PLATAFORMA
 * ============================================================================ */

/*
 * Retorna segundos desde boot ou epoch.
 * 
 * Arduino: return millis() / 1000;
 * ESP32: return esp_timer_get_time() / 1000000;
 * Com RTC: return rtc.now().unixtime();
 */
extern uint32_t cba_get_time(void);

/*
 * Retorna microssegundos para entropia.
 * 
 * Arduino: return micros();
 * ESP32: return (uint32_t)esp_timer_get_time();
 */
extern uint32_t cba_get_micros(void);

/* ============================================================================
 * FUNÇÕES INLINE OTIMIZADAS
 * ============================================================================ */

static inline uint8_t cba_rot_left(uint8_t b, uint8_t n) {
    n &= 7;
    return (uint8_t)((b << n) | (b >> (8 - n)));
}

static inline uint8_t cba_get_and(uint8_t idx) {
    return CBA_READ_BYTE(&CBA_CONST_AND[idx & 31]);
}

static inline uint8_t cba_get_or(uint8_t idx) {
    return CBA_READ_BYTE(&CBA_CONST_OR[idx & 31]);
}

/* Comparação em tempo constante */
static inline uint8_t cba_const_cmp(const uint8_t* a, const uint8_t* b, uint8_t len) {
    uint8_t result = 0;
    for (uint8_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/* ============================================================================
 * HASH E MAC (OTIMIZADOS)
 * ============================================================================ */

static void cba_feistel_round(uint8_t* state, uint8_t len, uint8_t round) {
    for (uint8_t i = 0; i < len; i++) {
        uint8_t x = state[i];
        x = cba_rot_left(x, (round + i) & 7);
        x = x & cba_get_and(i + round * 7);
        x = x | cba_get_or(i + round * 11);
        x = x ^ state[(i + round + 1) % len];
        state[i] = x;
    }
}

static void cba_hash(const uint8_t* data, uint16_t len, uint8_t* out, uint8_t out_len) {
    uint8_t state[32];
    
    /* Inicializa com prefixo fixo */
    static const uint8_t prefix[] = "TAVCBA1";
    memset(state, 0, 32);
    for (uint8_t i = 0; i < 7; i++) {
        state[i] = prefix[i];
    }
    
    /* Absorve dados */
    for (uint16_t i = 0; i < len; i++) {
        state[i & 31] ^= data[i];
        if ((i & 31) == 31) {
            for (uint8_t r = 0; r < 4; r++) {
                cba_feistel_round(state, 32, r);
            }
        }
    }
    
    /* Finalização */
    state[0] ^= (len >> 8) & 0xFF;
    state[1] ^= len & 0xFF;
    
    for (uint8_t r = 0; r < 6; r++) {
        cba_feistel_round(state, 32, r);
    }
    
    /* Output */
    uint8_t copy = (out_len < 32) ? out_len : 32;
    memcpy(out, state, copy);
}

static void cba_mac(const uint8_t* key, uint8_t key_len,
                    const uint8_t* data, uint16_t data_len,
                    uint8_t* out, uint8_t out_len) {
    uint8_t buffer[64];
    uint16_t pos = 0;
    
    /* key || data || key (truncado para buffer) */
    uint8_t k_copy = (key_len < 16) ? key_len : 16;
    memcpy(buffer, key, k_copy);
    pos = k_copy;
    
    uint16_t d_copy = (data_len < 32) ? data_len : 32;
    memcpy(buffer + pos, data, d_copy);
    pos += d_copy;
    
    memcpy(buffer + pos, key, k_copy);
    pos += k_copy;
    
    cba_hash(buffer, pos, out, out_len);
}

/* ============================================================================
 * API PRINCIPAL
 * ============================================================================ */

/**
 * Inicializa contexto CBA
 * 
 * @param ctx Contexto a inicializar
 * @param seed Seed secreta (string ou bytes)
 * @param seed_len Tamanho da seed
 * @return CBA_OK em sucesso
 */
cba_result_t cba_init(cba_ctx_t* ctx, const uint8_t* seed, uint8_t seed_len);

/**
 * Limpa dados sensíveis
 */
void cba_cleanup(cba_ctx_t* ctx);

/* ============================================================================
 * IDENTIDADE
 * ============================================================================ */

/**
 * Retorna assinaturas restantes
 */
uint16_t cba_identity_remaining(const cba_ctx_t* ctx);

/**
 * Assina dados com identidade (consome 1 posição da cadeia)
 * 
 * @param ctx Contexto
 * @param data Dados a assinar
 * @param data_len Tamanho dos dados (max 64 bytes recomendado)
 * @param sig_out Buffer para assinatura (66 bytes)
 * @param index_out Índice usado (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_identity_sign(cba_ctx_t* ctx,
                               const uint8_t* data, uint8_t data_len,
                               uint8_t* sig_out, uint16_t* index_out);

/**
 * Verifica assinatura de identidade
 */
cba_result_t cba_identity_verify(const uint8_t* public_key, uint16_t chain_len,
                                 const uint8_t* data, uint8_t data_len,
                                 const uint8_t* signature);

/* ============================================================================
 * SESSÃO
 * ============================================================================ */

/**
 * Cria nova sessão
 * 
 * @param ctx Contexto
 * @param duration Duração em segundos
 * @return CBA_OK em sucesso
 */
cba_result_t cba_session_create(cba_ctx_t* ctx, uint32_t duration);

/**
 * Gera prova de sessão
 * 
 * @param ctx Contexto
 * @param proof_out Buffer para prova (32 bytes)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_session_proof(cba_ctx_t* ctx, uint8_t* proof_out);

/**
 * Verifica se sessão está ativa
 */
uint8_t cba_session_active(const cba_ctx_t* ctx);

/* ============================================================================
 * CAPABILITIES
 * ============================================================================ */

/**
 * Emite nova capability
 * 
 * @param ctx Contexto do emissor
 * @param holder_key Chave pública do detentor (32 bytes)
 * @param permissions Flags de permissão
 * @param resources Array de strings de recursos
 * @param n_resources Número de recursos
 * @param duration Duração em segundos
 * @param max_uses Máximo de usos (-1 = ilimitado)
 * @param max_deleg Níveis de delegação permitidos
 * @param cap_out Capability gerada (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_cap_issue(cba_ctx_t* ctx,
                           const uint8_t* holder_key,
                           uint16_t permissions,
                           const char** resources, uint8_t n_resources,
                           uint32_t duration,
                           int16_t max_uses, uint8_t max_deleg,
                           cba_cap_t* cap_out);

/**
 * Delega capability existente
 */
cba_result_t cba_cap_delegate(cba_ctx_t* ctx,
                              const cba_cap_t* parent,
                              const uint8_t* new_holder_key,
                              uint16_t permissions,
                              const char** resources, uint8_t n_resources,
                              uint32_t duration,
                              cba_cap_t* cap_out);

/**
 * Revoga capability
 */
cba_result_t cba_cap_revoke(cba_ctx_t* ctx, const uint8_t* cap_id);

/**
 * Verifica se capability está revogada
 */
uint8_t cba_cap_is_revoked(const cba_ctx_t* ctx, const uint8_t* cap_id);

/**
 * Verifica se capability tem recurso
 */
uint8_t cba_cap_has_resource(const cba_cap_t* cap, const char* resource_id);

/**
 * Verifica se capability tem permissão
 */
uint8_t cba_cap_has_perm(const cba_cap_t* cap, uint16_t perm);

/* ============================================================================
 * PROVAS
 * ============================================================================ */

/**
 * Converte string de operação para código
 */
uint8_t cba_op_to_code(const char* operation);

/**
 * Gera prova de acesso
 * 
 * @param ctx Contexto
 * @param cap Capability sendo usada
 * @param op_code Código da operação (use cba_op_to_code)
 * @param resource_idx Índice do recurso na capability
 * @param include_identity Se deve incluir prova de identidade
 * @param proof_out Prova gerada (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_proof_generate(cba_ctx_t* ctx,
                                cba_cap_t* cap,
                                uint8_t op_code,
                                uint8_t resource_idx,
                                uint8_t include_identity,
                                cba_proof_t* proof_out);

/**
 * Verifica prova de acesso
 */
cba_result_t cba_proof_verify(const cba_ctx_t* ctx,
                              const cba_proof_t* proof,
                              const cba_cap_t* cap,
                              const uint8_t* issuer_key,
                              uint16_t issuer_chain_len,
                              uint32_t max_age);

/* ============================================================================
 * SERIALIZAÇÃO COMPACTA
 * ============================================================================ */

/**
 * Serializa capability para transmissão
 * 
 * @param cap Capability
 * @param buffer Buffer de saída
 * @param buf_size Tamanho do buffer
 * @return Tamanho serializado ou 0 em erro
 */
uint16_t cba_cap_serialize(const cba_cap_t* cap, uint8_t* buffer, uint16_t buf_size);

/**
 * Deserializa capability
 * 
 * @param buffer Buffer de entrada
 * @param len Tamanho dos dados
 * @param cap_out Capability deserializada (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_cap_deserialize(const uint8_t* buffer, uint16_t len, cba_cap_t* cap_out);

/**
 * Serializa prova
 */
uint16_t cba_proof_serialize(const cba_proof_t* proof, uint8_t* buffer, uint16_t buf_size);

/**
 * Deserializa prova
 */
cba_result_t cba_proof_deserialize(const uint8_t* buffer, uint16_t len, cba_proof_t* proof_out);

/* ============================================================================
 * IMPLEMENTAÇÃO
 * ============================================================================ */

/* Implementação inline para reduzir overhead de chamada */

static void _cba_gen_chain_element(const uint8_t* seed, uint16_t steps, uint8_t* out) {
    uint8_t current[CBA_HASH_SIZE];
    memcpy(current, seed, CBA_HASH_SIZE);
    
    for (uint16_t i = 0; i < steps; i++) {
        uint8_t input[CBA_HASH_SIZE + 4];
        memcpy(input, current, CBA_HASH_SIZE);
        input[CBA_HASH_SIZE] = (i >> 24) & 0xFF;
        input[CBA_HASH_SIZE + 1] = (i >> 16) & 0xFF;
        input[CBA_HASH_SIZE + 2] = (i >> 8) & 0xFF;
        input[CBA_HASH_SIZE + 3] = i & 0xFF;
        cba_hash(input, CBA_HASH_SIZE + 4, current, CBA_HASH_SIZE);
    }
    
    memcpy(out, current, CBA_HASH_SIZE);
}

static void _cba_gen_cap_id(cba_ctx_t* ctx, const uint8_t* holder, uint8_t* out) {
    uint32_t now = cba_get_time();
    uint8_t input[CBA_HASH_SIZE + CBA_HASH_SIZE + 8];
    
    memcpy(input, ctx->identity.public_key, CBA_HASH_SIZE);
    memcpy(input + CBA_HASH_SIZE, holder, CBA_HASH_SIZE);
    input[CBA_HASH_SIZE * 2] = (now >> 24) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 1] = (now >> 16) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 2] = (now >> 8) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 3] = now & 0xFF;
    input[CBA_HASH_SIZE * 2 + 4] = (ctx->id_counter >> 8) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 5] = ctx->id_counter & 0xFF;
    input[CBA_HASH_SIZE * 2 + 6] = 0;
    input[CBA_HASH_SIZE * 2 + 7] = 0;
    
    ctx->id_counter++;
    
    cba_hash(input, sizeof(input), out, CBA_ID_SIZE);
}

cba_result_t cba_init(cba_ctx_t* ctx, const uint8_t* seed, uint8_t seed_len) {
    memset(ctx, 0, sizeof(cba_ctx_t));
    
    /* Deriva seed privada */
    uint8_t seed_input[64];
    memcpy(seed_input, seed, (seed_len < 48) ? seed_len : 48);
    memcpy(seed_input + seed_len, "_ID", 3);
    cba_hash(seed_input, seed_len + 3, ctx->identity.private_seed, CBA_HASH_SIZE);
    
    /* Gera chave pública */
    ctx->identity.chain_length = CBA_IOT_CHAIN_LENGTH;
    _cba_gen_chain_element(ctx->identity.private_seed, CBA_IOT_CHAIN_LENGTH, 
                           ctx->identity.public_key);
    
    ctx->identity.current_index = 0;
    ctx->session.active = 0;
    ctx->revoked.count = 0;
    ctx->id_counter = 0;
    ctx->initialized = 1;
    
    return CBA_OK;
}

void cba_cleanup(cba_ctx_t* ctx) {
    if (ctx) {
        memset(ctx->identity.private_seed, 0, CBA_HASH_SIZE);
        memset(ctx->session.entropy, 0, CBA_SESSION_SIZE);
        ctx->initialized = 0;
    }
}

uint16_t cba_identity_remaining(const cba_ctx_t* ctx) {
    if (!ctx || !ctx->initialized) return 0;
    return ctx->identity.chain_length - ctx->identity.current_index;
}

cba_result_t cba_identity_sign(cba_ctx_t* ctx,
                               const uint8_t* data, uint8_t data_len,
                               uint8_t* sig_out, uint16_t* index_out) {
    if (!ctx || !ctx->initialized) return CBA_ERR_DATA;
    if (ctx->identity.current_index >= ctx->identity.chain_length) {
        return CBA_ERR_CHAIN;
    }
    
    uint16_t index = ctx->identity.current_index;
    uint16_t steps = ctx->identity.chain_length - index - 1;
    
    /* Reveal */
    uint8_t reveal[CBA_HASH_SIZE];
    _cba_gen_chain_element(ctx->identity.private_seed, steps, reveal);
    
    /* MAC */
    uint8_t mac_input[96];
    uint8_t copy = (data_len < 64) ? data_len : 64;
    memcpy(mac_input, data, copy);
    memcpy(mac_input + copy, reveal, CBA_HASH_SIZE);
    
    uint8_t mac[CBA_HASH_SIZE];
    cba_hash(mac_input, copy + CBA_HASH_SIZE, mac, CBA_HASH_SIZE);
    
    /* Assinatura: índice (2) + reveal (32) + mac (32) */
    sig_out[0] = (index >> 8) & 0xFF;
    sig_out[1] = index & 0xFF;
    memcpy(sig_out + 2, reveal, CBA_HASH_SIZE);
    memcpy(sig_out + 2 + CBA_HASH_SIZE, mac, CBA_HASH_SIZE);
    
    if (index_out) *index_out = index;
    ctx->identity.current_index++;
    
    return CBA_OK;
}

cba_result_t cba_identity_verify(const uint8_t* public_key, uint16_t chain_len,
                                 const uint8_t* data, uint8_t data_len,
                                 const uint8_t* signature) {
    uint16_t index = ((uint16_t)signature[0] << 8) | signature[1];
    const uint8_t* reveal = signature + 2;
    const uint8_t* mac = signature + 2 + CBA_HASH_SIZE;
    
    /* Verifica MAC */
    uint8_t mac_input[96];
    uint8_t copy = (data_len < 64) ? data_len : 64;
    memcpy(mac_input, data, copy);
    memcpy(mac_input + copy, reveal, CBA_HASH_SIZE);
    
    uint8_t expected[CBA_HASH_SIZE];
    cba_hash(mac_input, copy + CBA_HASH_SIZE, expected, CBA_HASH_SIZE);
    
    if (!cba_const_cmp(mac, expected, CBA_HASH_SIZE)) {
        return CBA_ERR_SIG;
    }
    
    /* Verifica cadeia */
    uint8_t current[CBA_HASH_SIZE];
    memcpy(current, reveal, CBA_HASH_SIZE);
    
    for (uint16_t i = chain_len - index - 1; i < chain_len; i++) {
        uint8_t input[CBA_HASH_SIZE + 4];
        memcpy(input, current, CBA_HASH_SIZE);
        input[CBA_HASH_SIZE] = (i >> 24) & 0xFF;
        input[CBA_HASH_SIZE + 1] = (i >> 16) & 0xFF;
        input[CBA_HASH_SIZE + 2] = (i >> 8) & 0xFF;
        input[CBA_HASH_SIZE + 3] = i & 0xFF;
        cba_hash(input, CBA_HASH_SIZE + 4, current, CBA_HASH_SIZE);
    }
    
    if (!cba_const_cmp(current, public_key, CBA_HASH_SIZE)) {
        return CBA_ERR_SIG;
    }
    
    return CBA_OK;
}

cba_result_t cba_session_create(cba_ctx_t* ctx, uint32_t duration) {
    if (!ctx || !ctx->initialized) return CBA_ERR_DATA;
    
    uint32_t now = cba_get_time();
    
    /* Entropia: seed + time + micros */
    uint8_t entropy_in[48];
    memcpy(entropy_in, ctx->identity.private_seed, CBA_HASH_SIZE);
    
    uint32_t t = cba_get_micros();
    entropy_in[32] = (now >> 24) & 0xFF;
    entropy_in[33] = (now >> 16) & 0xFF;
    entropy_in[34] = (now >> 8) & 0xFF;
    entropy_in[35] = now & 0xFF;
    entropy_in[36] = (t >> 24) & 0xFF;
    entropy_in[37] = (t >> 16) & 0xFF;
    entropy_in[38] = (t >> 8) & 0xFF;
    entropy_in[39] = t & 0xFF;
    entropy_in[40] = (ctx->id_counter >> 8) & 0xFF;
    entropy_in[41] = ctx->id_counter & 0xFF;
    
    cba_hash(entropy_in, 42, ctx->session.entropy, CBA_SESSION_SIZE);
    cba_hash(ctx->session.entropy, CBA_SESSION_SIZE, ctx->session.commitment, CBA_HASH_SIZE);
    
    ctx->session.created_at = now;
    ctx->session.expires_at = now + duration;
    ctx->session.tx_count = 0;
    ctx->session.active = 1;
    
    return CBA_OK;
}

cba_result_t cba_session_proof(cba_ctx_t* ctx, uint8_t* proof_out) {
    if (!ctx || !ctx->session.active) return CBA_ERR_SESSION;
    
    uint32_t now = cba_get_time();
    if (now > ctx->session.expires_at) {
        ctx->session.active = 0;
        return CBA_ERR_SESSION;
    }
    
    uint8_t input[CBA_SESSION_SIZE + 4];
    memcpy(input, ctx->session.entropy, CBA_SESSION_SIZE);
    input[CBA_SESSION_SIZE] = (ctx->session.tx_count >> 8) & 0xFF;
    input[CBA_SESSION_SIZE + 1] = ctx->session.tx_count & 0xFF;
    input[CBA_SESSION_SIZE + 2] = 0;
    input[CBA_SESSION_SIZE + 3] = 0;
    
    cba_hash(input, CBA_SESSION_SIZE + 4, proof_out, CBA_HASH_SIZE);
    
    ctx->session.tx_count++;
    
    return CBA_OK;
}

uint8_t cba_session_active(const cba_ctx_t* ctx) {
    if (!ctx || !ctx->session.active) return 0;
    return cba_get_time() <= ctx->session.expires_at;
}

cba_result_t cba_cap_issue(cba_ctx_t* ctx,
                           const uint8_t* holder_key,
                           uint16_t permissions,
                           const char** resources, uint8_t n_resources,
                           uint32_t duration,
                           int16_t max_uses, uint8_t max_deleg,
                           cba_cap_t* cap_out) {
    if (!ctx || !ctx->initialized || !holder_key || !cap_out) {
        return CBA_ERR_DATA;
    }
    
    if (n_resources > CBA_IOT_MAX_RESOURCES) {
        n_resources = CBA_IOT_MAX_RESOURCES;
    }
    
    uint32_t now = cba_get_time();
    
    memset(cap_out, 0, sizeof(cba_cap_t));
    
    /* Gera ID */
    _cba_gen_cap_id(ctx, holder_key, cap_out->id);
    
    /* IDs */
    cba_hash(ctx->identity.public_key, CBA_HASH_SIZE, cap_out->issuer_id, CBA_ID_SIZE);
    cba_hash(holder_key, CBA_HASH_SIZE, cap_out->holder_id, CBA_ID_SIZE);
    
    /* Dados */
    cap_out->permissions = permissions;
    cap_out->created_at = now;
    cap_out->expires_at = now + duration;
    cap_out->max_uses = max_uses;
    cap_out->uses_count = 0;
    cap_out->delegation_depth = 0;
    cap_out->max_delegation_depth = max_deleg;
    cap_out->has_parent = 0;
    cap_out->revoked = 0;
    
    /* Recursos */
    cap_out->n_resources = n_resources;
    for (uint8_t i = 0; i < n_resources && resources && resources[i]; i++) {
        uint8_t len = strlen(resources[i]);
        if (len >= CBA_IOT_RESOURCE_LEN) len = CBA_IOT_RESOURCE_LEN - 1;
        memcpy(cap_out->resources[i].id, resources[i], len);
        cap_out->resources[i].id[len] = '\0';
        cap_out->resources[i].len = len;
    }
    
    /* Dados para assinatura */
    uint8_t sign_data[128];
    uint16_t pos = 0;
    memcpy(sign_data + pos, cap_out->id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(sign_data + pos, cap_out->issuer_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(sign_data + pos, cap_out->holder_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    sign_data[pos++] = (permissions >> 8) & 0xFF;
    sign_data[pos++] = permissions & 0xFF;
    sign_data[pos++] = (now >> 24) & 0xFF;
    sign_data[pos++] = (now >> 16) & 0xFF;
    sign_data[pos++] = (now >> 8) & 0xFF;
    sign_data[pos++] = now & 0xFF;
    
    /* Assina */
    uint16_t idx;
    return cba_identity_sign(ctx, sign_data, pos, cap_out->signature, &idx);
}

cba_result_t cba_cap_delegate(cba_ctx_t* ctx,
                              const cba_cap_t* parent,
                              const uint8_t* new_holder_key,
                              uint16_t permissions,
                              const char** resources, uint8_t n_resources,
                              uint32_t duration,
                              cba_cap_t* cap_out) {
    if (!ctx || !parent || !new_holder_key || !cap_out) {
        return CBA_ERR_DATA;
    }
    
    if (parent->revoked) return CBA_ERR_REVOKED;
    if (parent->delegation_depth >= parent->max_delegation_depth) {
        return CBA_ERR_DELEG;
    }
    if (!(parent->permissions & CBA_PERM_DELEGATE)) {
        return CBA_ERR_PERM;
    }
    
    uint32_t now = cba_get_time();
    
    /* Restringe permissões e duração */
    uint16_t allowed_perms = permissions & parent->permissions;
    uint32_t max_exp = parent->expires_at;
    uint32_t actual_exp = now + duration;
    if (actual_exp > max_exp) actual_exp = max_exp;
    
    memset(cap_out, 0, sizeof(cba_cap_t));
    
    _cba_gen_cap_id(ctx, new_holder_key, cap_out->id);
    cba_hash(ctx->identity.public_key, CBA_HASH_SIZE, cap_out->issuer_id, CBA_ID_SIZE);
    cba_hash(new_holder_key, CBA_HASH_SIZE, cap_out->holder_id, CBA_ID_SIZE);
    
    cap_out->permissions = allowed_perms;
    cap_out->created_at = now;
    cap_out->expires_at = actual_exp;
    cap_out->max_uses = parent->max_uses;
    cap_out->uses_count = 0;
    cap_out->delegation_depth = parent->delegation_depth + 1;
    cap_out->max_delegation_depth = parent->max_delegation_depth;
    cap_out->has_parent = 1;
    memcpy(cap_out->parent_id, parent->id, CBA_ID_SIZE);
    cap_out->revoked = 0;
    
    /* Filtra recursos */
    uint8_t valid = 0;
    for (uint8_t i = 0; i < n_resources && resources && resources[i]; i++) {
        if (cba_cap_has_resource(parent, resources[i])) {
            uint8_t len = strlen(resources[i]);
            if (len >= CBA_IOT_RESOURCE_LEN) len = CBA_IOT_RESOURCE_LEN - 1;
            memcpy(cap_out->resources[valid].id, resources[i], len);
            cap_out->resources[valid].id[len] = '\0';
            cap_out->resources[valid].len = len;
            valid++;
            if (valid >= CBA_IOT_MAX_RESOURCES) break;
        }
    }
    cap_out->n_resources = valid;
    
    /* Assina */
    uint8_t sign_data[128];
    uint16_t pos = 0;
    memcpy(sign_data + pos, cap_out->id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(sign_data + pos, cap_out->issuer_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(sign_data + pos, cap_out->holder_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    sign_data[pos++] = (allowed_perms >> 8) & 0xFF;
    sign_data[pos++] = allowed_perms & 0xFF;
    sign_data[pos++] = (now >> 24) & 0xFF;
    sign_data[pos++] = (now >> 16) & 0xFF;
    sign_data[pos++] = (now >> 8) & 0xFF;
    sign_data[pos++] = now & 0xFF;
    
    uint16_t idx;
    return cba_identity_sign(ctx, sign_data, pos, cap_out->signature, &idx);
}

cba_result_t cba_cap_revoke(cba_ctx_t* ctx, const uint8_t* cap_id) {
    if (!ctx || !cap_id) return CBA_ERR_DATA;
    
    if (ctx->revoked.count < CBA_IOT_REVOKE_LIST) {
        memcpy(ctx->revoked.ids[ctx->revoked.count], cap_id, CBA_ID_SIZE);
        ctx->revoked.count++;
    }
    
    return CBA_OK;
}

uint8_t cba_cap_is_revoked(const cba_ctx_t* ctx, const uint8_t* cap_id) {
    if (!ctx || !cap_id) return 1;
    
    for (uint8_t i = 0; i < ctx->revoked.count; i++) {
        if (cba_const_cmp(ctx->revoked.ids[i], cap_id, CBA_ID_SIZE)) {
            return 1;
        }
    }
    return 0;
}

uint8_t cba_cap_has_resource(const cba_cap_t* cap, const char* resource_id) {
    if (!cap || !resource_id) return 0;
    
    for (uint8_t i = 0; i < cap->n_resources; i++) {
        if (strcmp(cap->resources[i].id, resource_id) == 0) {
            return 1;
        }
        if (cap->resources[i].id[0] == '*') {
            return 1;
        }
    }
    return 0;
}

uint8_t cba_cap_has_perm(const cba_cap_t* cap, uint16_t perm) {
    if (!cap) return 0;
    return (cap->permissions & perm) == perm;
}

uint8_t cba_op_to_code(const char* operation) {
    if (!operation) return 0;
    
    if (strcmp(operation, "READ") == 0) return 1;
    if (strcmp(operation, "WRITE") == 0) return 2;
    if (strcmp(operation, "DELETE") == 0) return 3;
    if (strcmp(operation, "ENCRYPT") == 0) return 4;
    if (strcmp(operation, "DECRYPT") == 0) return 5;
    if (strcmp(operation, "SIGN") == 0) return 6;
    if (strcmp(operation, "VERIFY") == 0) return 7;
    if (strcmp(operation, "DELEGATE") == 0) return 8;
    if (strcmp(operation, "REVOKE") == 0) return 9;
    if (strcmp(operation, "ADMIN") == 0) return 10;
    
    return 0;
}

static uint16_t _op_code_to_perm(uint8_t code) {
    switch (code) {
        case 1: return CBA_PERM_READ;
        case 2: return CBA_PERM_WRITE;
        case 3: return CBA_PERM_DELETE;
        case 4: return CBA_PERM_ENCRYPT;
        case 5: return CBA_PERM_DECRYPT;
        case 6: return CBA_PERM_SIGN;
        case 7: return CBA_PERM_VERIFY;
        case 8: return CBA_PERM_DELEGATE;
        case 9: return CBA_PERM_REVOKE;
        case 10: return CBA_PERM_ADMIN;
        default: return 0;
    }
}

cba_result_t cba_proof_generate(cba_ctx_t* ctx,
                                cba_cap_t* cap,
                                uint8_t op_code,
                                uint8_t resource_idx,
                                uint8_t include_identity,
                                cba_proof_t* proof_out) {
    if (!ctx || !cap || !proof_out) return CBA_ERR_DATA;
    
    /* Validações */
    if (cap->revoked || cba_cap_is_revoked(ctx, cap->id)) {
        return CBA_ERR_REVOKED;
    }
    
    uint32_t now = cba_get_time();
    if (now > cap->expires_at) {
        return CBA_ERR_EXPIRED;
    }
    
    if (cap->max_uses >= 0 && cap->uses_count >= (uint16_t)cap->max_uses) {
        return CBA_ERR_USES;
    }
    
    if (resource_idx >= cap->n_resources) {
        return CBA_ERR_RESOURCE;
    }
    
    uint16_t perm = _op_code_to_perm(op_code);
    if (!cba_cap_has_perm(cap, perm)) {
        return CBA_ERR_PERM;
    }
    
    memset(proof_out, 0, sizeof(cba_proof_t));
    
    memcpy(proof_out->cap_id, cap->id, CBA_ID_SIZE);
    
    /* Prova de sessão */
    cba_result_t res = cba_session_proof(ctx, proof_out->session_proof);
    if (res != CBA_OK) return res;
    
    proof_out->operation = op_code;
    proof_out->resource_idx = resource_idx;
    proof_out->timestamp = now;
    
    /* Nonce via timing */
    uint32_t t = cba_get_micros();
    proof_out->nonce[0] = (t >> 24) & 0xFF;
    proof_out->nonce[1] = (t >> 16) & 0xFF;
    proof_out->nonce[2] = (t >> 8) & 0xFF;
    proof_out->nonce[3] = t & 0xFF;
    proof_out->nonce[4] = (now >> 24) & 0xFF;
    proof_out->nonce[5] = (now >> 16) & 0xFF;
    proof_out->nonce[6] = (now >> 8) & 0xFF;
    proof_out->nonce[7] = now & 0xFF;
    
    /* Prova de identidade (opcional) */
    if (include_identity) {
        uint8_t id_data[CBA_ID_SIZE + CBA_HASH_SIZE + CBA_NONCE_SIZE];
        memcpy(id_data, cap->id, CBA_ID_SIZE);
        memcpy(id_data + CBA_ID_SIZE, proof_out->session_proof, CBA_HASH_SIZE);
        memcpy(id_data + CBA_ID_SIZE + CBA_HASH_SIZE, proof_out->nonce, CBA_NONCE_SIZE);
        
        res = cba_identity_sign(ctx, id_data, sizeof(id_data),
                                proof_out->identity_proof, &proof_out->chain_index);
        if (res != CBA_OK) return res;
        
        proof_out->has_identity = 1;
    }
    
    /* Assinatura da prova */
    uint8_t proof_data[80];
    uint16_t pos = 0;
    memcpy(proof_data + pos, proof_out->cap_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(proof_data + pos, proof_out->session_proof, CBA_HASH_SIZE); pos += CBA_HASH_SIZE;
    proof_data[pos++] = proof_out->operation;
    proof_data[pos++] = proof_out->resource_idx;
    proof_data[pos++] = (now >> 24) & 0xFF;
    proof_data[pos++] = (now >> 16) & 0xFF;
    proof_data[pos++] = (now >> 8) & 0xFF;
    proof_data[pos++] = now & 0xFF;
    memcpy(proof_data + pos, proof_out->nonce, CBA_NONCE_SIZE); pos += CBA_NONCE_SIZE;
    
    cba_mac(ctx->session.entropy, CBA_SESSION_SIZE, proof_data, pos, 
            proof_out->proof_sig, CBA_MAC_SIZE);
    
    cap->uses_count++;
    
    return CBA_OK;
}

cba_result_t cba_proof_verify(const cba_ctx_t* ctx,
                              const cba_proof_t* proof,
                              const cba_cap_t* cap,
                              const uint8_t* issuer_key,
                              uint16_t issuer_chain_len,
                              uint32_t max_age) {
    if (!proof || !cap || !issuer_key) return CBA_ERR_DATA;
    
    uint32_t now = cba_get_time();
    
    /* Timestamp */
    if (now - proof->timestamp > max_age) {
        return CBA_ERR_PROOF;
    }
    
    /* Capability ID */
    if (!cba_const_cmp(proof->cap_id, cap->id, CBA_ID_SIZE)) {
        return CBA_ERR_DATA;
    }
    
    /* Revogação */
    if (cap->revoked) return CBA_ERR_REVOKED;
    if (ctx && cba_cap_is_revoked(ctx, cap->id)) {
        return CBA_ERR_REVOKED;
    }
    
    /* Expiração */
    if (now > cap->expires_at) return CBA_ERR_EXPIRED;
    
    /* Permissão */
    uint16_t perm = _op_code_to_perm(proof->operation);
    if (!cba_cap_has_perm(cap, perm)) {
        return CBA_ERR_PERM;
    }
    
    /* Recurso */
    if (proof->resource_idx >= cap->n_resources) {
        return CBA_ERR_RESOURCE;
    }
    
    /* Prova de identidade */
    if (proof->has_identity) {
        uint8_t id_data[CBA_ID_SIZE + CBA_HASH_SIZE + CBA_NONCE_SIZE];
        memcpy(id_data, cap->id, CBA_ID_SIZE);
        memcpy(id_data + CBA_ID_SIZE, proof->session_proof, CBA_HASH_SIZE);
        memcpy(id_data + CBA_ID_SIZE + CBA_HASH_SIZE, proof->nonce, CBA_NONCE_SIZE);
        
        cba_result_t res = cba_identity_verify(issuer_key, issuer_chain_len,
                                               id_data, sizeof(id_data),
                                               proof->identity_proof);
        if (res != CBA_OK) return res;
    }
    
    return CBA_OK;
}

/* Serialização compacta */
uint16_t cba_cap_serialize(const cba_cap_t* cap, uint8_t* buffer, uint16_t buf_size) {
    if (!cap || !buffer || buf_size < 100) return 0;
    
    uint16_t pos = 0;
    
    /* Magic */
    buffer[pos++] = 'C';
    buffer[pos++] = 'A';
    buffer[pos++] = 'P';
    buffer[pos++] = 1;
    
    /* IDs */
    memcpy(buffer + pos, cap->id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(buffer + pos, cap->issuer_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(buffer + pos, cap->holder_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    
    /* Permissões */
    buffer[pos++] = (cap->permissions >> 8) & 0xFF;
    buffer[pos++] = cap->permissions & 0xFF;
    
    /* Timestamps */
    buffer[pos++] = (cap->created_at >> 24) & 0xFF;
    buffer[pos++] = (cap->created_at >> 16) & 0xFF;
    buffer[pos++] = (cap->created_at >> 8) & 0xFF;
    buffer[pos++] = cap->created_at & 0xFF;
    buffer[pos++] = (cap->expires_at >> 24) & 0xFF;
    buffer[pos++] = (cap->expires_at >> 16) & 0xFF;
    buffer[pos++] = (cap->expires_at >> 8) & 0xFF;
    buffer[pos++] = cap->expires_at & 0xFF;
    
    /* Limites */
    buffer[pos++] = (cap->max_uses >> 8) & 0xFF;
    buffer[pos++] = cap->max_uses & 0xFF;
    buffer[pos++] = (cap->uses_count >> 8) & 0xFF;
    buffer[pos++] = cap->uses_count & 0xFF;
    
    /* Delegação */
    buffer[pos++] = cap->delegation_depth;
    buffer[pos++] = cap->max_delegation_depth;
    buffer[pos++] = cap->has_parent;
    if (cap->has_parent) {
        memcpy(buffer + pos, cap->parent_id, CBA_ID_SIZE);
        pos += CBA_ID_SIZE;
    }
    
    /* Recursos */
    buffer[pos++] = cap->n_resources;
    for (uint8_t i = 0; i < cap->n_resources; i++) {
        buffer[pos++] = cap->resources[i].len;
        memcpy(buffer + pos, cap->resources[i].id, cap->resources[i].len);
        pos += cap->resources[i].len;
    }
    
    /* Assinatura */
    buffer[pos++] = CBA_SIGNATURE_SIZE;
    memcpy(buffer + pos, cap->signature, CBA_SIGNATURE_SIZE);
    pos += CBA_SIGNATURE_SIZE;
    
    return pos;
}

cba_result_t cba_cap_deserialize(const uint8_t* buffer, uint16_t len, cba_cap_t* cap_out) {
    if (!buffer || !cap_out || len < 50) return CBA_ERR_DATA;
    
    uint16_t pos = 0;
    
    /* Magic */
    if (buffer[0] != 'C' || buffer[1] != 'A' || buffer[2] != 'P') {
        return CBA_ERR_DATA;
    }
    pos = 4;
    
    memset(cap_out, 0, sizeof(cba_cap_t));
    
    /* IDs */
    memcpy(cap_out->id, buffer + pos, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(cap_out->issuer_id, buffer + pos, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(cap_out->holder_id, buffer + pos, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    
    /* Permissões */
    cap_out->permissions = ((uint16_t)buffer[pos] << 8) | buffer[pos + 1];
    pos += 2;
    
    /* Timestamps */
    cap_out->created_at = ((uint32_t)buffer[pos] << 24) | ((uint32_t)buffer[pos+1] << 16) |
                          ((uint32_t)buffer[pos+2] << 8) | buffer[pos+3];
    pos += 4;
    cap_out->expires_at = ((uint32_t)buffer[pos] << 24) | ((uint32_t)buffer[pos+1] << 16) |
                          ((uint32_t)buffer[pos+2] << 8) | buffer[pos+3];
    pos += 4;
    
    /* Limites */
    cap_out->max_uses = (int16_t)(((uint16_t)buffer[pos] << 8) | buffer[pos + 1]);
    pos += 2;
    cap_out->uses_count = ((uint16_t)buffer[pos] << 8) | buffer[pos + 1];
    pos += 2;
    
    /* Delegação */
    cap_out->delegation_depth = buffer[pos++];
    cap_out->max_delegation_depth = buffer[pos++];
    cap_out->has_parent = buffer[pos++];
    if (cap_out->has_parent) {
        memcpy(cap_out->parent_id, buffer + pos, CBA_ID_SIZE);
        pos += CBA_ID_SIZE;
    }
    
    /* Recursos */
    cap_out->n_resources = buffer[pos++];
    if (cap_out->n_resources > CBA_IOT_MAX_RESOURCES) {
        cap_out->n_resources = CBA_IOT_MAX_RESOURCES;
    }
    for (uint8_t i = 0; i < cap_out->n_resources; i++) {
        cap_out->resources[i].len = buffer[pos++];
        if (cap_out->resources[i].len >= CBA_IOT_RESOURCE_LEN) {
            cap_out->resources[i].len = CBA_IOT_RESOURCE_LEN - 1;
        }
        memcpy(cap_out->resources[i].id, buffer + pos, cap_out->resources[i].len);
        cap_out->resources[i].id[cap_out->resources[i].len] = '\0';
        pos += cap_out->resources[i].len;
    }
    
    /* Assinatura */
    uint8_t sig_len = buffer[pos++];
    if (sig_len > CBA_SIGNATURE_SIZE) sig_len = CBA_SIGNATURE_SIZE;
    memcpy(cap_out->signature, buffer + pos, sig_len);
    cap_out->sig_len = sig_len;
    
    return CBA_OK;
}

uint16_t cba_proof_serialize(const cba_proof_t* proof, uint8_t* buffer, uint16_t buf_size) {
    if (!proof || !buffer || buf_size < 80) return 0;
    
    uint16_t pos = 0;
    
    buffer[pos++] = 'P';
    buffer[pos++] = 'R';
    buffer[pos++] = 'F';
    buffer[pos++] = 1;
    
    memcpy(buffer + pos, proof->cap_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(buffer + pos, proof->session_proof, CBA_HASH_SIZE); pos += CBA_HASH_SIZE;
    
    buffer[pos++] = proof->operation;
    buffer[pos++] = proof->resource_idx;
    
    buffer[pos++] = (proof->timestamp >> 24) & 0xFF;
    buffer[pos++] = (proof->timestamp >> 16) & 0xFF;
    buffer[pos++] = (proof->timestamp >> 8) & 0xFF;
    buffer[pos++] = proof->timestamp & 0xFF;
    
    memcpy(buffer + pos, proof->nonce, CBA_NONCE_SIZE); pos += CBA_NONCE_SIZE;
    memcpy(buffer + pos, proof->proof_sig, CBA_MAC_SIZE); pos += CBA_MAC_SIZE;
    
    buffer[pos++] = proof->has_identity;
    if (proof->has_identity) {
        memcpy(buffer + pos, proof->identity_proof, CBA_SIGNATURE_SIZE);
        pos += CBA_SIGNATURE_SIZE;
        buffer[pos++] = (proof->chain_index >> 8) & 0xFF;
        buffer[pos++] = proof->chain_index & 0xFF;
    }
    
    return pos;
}

cba_result_t cba_proof_deserialize(const uint8_t* buffer, uint16_t len, cba_proof_t* proof_out) {
    if (!buffer || !proof_out || len < 70) return CBA_ERR_DATA;
    
    if (buffer[0] != 'P' || buffer[1] != 'R' || buffer[2] != 'F') {
        return CBA_ERR_DATA;
    }
    
    uint16_t pos = 4;
    
    memset(proof_out, 0, sizeof(cba_proof_t));
    
    memcpy(proof_out->cap_id, buffer + pos, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(proof_out->session_proof, buffer + pos, CBA_HASH_SIZE); pos += CBA_HASH_SIZE;
    
    proof_out->operation = buffer[pos++];
    proof_out->resource_idx = buffer[pos++];
    
    proof_out->timestamp = ((uint32_t)buffer[pos] << 24) | ((uint32_t)buffer[pos+1] << 16) |
                           ((uint32_t)buffer[pos+2] << 8) | buffer[pos+3];
    pos += 4;
    
    memcpy(proof_out->nonce, buffer + pos, CBA_NONCE_SIZE); pos += CBA_NONCE_SIZE;
    memcpy(proof_out->proof_sig, buffer + pos, CBA_MAC_SIZE); pos += CBA_MAC_SIZE;
    
    proof_out->has_identity = buffer[pos++];
    if (proof_out->has_identity && pos + CBA_SIGNATURE_SIZE + 2 <= len) {
        memcpy(proof_out->identity_proof, buffer + pos, CBA_SIGNATURE_SIZE);
        pos += CBA_SIGNATURE_SIZE;
        proof_out->chain_index = ((uint16_t)buffer[pos] << 8) | buffer[pos + 1];
    }
    
    return CBA_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* TAV_CBA_IOT_H */
