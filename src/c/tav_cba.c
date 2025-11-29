/*
 * TAV CAPABILITY-BASED AUTHENTICATION (CBA) V1.0 - C Implementation
 * ==================================================================
 */

#include "tav_cba.h"
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * CONSTANTES CRIPTOGRÁFICAS
 * ============================================================================ */

const uint8_t CBA_CONST_AND[32] = {
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF
};

const uint8_t CBA_CONST_OR[32] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
};

/* ============================================================================
 * IMPLEMENTAÇÃO PADRÃO DE PLATAFORMA (substitua para seu sistema)
 * ============================================================================ */

#ifndef CBA_CUSTOM_PLATFORM

#include <time.h>
#include <stdlib.h>

uint64_t cba_get_time(void) {
    return (uint64_t)time(NULL);
}

void cba_get_random(uint8_t* out, size_t len) {
    /* ATENÇÃO: Use gerador seguro em produção! */
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(rand() & 0xFF);
    }
}

#endif /* CBA_CUSTOM_PLATFORM */

/* ============================================================================
 * FUNÇÕES AUXILIARES
 * ============================================================================ */

bool cba_constant_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

static void feistel_round(uint8_t* state, size_t len, uint8_t round) {
    for (size_t i = 0; i < len; i++) {
        uint8_t x = state[i];
        x = cba_rot_left(x, (round + i) & 7);
        x = x & CBA_CONST_AND[(i + round * 7) & 31];
        x = x | CBA_CONST_OR[(i + round * 11) & 31];
        x = x ^ state[(i + round + 1) % len];
        state[i] = x;
    }
}

/* ============================================================================
 * HASH E MAC
 * ============================================================================ */

void cba_hash(const uint8_t* data, size_t len, uint8_t* out, size_t out_len) {
    uint8_t state[32];
    
    /* Inicializa com prefixo */
    const char* prefix = "TAV-CBA-HASH-V1";
    size_t prefix_len = strlen(prefix);
    
    memset(state, 0, 32);
    for (size_t i = 0; i < prefix_len; i++) {
        state[i % 32] ^= (uint8_t)prefix[i];
    }
    
    /* Absorve dados */
    for (size_t i = 0; i < len; i++) {
        state[i % 32] ^= data[i];
        if ((i + 1) % 32 == 0) {
            for (uint8_t r = 0; r < 4; r++) {
                feistel_round(state, 32, r);
            }
        }
    }
    
    /* Finalização */
    state[0] ^= (len >> 8) & 0xFF;
    state[1] ^= len & 0xFF;
    
    for (uint8_t r = 0; r < 8; r++) {
        feistel_round(state, 32, r);
    }
    
    /* Output */
    size_t copy_len = (out_len < 32) ? out_len : 32;
    memcpy(out, state, copy_len);
}

void cba_mac(const uint8_t* key, size_t key_len,
             const uint8_t* data, size_t data_len,
             uint8_t* out, size_t out_len) {
    /* MAC = hash(key || data || key) */
    uint8_t buffer[256];
    size_t total = 0;
    
    /* Copia key */
    size_t k_copy = (key_len < 64) ? key_len : 64;
    memcpy(buffer + total, key, k_copy);
    total += k_copy;
    
    /* Copia data */
    size_t d_copy = (data_len < 128) ? data_len : 128;
    memcpy(buffer + total, data, d_copy);
    total += d_copy;
    
    /* Copia key novamente */
    memcpy(buffer + total, key, k_copy);
    total += k_copy;
    
    cba_hash(buffer, total, out, out_len);
    
    /* Limpa buffer */
    memset(buffer, 0, sizeof(buffer));
}

/* ============================================================================
 * INICIALIZAÇÃO
 * ============================================================================ */

cba_result_t cba_init(cba_ctx_t* ctx, 
                      const uint8_t* seed, size_t seed_len,
                      uint16_t chain_length) {
    if (!ctx || !seed) return CBA_ERROR_NULL_POINTER;
    if (chain_length > CBA_MAX_CHAIN_LENGTH) chain_length = CBA_MAX_CHAIN_LENGTH;
    
    memset(ctx, 0, sizeof(cba_ctx_t));
    
    /* Deriva seed privada */
    uint8_t seed_with_suffix[256];
    size_t copy_len = (seed_len < 200) ? seed_len : 200;
    memcpy(seed_with_suffix, seed, copy_len);
    memcpy(seed_with_suffix + copy_len, "_IDENTITY_SEED", 14);
    
    cba_hash(seed_with_suffix, copy_len + 14, 
             ctx->identity.private_seed, CBA_HASH_SIZE);
    
    /* Gera cadeia e chave pública */
    uint8_t current[CBA_HASH_SIZE];
    memcpy(current, ctx->identity.private_seed, CBA_HASH_SIZE);
    
    uint8_t index_buf[4];
    for (uint16_t i = 0; i < chain_length; i++) {
        index_buf[0] = (i >> 24) & 0xFF;
        index_buf[1] = (i >> 16) & 0xFF;
        index_buf[2] = (i >> 8) & 0xFF;
        index_buf[3] = i & 0xFF;
        
        uint8_t input[CBA_HASH_SIZE + 4];
        memcpy(input, current, CBA_HASH_SIZE);
        memcpy(input + CBA_HASH_SIZE, index_buf, 4);
        
        cba_hash(input, CBA_HASH_SIZE + 4, current, CBA_HASH_SIZE);
    }
    
    memcpy(ctx->identity.public_key, current, CBA_HASH_SIZE);
    ctx->identity.chain_length = chain_length;
    ctx->identity.current_index = 0;
    ctx->identity.chain_cache = NULL;
    ctx->identity.cache_size = 0;
    
    ctx->session.active = false;
    ctx->revocation_list.count = 0;
    ctx->id_counter = 0;
    ctx->initialized = true;
    
    /* Limpa dados temporários */
    memset(seed_with_suffix, 0, sizeof(seed_with_suffix));
    memset(current, 0, sizeof(current));
    
    return CBA_OK;
}

void cba_cleanup(cba_ctx_t* ctx) {
    if (ctx) {
        memset(ctx->identity.private_seed, 0, CBA_HASH_SIZE);
        memset(ctx->session.master_entropy, 0, CBA_SESSION_ENTROPY);
        ctx->initialized = false;
    }
}

/* ============================================================================
 * IDENTIDADE (Hash-Chain)
 * ============================================================================ */

static void get_chain_element(const cba_identity_t* id, uint16_t steps, uint8_t* out) {
    uint8_t current[CBA_HASH_SIZE];
    memcpy(current, id->private_seed, CBA_HASH_SIZE);
    
    uint8_t index_buf[4];
    for (uint16_t i = 0; i < steps; i++) {
        index_buf[0] = (i >> 24) & 0xFF;
        index_buf[1] = (i >> 16) & 0xFF;
        index_buf[2] = (i >> 8) & 0xFF;
        index_buf[3] = i & 0xFF;
        
        uint8_t input[CBA_HASH_SIZE + 4];
        memcpy(input, current, CBA_HASH_SIZE);
        memcpy(input + CBA_HASH_SIZE, index_buf, 4);
        
        cba_hash(input, CBA_HASH_SIZE + 4, current, CBA_HASH_SIZE);
    }
    
    memcpy(out, current, CBA_HASH_SIZE);
}

cba_result_t cba_identity_sign(cba_ctx_t* ctx,
                               const uint8_t* data, size_t data_len,
                               uint8_t* signature, size_t* sig_len,
                               uint16_t* index_used) {
    if (!ctx || !data || !signature || !sig_len) return CBA_ERROR_NULL_POINTER;
    if (!ctx->initialized) return CBA_ERROR_INVALID_DATA;
    
    if (ctx->identity.current_index >= ctx->identity.chain_length) {
        return CBA_ERROR_CHAIN_EXHAUSTED;
    }
    
    uint16_t index = ctx->identity.current_index;
    uint16_t steps = ctx->identity.chain_length - index - 1;
    
    /* Obtém reveal */
    uint8_t reveal[CBA_HASH_SIZE];
    get_chain_element(&ctx->identity, steps, reveal);
    
    /* Calcula MAC */
    uint8_t mac_input[256];
    size_t mac_len = (data_len < 200) ? data_len : 200;
    memcpy(mac_input, data, mac_len);
    memcpy(mac_input + mac_len, reveal, CBA_HASH_SIZE);
    
    uint8_t mac[CBA_HASH_SIZE];
    cba_hash(mac_input, mac_len + CBA_HASH_SIZE, mac, CBA_HASH_SIZE);
    
    /* Monta assinatura: índice (2) + reveal (32) + mac (32) = 66 bytes */
    signature[0] = (index >> 8) & 0xFF;
    signature[1] = index & 0xFF;
    memcpy(signature + 2, reveal, CBA_HASH_SIZE);
    memcpy(signature + 2 + CBA_HASH_SIZE, mac, CBA_HASH_SIZE);
    
    *sig_len = CBA_SIGNATURE_SIZE;
    if (index_used) *index_used = index;
    
    ctx->identity.current_index++;
    
    return CBA_OK;
}

cba_result_t cba_identity_verify(const uint8_t* public_key,
                                 const uint8_t* data, size_t data_len,
                                 const uint8_t* signature, size_t sig_len) {
    if (!public_key || !data || !signature) return CBA_ERROR_NULL_POINTER;
    if (sig_len < CBA_SIGNATURE_SIZE) return CBA_ERROR_INVALID_DATA;
    
    uint16_t index = ((uint16_t)signature[0] << 8) | signature[1];
    const uint8_t* reveal = signature + 2;
    const uint8_t* mac = signature + 2 + CBA_HASH_SIZE;
    
    /* Verifica MAC */
    uint8_t mac_input[256];
    size_t mac_len = (data_len < 200) ? data_len : 200;
    memcpy(mac_input, data, mac_len);
    memcpy(mac_input + mac_len, reveal, CBA_HASH_SIZE);
    
    uint8_t expected_mac[CBA_HASH_SIZE];
    cba_hash(mac_input, mac_len + CBA_HASH_SIZE, expected_mac, CBA_HASH_SIZE);
    
    if (!cba_constant_compare(mac, expected_mac, CBA_HASH_SIZE)) {
        return CBA_ERROR_SIGNATURE_INVALID;
    }
    
    /* Verifica cadeia: hash^(index+1)(reveal) == public_key */
    uint8_t current[CBA_HASH_SIZE];
    memcpy(current, reveal, CBA_HASH_SIZE);
    
    /* Nota: Esta é uma verificação simplificada.
       Em produção, precisa saber o chain_length original */
    for (uint16_t i = 0; i <= index; i++) {
        uint8_t idx_buf[4] = {0, 0, (uint8_t)(i >> 8), (uint8_t)(i & 0xFF)};
        uint8_t input[CBA_HASH_SIZE + 4];
        memcpy(input, current, CBA_HASH_SIZE);
        memcpy(input + CBA_HASH_SIZE, idx_buf, 4);
        cba_hash(input, CBA_HASH_SIZE + 4, current, CBA_HASH_SIZE);
    }
    
    if (!cba_constant_compare(current, public_key, CBA_HASH_SIZE)) {
        return CBA_ERROR_SIGNATURE_INVALID;
    }
    
    return CBA_OK;
}

uint16_t cba_identity_remaining(const cba_ctx_t* ctx) {
    if (!ctx || !ctx->initialized) return 0;
    return ctx->identity.chain_length - ctx->identity.current_index;
}

/* ============================================================================
 * SESSÃO (Commitment-Reveal)
 * ============================================================================ */

cba_result_t cba_session_create(cba_ctx_t* ctx, uint32_t duration_seconds) {
    if (!ctx) return CBA_ERROR_NULL_POINTER;
    if (!ctx->initialized) return CBA_ERROR_INVALID_DATA;
    
    uint64_t now = cba_get_time();
    
    /* Gera entropia para sessão */
    uint8_t random[16];
    cba_get_random(random, 16);
    
    uint8_t entropy_input[128];
    memcpy(entropy_input, ctx->identity.private_seed, CBA_HASH_SIZE);
    memcpy(entropy_input + CBA_HASH_SIZE, &now, 8);
    memcpy(entropy_input + CBA_HASH_SIZE + 8, &ctx->id_counter, 4);
    memcpy(entropy_input + CBA_HASH_SIZE + 12, random, 16);
    ctx->id_counter++;
    
    cba_hash(entropy_input, CBA_HASH_SIZE + 28, 
             ctx->session.master_entropy, CBA_SESSION_ENTROPY);
    
    /* Commitment */
    cba_hash(ctx->session.master_entropy, CBA_SESSION_ENTROPY,
             ctx->session.commitment, CBA_HASH_SIZE);
    
    /* Session ID */
    uint8_t sid_input[CBA_HASH_SIZE + 8];
    memcpy(sid_input, ctx->session.commitment, CBA_HASH_SIZE);
    memcpy(sid_input + CBA_HASH_SIZE, &now, 8);
    cba_hash(sid_input, CBA_HASH_SIZE + 8, ctx->session.session_id, CBA_ID_SIZE);
    
    ctx->session.created_at = now;
    ctx->session.expires_at = now + duration_seconds;
    ctx->session.tx_count = 0;
    ctx->session.active = true;
    
    return CBA_OK;
}

cba_result_t cba_session_proof(cba_ctx_t* ctx, uint8_t* proof) {
    if (!ctx || !proof) return CBA_ERROR_NULL_POINTER;
    if (!ctx->session.active) return CBA_ERROR_INVALID_DATA;
    
    uint64_t now = cba_get_time();
    if (now > ctx->session.expires_at) {
        ctx->session.active = false;
        return CBA_ERROR_SESSION_EXPIRED;
    }
    
    /* Prova = hash(entropy || tx_count) */
    uint8_t input[CBA_SESSION_ENTROPY + 8];
    memcpy(input, ctx->session.master_entropy, CBA_SESSION_ENTROPY);
    
    uint32_t tc = ctx->session.tx_count;
    input[CBA_SESSION_ENTROPY] = (tc >> 24) & 0xFF;
    input[CBA_SESSION_ENTROPY + 1] = (tc >> 16) & 0xFF;
    input[CBA_SESSION_ENTROPY + 2] = (tc >> 8) & 0xFF;
    input[CBA_SESSION_ENTROPY + 3] = tc & 0xFF;
    
    cba_hash(input, CBA_SESSION_ENTROPY + 4, proof, CBA_HASH_SIZE);
    
    ctx->session.tx_count++;
    
    return CBA_OK;
}

bool cba_session_is_active(const cba_ctx_t* ctx) {
    if (!ctx) return false;
    if (!ctx->session.active) return false;
    return cba_get_time() <= ctx->session.expires_at;
}

/* ============================================================================
 * CAPABILITIES
 * ============================================================================ */

static void generate_capability_id(cba_ctx_t* ctx, 
                                   const uint8_t* holder_key,
                                   uint8_t* out) {
    uint64_t now = cba_get_time();
    uint8_t input[CBA_HASH_SIZE + CBA_HASH_SIZE + 12];
    
    memcpy(input, ctx->identity.public_key, CBA_HASH_SIZE);
    memcpy(input + CBA_HASH_SIZE, holder_key, CBA_HASH_SIZE);
    
    input[CBA_HASH_SIZE * 2] = (now >> 56) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 1] = (now >> 48) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 2] = (now >> 40) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 3] = (now >> 32) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 4] = (now >> 24) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 5] = (now >> 16) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 6] = (now >> 8) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 7] = now & 0xFF;
    
    input[CBA_HASH_SIZE * 2 + 8] = (ctx->id_counter >> 24) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 9] = (ctx->id_counter >> 16) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 10] = (ctx->id_counter >> 8) & 0xFF;
    input[CBA_HASH_SIZE * 2 + 11] = ctx->id_counter & 0xFF;
    
    ctx->id_counter++;
    
    cba_hash(input, sizeof(input), out, CBA_ID_SIZE);
}

static size_t serialize_capability_for_signing(const cba_capability_t* cap, 
                                                uint8_t* buffer) {
    size_t pos = 0;
    
    memcpy(buffer + pos, cap->id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(buffer + pos, cap->issuer_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(buffer + pos, cap->holder_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    
    buffer[pos++] = (cap->permissions >> 24) & 0xFF;
    buffer[pos++] = (cap->permissions >> 16) & 0xFF;
    buffer[pos++] = (cap->permissions >> 8) & 0xFF;
    buffer[pos++] = cap->permissions & 0xFF;
    
    for (int i = 7; i >= 0; i--) buffer[pos++] = (cap->created_at >> (i * 8)) & 0xFF;
    for (int i = 7; i >= 0; i--) buffer[pos++] = (cap->expires_at >> (i * 8)) & 0xFF;
    
    buffer[pos++] = (cap->max_uses >> 24) & 0xFF;
    buffer[pos++] = (cap->max_uses >> 16) & 0xFF;
    buffer[pos++] = (cap->max_uses >> 8) & 0xFF;
    buffer[pos++] = cap->max_uses & 0xFF;
    
    buffer[pos++] = cap->delegation_depth;
    buffer[pos++] = cap->max_delegation_depth;
    
    if (cap->has_parent) {
        memcpy(buffer + pos, cap->parent_id, CBA_ID_SIZE);
        pos += CBA_ID_SIZE;
    }
    
    buffer[pos++] = cap->n_resources;
    for (uint8_t i = 0; i < cap->n_resources; i++) {
        memcpy(buffer + pos, cap->resources[i].id, cap->resources[i].id_len);
        pos += cap->resources[i].id_len;
    }
    
    return pos;
}

cba_result_t cba_capability_issue(cba_ctx_t* ctx,
                                  const uint8_t* holder_public_key,
                                  uint32_t permissions,
                                  const char** resources, uint8_t n_resources,
                                  uint32_t duration_seconds,
                                  int32_t max_uses,
                                  uint8_t max_delegation,
                                  cba_capability_t* cap) {
    if (!ctx || !holder_public_key || !cap) return CBA_ERROR_NULL_POINTER;
    if (!ctx->initialized) return CBA_ERROR_INVALID_DATA;
    if (n_resources > CBA_MAX_RESOURCES) n_resources = CBA_MAX_RESOURCES;
    
    uint64_t now = cba_get_time();
    
    memset(cap, 0, sizeof(cba_capability_t));
    
    /* Gera ID */
    generate_capability_id(ctx, holder_public_key, cap->id);
    
    /* IDs */
    cba_hash(ctx->identity.public_key, CBA_HASH_SIZE, cap->issuer_id, CBA_ID_SIZE);
    cba_hash(holder_public_key, CBA_HASH_SIZE, cap->holder_id, CBA_ID_SIZE);
    
    /* Dados */
    cap->permissions = permissions;
    cap->created_at = now;
    cap->expires_at = now + duration_seconds;
    cap->max_uses = max_uses;
    cap->uses_count = 0;
    cap->delegation_depth = 0;
    cap->max_delegation_depth = max_delegation;
    cap->has_parent = false;
    cap->revoked = false;
    
    /* Recursos */
    cap->n_resources = n_resources;
    for (uint8_t i = 0; i < n_resources && resources && resources[i]; i++) {
        size_t len = strlen(resources[i]);
        if (len >= CBA_MAX_RESOURCE_LEN) len = CBA_MAX_RESOURCE_LEN - 1;
        memcpy(cap->resources[i].id, resources[i], len);
        cap->resources[i].id[len] = '\0';
        cap->resources[i].id_len = (uint8_t)len;
    }
    
    /* Assina */
    uint8_t sign_buffer[512];
    size_t sign_len = serialize_capability_for_signing(cap, sign_buffer);
    
    cba_result_t res = cba_identity_sign(ctx, sign_buffer, sign_len,
                                         cap->signature, &cap->signature_len, NULL);
    
    return res;
}

cba_result_t cba_capability_delegate(cba_ctx_t* ctx,
                                     const cba_capability_t* parent,
                                     const uint8_t* new_holder_public_key,
                                     uint32_t permissions,
                                     const char** resources, uint8_t n_resources,
                                     uint32_t duration_seconds,
                                     cba_capability_t* delegated) {
    if (!ctx || !parent || !new_holder_public_key || !delegated) {
        return CBA_ERROR_NULL_POINTER;
    }
    
    if (parent->revoked) return CBA_ERROR_CAPABILITY_REVOKED;
    if (parent->delegation_depth >= parent->max_delegation_depth) {
        return CBA_ERROR_MAX_DELEGATION;
    }
    if (!(parent->permissions & CBA_PERM_DELEGATE)) {
        return CBA_ERROR_PERMISSION_DENIED;
    }
    
    uint64_t now = cba_get_time();
    
    /* Restringe permissões */
    uint32_t allowed_perms = permissions & parent->permissions;
    
    /* Restringe duração */
    uint64_t max_expires = parent->expires_at;
    uint64_t actual_expires = now + duration_seconds;
    if (actual_expires > max_expires) actual_expires = max_expires;
    
    memset(delegated, 0, sizeof(cba_capability_t));
    
    /* Gera ID */
    generate_capability_id(ctx, new_holder_public_key, delegated->id);
    
    /* IDs */
    cba_hash(ctx->identity.public_key, CBA_HASH_SIZE, delegated->issuer_id, CBA_ID_SIZE);
    cba_hash(new_holder_public_key, CBA_HASH_SIZE, delegated->holder_id, CBA_ID_SIZE);
    
    /* Dados */
    delegated->permissions = allowed_perms;
    delegated->created_at = now;
    delegated->expires_at = actual_expires;
    delegated->max_uses = parent->max_uses;
    delegated->uses_count = 0;
    delegated->delegation_depth = parent->delegation_depth + 1;
    delegated->max_delegation_depth = parent->max_delegation_depth;
    delegated->has_parent = true;
    memcpy(delegated->parent_id, parent->id, CBA_ID_SIZE);
    delegated->revoked = false;
    
    /* Filtra recursos (apenas os que estão no parent) */
    uint8_t valid_count = 0;
    for (uint8_t i = 0; i < n_resources && resources && resources[i]; i++) {
        if (cba_capability_has_resource(parent, resources[i])) {
            size_t len = strlen(resources[i]);
            if (len >= CBA_MAX_RESOURCE_LEN) len = CBA_MAX_RESOURCE_LEN - 1;
            memcpy(delegated->resources[valid_count].id, resources[i], len);
            delegated->resources[valid_count].id[len] = '\0';
            delegated->resources[valid_count].id_len = (uint8_t)len;
            valid_count++;
            if (valid_count >= CBA_MAX_RESOURCES) break;
        }
    }
    delegated->n_resources = valid_count;
    
    /* Assina */
    uint8_t sign_buffer[512];
    size_t sign_len = serialize_capability_for_signing(delegated, sign_buffer);
    
    return cba_identity_sign(ctx, sign_buffer, sign_len,
                             delegated->signature, &delegated->signature_len, NULL);
}

cba_result_t cba_capability_revoke(cba_ctx_t* ctx, const uint8_t* cap_id) {
    if (!ctx || !cap_id) return CBA_ERROR_NULL_POINTER;
    
    if (ctx->revocation_list.count < CBA_REVOCATION_LIST_SIZE) {
        memcpy(ctx->revocation_list.ids[ctx->revocation_list.count], 
               cap_id, CBA_ID_SIZE);
        ctx->revocation_list.count++;
    }
    
    return CBA_OK;
}

bool cba_capability_is_revoked(const cba_ctx_t* ctx, const uint8_t* cap_id) {
    if (!ctx || !cap_id) return true;
    
    for (uint16_t i = 0; i < ctx->revocation_list.count; i++) {
        if (cba_constant_compare(ctx->revocation_list.ids[i], cap_id, CBA_ID_SIZE)) {
            return true;
        }
    }
    return false;
}

bool cba_capability_has_resource(const cba_capability_t* cap, const char* resource_id) {
    if (!cap || !resource_id) return false;
    
    for (uint8_t i = 0; i < cap->n_resources; i++) {
        if (strcmp(cap->resources[i].id, resource_id) == 0) {
            return true;
        }
    }
    return false;
}

bool cba_capability_has_permission(const cba_capability_t* cap, cba_permission_t perm) {
    if (!cap) return false;
    return (cap->permissions & perm) == perm;
}

/* ============================================================================
 * PROVA CBA
 * ============================================================================ */

cba_permission_t cba_operation_to_permission(const char* operation) {
    if (!operation) return CBA_PERM_NONE;
    
    if (strcmp(operation, "READ") == 0) return CBA_PERM_READ;
    if (strcmp(operation, "WRITE") == 0) return CBA_PERM_WRITE;
    if (strcmp(operation, "DELETE") == 0) return CBA_PERM_DELETE;
    if (strcmp(operation, "ENCRYPT") == 0) return CBA_PERM_ENCRYPT;
    if (strcmp(operation, "DECRYPT") == 0) return CBA_PERM_DECRYPT;
    if (strcmp(operation, "SIGN") == 0) return CBA_PERM_SIGN;
    if (strcmp(operation, "VERIFY") == 0) return CBA_PERM_VERIFY;
    if (strcmp(operation, "DELEGATE") == 0) return CBA_PERM_DELEGATE;
    if (strcmp(operation, "REVOKE") == 0) return CBA_PERM_REVOKE;
    if (strcmp(operation, "ADMIN") == 0) return CBA_PERM_ADMIN;
    
    return CBA_PERM_NONE;
}

cba_result_t cba_proof_generate(cba_ctx_t* ctx,
                                cba_capability_t* cap,
                                const char* operation,
                                const char* resource_id,
                                bool include_identity,
                                cba_proof_t* proof) {
    if (!ctx || !cap || !operation || !resource_id || !proof) {
        return CBA_ERROR_NULL_POINTER;
    }
    
    /* Validações */
    if (cap->revoked || cba_capability_is_revoked(ctx, cap->id)) {
        return CBA_ERROR_CAPABILITY_REVOKED;
    }
    
    uint64_t now = cba_get_time();
    if (now > cap->expires_at) {
        return CBA_ERROR_CAPABILITY_EXPIRED;
    }
    
    if (cap->max_uses >= 0 && cap->uses_count >= (uint32_t)cap->max_uses) {
        return CBA_ERROR_MAX_USES_EXCEEDED;
    }
    
    if (!cba_capability_has_resource(cap, resource_id)) {
        return CBA_ERROR_RESOURCE_DENIED;
    }
    
    cba_permission_t perm = cba_operation_to_permission(operation);
    if (!cba_capability_has_permission(cap, perm)) {
        return CBA_ERROR_PERMISSION_DENIED;
    }
    
    memset(proof, 0, sizeof(cba_proof_t));
    
    /* Preenche prova */
    memcpy(proof->capability_id, cap->id, CBA_ID_SIZE);
    
    /* Prova de sessão */
    cba_result_t res = cba_session_proof(ctx, proof->session_proof);
    if (res != CBA_OK) return res;
    
    /* Operação e recurso */
    size_t op_len = strlen(operation);
    if (op_len >= CBA_MAX_OPERATION_LEN) op_len = CBA_MAX_OPERATION_LEN - 1;
    memcpy(proof->operation, operation, op_len);
    proof->operation_len = (uint8_t)op_len;
    
    size_t res_len = strlen(resource_id);
    if (res_len >= CBA_MAX_RESOURCE_LEN) res_len = CBA_MAX_RESOURCE_LEN - 1;
    memcpy(proof->resource_id, resource_id, res_len);
    proof->resource_id_len = (uint8_t)res_len;
    
    proof->timestamp = now;
    
    /* Nonce */
    cba_get_random(proof->nonce, CBA_NONCE_SIZE);
    
    /* Prova de identidade (opcional) */
    if (include_identity) {
        uint8_t id_data[CBA_ID_SIZE + CBA_HASH_SIZE + CBA_NONCE_SIZE];
        memcpy(id_data, cap->id, CBA_ID_SIZE);
        memcpy(id_data + CBA_ID_SIZE, proof->session_proof, CBA_HASH_SIZE);
        memcpy(id_data + CBA_ID_SIZE + CBA_HASH_SIZE, proof->nonce, CBA_NONCE_SIZE);
        
        size_t id_sig_len;
        res = cba_identity_sign(ctx, id_data, sizeof(id_data),
                                proof->identity_proof, &id_sig_len, &proof->chain_index);
        if (res != CBA_OK) return res;
        
        proof->has_identity_proof = true;
    }
    
    /* Assinatura final */
    uint8_t proof_data[256];
    size_t pos = 0;
    
    memcpy(proof_data + pos, proof->capability_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(proof_data + pos, proof->session_proof, CBA_HASH_SIZE); pos += CBA_HASH_SIZE;
    memcpy(proof_data + pos, proof->operation, proof->operation_len); pos += proof->operation_len;
    memcpy(proof_data + pos, proof->resource_id, proof->resource_id_len); pos += proof->resource_id_len;
    
    for (int i = 7; i >= 0; i--) proof_data[pos++] = (proof->timestamp >> (i * 8)) & 0xFF;
    
    memcpy(proof_data + pos, proof->nonce, CBA_NONCE_SIZE); pos += CBA_NONCE_SIZE;
    
    if (proof->has_identity_proof) {
        memcpy(proof_data + pos, proof->identity_proof, CBA_SIGNATURE_SIZE);
        pos += CBA_SIGNATURE_SIZE;
    }
    
    cba_mac(ctx->session.master_entropy, CBA_SESSION_ENTROPY,
            proof_data, pos, proof->proof_signature, CBA_HASH_SIZE);
    
    /* Incrementa uso */
    cap->uses_count++;
    
    return CBA_OK;
}

cba_result_t cba_proof_verify(const cba_ctx_t* ctx,
                              const cba_proof_t* proof,
                              const cba_capability_t* cap,
                              const uint8_t* issuer_public_key,
                              uint32_t max_age_seconds) {
    if (!proof || !cap || !issuer_public_key) return CBA_ERROR_NULL_POINTER;
    
    uint64_t now = cba_get_time();
    
    /* Verifica timestamp */
    if (now - proof->timestamp > max_age_seconds) {
        return CBA_ERROR_PROOF_EXPIRED;
    }
    
    if (proof->timestamp > now + 60) {
        return CBA_ERROR_PROOF_INVALID;
    }
    
    /* Verifica capability ID */
    if (!cba_constant_compare(proof->capability_id, cap->id, CBA_ID_SIZE)) {
        return CBA_ERROR_INVALID_DATA;
    }
    
    /* Verifica revogação */
    if (cap->revoked) return CBA_ERROR_CAPABILITY_REVOKED;
    if (ctx && cba_capability_is_revoked(ctx, cap->id)) {
        return CBA_ERROR_CAPABILITY_REVOKED;
    }
    
    /* Verifica expiração */
    if (now > cap->expires_at) return CBA_ERROR_CAPABILITY_EXPIRED;
    
    /* Verifica assinatura da capability */
    uint8_t sign_buffer[512];
    size_t sign_len = serialize_capability_for_signing(cap, sign_buffer);
    
    cba_result_t res = cba_identity_verify(issuer_public_key, sign_buffer, sign_len,
                                           cap->signature, cap->signature_len);
    if (res != CBA_OK) return res;
    
    /* Verifica operação e recurso */
    if (!cba_capability_has_resource(cap, proof->resource_id)) {
        return CBA_ERROR_RESOURCE_DENIED;
    }
    
    cba_permission_t perm = cba_operation_to_permission(proof->operation);
    if (!cba_capability_has_permission(cap, perm)) {
        return CBA_ERROR_PERMISSION_DENIED;
    }
    
    /* Verifica prova de identidade se presente */
    if (proof->has_identity_proof) {
        uint8_t id_data[CBA_ID_SIZE + CBA_HASH_SIZE + CBA_NONCE_SIZE];
        memcpy(id_data, cap->id, CBA_ID_SIZE);
        memcpy(id_data + CBA_ID_SIZE, proof->session_proof, CBA_HASH_SIZE);
        memcpy(id_data + CBA_ID_SIZE + CBA_HASH_SIZE, proof->nonce, CBA_NONCE_SIZE);
        
        res = cba_identity_verify(issuer_public_key, id_data, sizeof(id_data),
                                  proof->identity_proof, CBA_SIGNATURE_SIZE);
        if (res != CBA_OK) return res;
    }
    
    return CBA_OK;
}

/* ============================================================================
 * SERIALIZAÇÃO
 * ============================================================================ */

cba_result_t cba_capability_serialize(const cba_capability_t* cap,
                                      uint8_t* buffer, size_t buffer_size,
                                      size_t* out_len) {
    if (!cap || !buffer || !out_len) return CBA_ERROR_NULL_POINTER;
    
    size_t pos = 0;
    
    /* Magic + Version */
    if (pos + 5 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    buffer[pos++] = 'T';
    buffer[pos++] = 'C';
    buffer[pos++] = 'A';
    buffer[pos++] = 'P';
    buffer[pos++] = 1;
    
    /* IDs */
    if (pos + CBA_ID_SIZE * 3 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    memcpy(buffer + pos, cap->id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(buffer + pos, cap->issuer_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(buffer + pos, cap->holder_id, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    
    /* Permissions */
    if (pos + 4 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    buffer[pos++] = (cap->permissions >> 24) & 0xFF;
    buffer[pos++] = (cap->permissions >> 16) & 0xFF;
    buffer[pos++] = (cap->permissions >> 8) & 0xFF;
    buffer[pos++] = cap->permissions & 0xFF;
    
    /* Timestamps */
    if (pos + 16 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    for (int i = 7; i >= 0; i--) buffer[pos++] = (cap->created_at >> (i * 8)) & 0xFF;
    for (int i = 7; i >= 0; i--) buffer[pos++] = (cap->expires_at >> (i * 8)) & 0xFF;
    
    /* Limits */
    if (pos + 8 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    buffer[pos++] = (cap->max_uses >> 24) & 0xFF;
    buffer[pos++] = (cap->max_uses >> 16) & 0xFF;
    buffer[pos++] = (cap->max_uses >> 8) & 0xFF;
    buffer[pos++] = cap->max_uses & 0xFF;
    buffer[pos++] = (cap->uses_count >> 24) & 0xFF;
    buffer[pos++] = (cap->uses_count >> 16) & 0xFF;
    buffer[pos++] = (cap->uses_count >> 8) & 0xFF;
    buffer[pos++] = cap->uses_count & 0xFF;
    
    /* Delegation */
    if (pos + 2 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    buffer[pos++] = cap->delegation_depth;
    buffer[pos++] = cap->max_delegation_depth;
    
    /* Parent */
    if (pos + 1 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    buffer[pos++] = cap->has_parent ? 1 : 0;
    if (cap->has_parent) {
        if (pos + CBA_ID_SIZE > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
        memcpy(buffer + pos, cap->parent_id, CBA_ID_SIZE);
        pos += CBA_ID_SIZE;
    }
    
    /* Resources */
    if (pos + 1 > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    buffer[pos++] = cap->n_resources;
    
    for (uint8_t i = 0; i < cap->n_resources; i++) {
        if (pos + 1 + cap->resources[i].id_len > buffer_size) {
            return CBA_ERROR_BUFFER_TOO_SMALL;
        }
        buffer[pos++] = cap->resources[i].id_len;
        memcpy(buffer + pos, cap->resources[i].id, cap->resources[i].id_len);
        pos += cap->resources[i].id_len;
    }
    
    /* Signature */
    if (pos + 2 + cap->signature_len > buffer_size) return CBA_ERROR_BUFFER_TOO_SMALL;
    buffer[pos++] = (cap->signature_len >> 8) & 0xFF;
    buffer[pos++] = cap->signature_len & 0xFF;
    memcpy(buffer + pos, cap->signature, cap->signature_len);
    pos += cap->signature_len;
    
    *out_len = pos;
    return CBA_OK;
}

cba_result_t cba_capability_deserialize(const uint8_t* buffer, size_t len,
                                        cba_capability_t* cap) {
    if (!buffer || !cap) return CBA_ERROR_NULL_POINTER;
    if (len < 5) return CBA_ERROR_INVALID_DATA;
    
    size_t pos = 0;
    
    /* Magic + Version */
    if (buffer[0] != 'T' || buffer[1] != 'C' || 
        buffer[2] != 'A' || buffer[3] != 'P') {
        return CBA_ERROR_INVALID_DATA;
    }
    pos = 5;
    
    memset(cap, 0, sizeof(cba_capability_t));
    
    /* IDs */
    if (pos + CBA_ID_SIZE * 3 > len) return CBA_ERROR_INVALID_DATA;
    memcpy(cap->id, buffer + pos, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(cap->issuer_id, buffer + pos, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    memcpy(cap->holder_id, buffer + pos, CBA_ID_SIZE); pos += CBA_ID_SIZE;
    
    /* Permissions */
    if (pos + 4 > len) return CBA_ERROR_INVALID_DATA;
    cap->permissions = ((uint32_t)buffer[pos] << 24) | ((uint32_t)buffer[pos+1] << 16) |
                       ((uint32_t)buffer[pos+2] << 8) | buffer[pos+3];
    pos += 4;
    
    /* Timestamps */
    if (pos + 16 > len) return CBA_ERROR_INVALID_DATA;
    cap->created_at = 0;
    for (int i = 0; i < 8; i++) cap->created_at = (cap->created_at << 8) | buffer[pos++];
    cap->expires_at = 0;
    for (int i = 0; i < 8; i++) cap->expires_at = (cap->expires_at << 8) | buffer[pos++];
    
    /* Limits */
    if (pos + 8 > len) return CBA_ERROR_INVALID_DATA;
    cap->max_uses = ((int32_t)buffer[pos] << 24) | ((int32_t)buffer[pos+1] << 16) |
                    ((int32_t)buffer[pos+2] << 8) | buffer[pos+3];
    pos += 4;
    cap->uses_count = ((uint32_t)buffer[pos] << 24) | ((uint32_t)buffer[pos+1] << 16) |
                      ((uint32_t)buffer[pos+2] << 8) | buffer[pos+3];
    pos += 4;
    
    /* Delegation */
    if (pos + 2 > len) return CBA_ERROR_INVALID_DATA;
    cap->delegation_depth = buffer[pos++];
    cap->max_delegation_depth = buffer[pos++];
    
    /* Parent */
    if (pos + 1 > len) return CBA_ERROR_INVALID_DATA;
    cap->has_parent = buffer[pos++] != 0;
    if (cap->has_parent) {
        if (pos + CBA_ID_SIZE > len) return CBA_ERROR_INVALID_DATA;
        memcpy(cap->parent_id, buffer + pos, CBA_ID_SIZE);
        pos += CBA_ID_SIZE;
    }
    
    /* Resources */
    if (pos + 1 > len) return CBA_ERROR_INVALID_DATA;
    cap->n_resources = buffer[pos++];
    if (cap->n_resources > CBA_MAX_RESOURCES) cap->n_resources = CBA_MAX_RESOURCES;
    
    for (uint8_t i = 0; i < cap->n_resources; i++) {
        if (pos + 1 > len) return CBA_ERROR_INVALID_DATA;
        cap->resources[i].id_len = buffer[pos++];
        if (cap->resources[i].id_len >= CBA_MAX_RESOURCE_LEN) {
            cap->resources[i].id_len = CBA_MAX_RESOURCE_LEN - 1;
        }
        if (pos + cap->resources[i].id_len > len) return CBA_ERROR_INVALID_DATA;
        memcpy(cap->resources[i].id, buffer + pos, cap->resources[i].id_len);
        cap->resources[i].id[cap->resources[i].id_len] = '\0';
        pos += cap->resources[i].id_len;
    }
    
    /* Signature */
    if (pos + 2 > len) return CBA_ERROR_INVALID_DATA;
    cap->signature_len = ((uint16_t)buffer[pos] << 8) | buffer[pos+1];
    pos += 2;
    if (cap->signature_len > CBA_SIGNATURE_SIZE) cap->signature_len = CBA_SIGNATURE_SIZE;
    if (pos + cap->signature_len > len) return CBA_ERROR_INVALID_DATA;
    memcpy(cap->signature, buffer + pos, cap->signature_len);
    
    return CBA_OK;
}

/* ============================================================================
 * UTILIDADES
 * ============================================================================ */

const char* cba_error_string(cba_result_t error) {
    switch (error) {
        case CBA_OK: return "OK";
        case CBA_ERROR_NULL_POINTER: return "Null pointer";
        case CBA_ERROR_INVALID_DATA: return "Invalid data";
        case CBA_ERROR_CHAIN_EXHAUSTED: return "Identity chain exhausted";
        case CBA_ERROR_SESSION_EXPIRED: return "Session expired";
        case CBA_ERROR_CAPABILITY_EXPIRED: return "Capability expired";
        case CBA_ERROR_CAPABILITY_REVOKED: return "Capability revoked";
        case CBA_ERROR_PERMISSION_DENIED: return "Permission denied";
        case CBA_ERROR_RESOURCE_DENIED: return "Resource access denied";
        case CBA_ERROR_MAX_USES_EXCEEDED: return "Maximum uses exceeded";
        case CBA_ERROR_MAX_DELEGATION: return "Maximum delegation depth reached";
        case CBA_ERROR_SIGNATURE_INVALID: return "Invalid signature";
        case CBA_ERROR_PROOF_EXPIRED: return "Proof expired";
        case CBA_ERROR_PROOF_INVALID: return "Invalid proof";
        case CBA_ERROR_BUFFER_TOO_SMALL: return "Buffer too small";
        default: return "Unknown error";
    }
}

/* ============================================================================
 * DEMONSTRAÇÃO
 * ============================================================================ */

#ifdef CBA_DEMO

#include <stdio.h>

int main(void) {
    printf("======================================================================\n");
    printf("TAV CAPABILITY-BASED AUTHENTICATION (CBA) V1.0 - C Demo\n");
    printf("======================================================================\n\n");
    
    /* Alice */
    printf("1. Inicializando Alice...\n");
    cba_ctx_t alice;
    const char* alice_seed = "alice super secret seed";
    cba_result_t res = cba_init(&alice, (uint8_t*)alice_seed, strlen(alice_seed), 100);
    printf("   Resultado: %s\n", cba_error_string(res));
    printf("   Assinaturas disponíveis: %d\n", cba_identity_remaining(&alice));
    
    /* Bob */
    printf("\n2. Inicializando Bob...\n");
    cba_ctx_t bob;
    const char* bob_seed = "bob super secret seed";
    res = cba_init(&bob, (uint8_t*)bob_seed, strlen(bob_seed), 100);
    printf("   Resultado: %s\n", cba_error_string(res));
    
    /* Sessões */
    printf("\n3. Criando sessões...\n");
    cba_session_create(&alice, 3600);
    cba_session_create(&bob, 3600);
    printf("   Alice session ativa: %s\n", cba_session_is_active(&alice) ? "sim" : "não");
    printf("   Bob session ativa: %s\n", cba_session_is_active(&bob) ? "sim" : "não");
    
    /* Capability */
    printf("\n4. Alice emite capability para Bob...\n");
    const char* resources[] = {"file:documento.txt", "file:relatorio.pdf", NULL};
    cba_capability_t cap;
    res = cba_capability_issue(&alice, bob.identity.public_key,
                               CBA_PERM_READ | CBA_PERM_ENCRYPT | CBA_PERM_DELEGATE,
                               resources, 2, 7200, 50, 2, &cap);
    printf("   Resultado: %s\n", cba_error_string(res));
    printf("   Capability ID: ");
    for (int i = 0; i < 8; i++) printf("%02x", cap.id[i]);
    printf("...\n");
    printf("   Permissões: %u\n", cap.permissions);
    printf("   Assinatura: %zu bytes\n", cap.signature_len);
    
    /* Serialização */
    printf("\n5. Serializando capability...\n");
    uint8_t cap_buffer[CBA_CAPABILITY_MAX_SIZE];
    size_t cap_len;
    res = cba_capability_serialize(&cap, cap_buffer, sizeof(cap_buffer), &cap_len);
    printf("   Resultado: %s\n", cba_error_string(res));
    printf("   Tamanho serializado: %zu bytes\n", cap_len);
    
    /* Bob gera prova */
    printf("\n6. Bob gera prova de acesso...\n");
    cba_proof_t proof;
    res = cba_proof_generate(&bob, &cap, "READ", "file:documento.txt", true, &proof);
    printf("   Resultado: %s\n", cba_error_string(res));
    printf("   Operação: %s\n", proof.operation);
    printf("   Recurso: %s\n", proof.resource_id);
    printf("   Com identidade: %s\n", proof.has_identity_proof ? "sim" : "não");
    
    /* Verificação */
    printf("\n7. Verificando prova...\n");
    res = cba_proof_verify(&alice, &proof, &cap, alice.identity.public_key, 300);
    printf("   Resultado: %s\n", cba_error_string(res));
    
    /* Teste de permissão negada */
    printf("\n8. Bob tenta operação não permitida (DELETE)...\n");
    cba_proof_t bad_proof;
    res = cba_proof_generate(&bob, &cap, "DELETE", "file:documento.txt", false, &bad_proof);
    printf("   Resultado: %s\n", cba_error_string(res));
    
    /* Revogação */
    printf("\n9. Alice revoga capability...\n");
    cba_capability_revoke(&alice, cap.id);
    printf("   Revogada: %s\n", cba_capability_is_revoked(&alice, cap.id) ? "sim" : "não");
    
    /* Tenta usar após revogação */
    printf("\n10. Bob tenta usar capability revogada...\n");
    cba_proof_t revoked_proof;
    res = cba_proof_generate(&bob, &cap, "READ", "file:documento.txt", false, &revoked_proof);
    printf("    Resultado: %s\n", cba_error_string(res));
    
    /* Status final */
    printf("\n11. Status final:\n");
    printf("    Alice assinaturas restantes: %d\n", cba_identity_remaining(&alice));
    printf("    Bob assinaturas restantes: %d\n", cba_identity_remaining(&bob));
    
    /* Cleanup */
    cba_cleanup(&alice);
    cba_cleanup(&bob);
    
    printf("\n======================================================================\n");
    printf("Demo concluída!\n");
    printf("======================================================================\n");
    
    return 0;
}

#endif /* CBA_DEMO */
