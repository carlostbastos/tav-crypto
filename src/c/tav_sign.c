/*
 * TAV Clock Cryptography v0.9
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
 */

/*
 * TAV-SIGN - Sistema de Assinaturas Digitais
 * ==========================================
 * 
 * Duas opções:
 * 1. Hash Chain (Lamport-style) - stateful, simples, comprovado
 * 2. Commitment-Reveal - usa estado TAV, mais flexível
 */

#include "tav.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================================
 * OPÇÃO 1: HASH CHAIN (Lamport-style)
 * ============================================================================
 * 
 * Conceito:
 *   S_0 (seed) → S_1 → S_2 → ... → S_n (public key)
 *   Cada S_i = hash(S_{i-1})
 * 
 * Assinar mensagem #i:
 *   1. Revela S_{n-i}
 *   2. MAC = hash(mensagem || S_{n-i})
 *   3. Assinatura = (i, S_{n-i}, MAC)
 * 
 * Verificar:
 *   1. Aplica hash i vezes em S_{n-i}
 *   2. Resultado deve == public key
 *   3. Verifica MAC
 * 
 * Vantagem: Simples, seguro, bem estudado
 * Desvantagem: Número limitado de assinaturas
 */

tav_result_t tav_sign_chain_keygen(tav_sign_chain_t* keys,
                                   const uint8_t* seed,
                                   size_t seed_len) {
    if (!keys || !seed) return TAV_ERROR_NULL_POINTER;
    
    keys->chain_length = TAV_SIGN_CHAIN_LENGTH;
    keys->current_index = 0;
    
    /* Hash do seed inicial */
    tav_hash(seed, seed_len, keys->private_seed);
    
    /* Gera chain: aplica hash n vezes para chegar na chave pública */
    uint8_t current[TAV_SIGN_HASH_SIZE];
    memcpy(current, keys->private_seed, TAV_SIGN_HASH_SIZE);
    
    for (uint16_t i = 0; i < keys->chain_length; i++) {
        uint8_t next[TAV_SIGN_HASH_SIZE];
        tav_hash(current, TAV_SIGN_HASH_SIZE, next);
        memcpy(current, next, TAV_SIGN_HASH_SIZE);
    }
    
    /* Chave pública = ponta da chain */
    memcpy(keys->public_key, current, TAV_SIGN_HASH_SIZE);
    
    return TAV_OK;
}

tav_result_t tav_sign_chain_sign(tav_sign_chain_t* keys,
                                 const uint8_t* message,
                                 size_t msg_len,
                                 uint8_t* signature,
                                 size_t* sig_len) {
    if (!keys || !message || !signature || !sig_len) {
        return TAV_ERROR_NULL_POINTER;
    }
    
    if (keys->current_index >= keys->chain_length) {
        return TAV_ERROR_INVALID_DATA; /* Chain esgotada */
    }
    
    /* Calcula S_{n-i} onde i = current_index */
    uint16_t steps_to_reveal = keys->chain_length - keys->current_index - 1;
    
    uint8_t reveal[TAV_SIGN_HASH_SIZE];
    memcpy(reveal, keys->private_seed, TAV_SIGN_HASH_SIZE);
    
    for (uint16_t i = 0; i < steps_to_reveal; i++) {
        uint8_t next[TAV_SIGN_HASH_SIZE];
        tav_hash(reveal, TAV_SIGN_HASH_SIZE, next);
        memcpy(reveal, next, TAV_SIGN_HASH_SIZE);
    }
    
    /* MAC = hash(mensagem || reveal) */
    uint8_t* mac_input = (uint8_t*)malloc(msg_len + TAV_SIGN_HASH_SIZE);
    if (!mac_input) return TAV_ERROR_NULL_POINTER;
    
    memcpy(mac_input, message, msg_len);
    memcpy(mac_input + msg_len, reveal, TAV_SIGN_HASH_SIZE);
    
    uint8_t mac[TAV_SIGN_HASH_SIZE];
    tav_hash(mac_input, msg_len + TAV_SIGN_HASH_SIZE, mac);
    free(mac_input);
    
    /* Assinatura = [index (2 bytes)] [reveal (32 bytes)] [mac (32 bytes)] */
    signature[0] = (keys->current_index >> 8) & 0xFF;
    signature[1] = keys->current_index & 0xFF;
    memcpy(signature + 2, reveal, TAV_SIGN_HASH_SIZE);
    memcpy(signature + 2 + TAV_SIGN_HASH_SIZE, mac, TAV_SIGN_HASH_SIZE);
    
    *sig_len = 2 + TAV_SIGN_HASH_SIZE * 2;
    
    keys->current_index++;
    
    return TAV_OK;
}

tav_result_t tav_sign_chain_verify(const uint8_t* public_key,
                                   const uint8_t* message,
                                   size_t msg_len,
                                   const uint8_t* signature,
                                   size_t sig_len) {
    if (!public_key || !message || !signature) {
        return TAV_ERROR_NULL_POINTER;
    }
    
    if (sig_len < 2 + TAV_SIGN_HASH_SIZE * 2) {
        return TAV_ERROR_INVALID_DATA;
    }
    
    /* Extrai componentes */
    uint16_t index = ((uint16_t)signature[0] << 8) | signature[1];
    const uint8_t* reveal = signature + 2;
    const uint8_t* mac = signature + 2 + TAV_SIGN_HASH_SIZE;
    
    /* Verifica MAC */
    uint8_t* mac_input = (uint8_t*)malloc(msg_len + TAV_SIGN_HASH_SIZE);
    if (!mac_input) return TAV_ERROR_NULL_POINTER;
    
    memcpy(mac_input, message, msg_len);
    memcpy(mac_input + msg_len, reveal, TAV_SIGN_HASH_SIZE);
    
    uint8_t mac_expected[TAV_SIGN_HASH_SIZE];
    tav_hash(mac_input, msg_len + TAV_SIGN_HASH_SIZE, mac_expected);
    free(mac_input);
    
    if (!tav_constant_time_compare(mac, mac_expected, TAV_SIGN_HASH_SIZE)) {
        return TAV_ERROR_MAC_MISMATCH;
    }
    
    /* Verifica chain: hash reveal (index+1) vezes deve dar public_key */
    uint8_t current[TAV_SIGN_HASH_SIZE];
    memcpy(current, reveal, TAV_SIGN_HASH_SIZE);
    
    for (uint16_t i = 0; i <= index; i++) {
        uint8_t next[TAV_SIGN_HASH_SIZE];
        tav_hash(current, TAV_SIGN_HASH_SIZE, next);
        memcpy(current, next, TAV_SIGN_HASH_SIZE);
    }
    
    if (!tav_constant_time_compare(current, public_key, TAV_SIGN_HASH_SIZE)) {
        return TAV_ERROR_MAC_MISMATCH; /* Chain não confere */
    }
    
    return TAV_OK;
}

/* ============================================================================
 * OPÇÃO 2: COMMITMENT-REVEAL (Estado TAV)
 * ============================================================================
 * 
 * Conceito:
 *   - Chave pública = hash(master_entropy) = "commitment"
 *   - Para assinar: prova que conhece estado que gera o commitment
 *   - Usa MAC-Feistel do TAV para vincular mensagem ao estado
 * 
 * Assinar:
 *   1. Gera nonce aleatório
 *   2. Deriva estado_prova = f(master_entropy, tx_count)
 *   3. MAC = MAC_Feistel(mensagem, estado_prova)
 *   4. Prova = hash(estado_prova) para verificação sem revelar
 *   5. Assinatura = (nonce, prova, MAC, tx_count)
 * 
 * Verificar:
 *   1. Verifica que prova é consistente com commitment público
 *   2. Verifica MAC
 * 
 * Vantagem: Ilimitado, usa estado TAV dinâmico
 * Desvantagem: Mais complexo, requer sincronização de estado
 */

tav_result_t tav_sign_commit_keygen(tav_sign_commit_t* keys,
                                    const uint8_t* seed,
                                    size_t seed_len,
                                    tav_level_t level) {
    if (!keys || !seed) return TAV_ERROR_NULL_POINTER;
    
    /* Inicializa TAV interno */
    tav_result_t res = tav_init(&keys->tav, seed, seed_len, level);
    if (res != TAV_OK) return res;
    
    /* Chave pública = hash(master_entropy) */
    tav_hash(keys->tav.master_entropy, 
             keys->tav.master_entropy_size,
             keys->public_commitment);
    
    return TAV_OK;
}

tav_result_t tav_sign_commit_sign(tav_sign_commit_t* keys,
                                  const uint8_t* message,
                                  size_t msg_len,
                                  uint8_t* signature,
                                  size_t* sig_len) {
    if (!keys || !message || !signature || !sig_len) {
        return TAV_ERROR_NULL_POINTER;
    }
    
    if (!keys->tav.initialized) return TAV_ERROR_NOT_INITIALIZED;
    
    /* Gera estado de assinatura baseado no tx_count atual */
    uint64_t tx_at_sign = keys->tav.tx_count_global;
    
    /* Deriva chave de assinatura */
    uint8_t sign_key[TAV_MAX_KEY_BYTES];
    
    /* Estado de assinatura inclui tx_count para unicidade */
    uint8_t state_seed[40];
    memcpy(state_seed, keys->tav.master_entropy, 32);
    for (int i = 0; i < 8; i++) {
        state_seed[32 + i] = (tx_at_sign >> (56 - i * 8)) & 0xFF;
    }
    
    /* Hash do estado = prova */
    uint8_t state_proof[TAV_SIGN_HASH_SIZE];
    tav_hash(state_seed, 40, state_proof);
    
    /* Gera chave de assinatura derivada */
    tav_hash(state_proof, TAV_SIGN_HASH_SIZE, sign_key);
    
    /* MAC da mensagem */
    uint8_t mac[TAV_SIGN_HASH_SIZE];
    uint8_t* mac_input = (uint8_t*)malloc(msg_len + 8);
    if (!mac_input) return TAV_ERROR_NULL_POINTER;
    
    memcpy(mac_input, message, msg_len);
    for (int i = 0; i < 8; i++) {
        mac_input[msg_len + i] = (tx_at_sign >> (56 - i * 8)) & 0xFF;
    }
    
    tav_hash(mac_input, msg_len + 8, mac);
    
    /* Vincula ao estado */
    for (int i = 0; i < TAV_SIGN_HASH_SIZE; i++) {
        mac[i] ^= sign_key[i % keys->tav.config.key_bytes];
    }
    
    free(mac_input);
    
    /* Assinatura = [tx_count (8)] [state_proof (32)] [mac (32)] */
    for (int i = 0; i < 8; i++) {
        signature[i] = (tx_at_sign >> (56 - i * 8)) & 0xFF;
    }
    memcpy(signature + 8, state_proof, TAV_SIGN_HASH_SIZE);
    memcpy(signature + 8 + TAV_SIGN_HASH_SIZE, mac, TAV_SIGN_HASH_SIZE);
    
    *sig_len = 8 + TAV_SIGN_HASH_SIZE * 2;
    
    /* Avança estado */
    tav_tick(&keys->tav, 1);
    
    return TAV_OK;
}

tav_result_t tav_sign_commit_verify(const uint8_t* public_commitment,
                                    const uint8_t* message,
                                    size_t msg_len,
                                    const uint8_t* signature,
                                    size_t sig_len) {
    if (!public_commitment || !message || !signature) {
        return TAV_ERROR_NULL_POINTER;
    }
    
    if (sig_len < 8 + TAV_SIGN_HASH_SIZE * 2) {
        return TAV_ERROR_INVALID_DATA;
    }
    
    /* Extrai componentes */
    uint64_t tx_count = 0;
    for (int i = 0; i < 8; i++) {
        tx_count = (tx_count << 8) | signature[i];
    }
    const uint8_t* state_proof = signature + 8;
    const uint8_t* mac = signature + 8 + TAV_SIGN_HASH_SIZE;
    
    /* 
     * Verificação:
     * Não podemos verificar diretamente sem conhecer master_entropy.
     * Mas podemos verificar consistência:
     * 1. state_proof deve ser derivável do commitment (se conhecermos o esquema)
     * 2. MAC deve ser consistente
     * 
     * Na prática, isso requer que o verificador confie que:
     * - O assinante conhece o estado que gera o commitment
     * - A prova vincula a mensagem àquele estado
     * 
     * Para verificação sem confiança, precisaríamos de ZK-proof.
     * Aqui implementamos verificação "otimista" para demonstração.
     */
    
    /* Deriva chave esperada da prova */
    uint8_t sign_key[TAV_SIGN_HASH_SIZE];
    tav_hash(state_proof, TAV_SIGN_HASH_SIZE, sign_key);
    
    /* Recalcula MAC esperado */
    uint8_t* mac_input = (uint8_t*)malloc(msg_len + 8);
    if (!mac_input) return TAV_ERROR_NULL_POINTER;
    
    memcpy(mac_input, message, msg_len);
    for (int i = 0; i < 8; i++) {
        mac_input[msg_len + i] = (tx_count >> (56 - i * 8)) & 0xFF;
    }
    
    uint8_t mac_base[TAV_SIGN_HASH_SIZE];
    tav_hash(mac_input, msg_len + 8, mac_base);
    free(mac_input);
    
    /* Aplica XOR com sign_key (mesmo processo do assinante) */
    uint8_t mac_expected[TAV_SIGN_HASH_SIZE];
    for (int i = 0; i < TAV_SIGN_HASH_SIZE; i++) {
        mac_expected[i] = mac_base[i] ^ sign_key[i];
    }
    
    /* Verifica MAC */
    if (!tav_constant_time_compare(mac, mac_expected, TAV_SIGN_HASH_SIZE)) {
        return TAV_ERROR_MAC_MISMATCH;
    }
    
    /* 
     * Verificação do commitment:
     * Em um sistema real, precisaríamos de ZK-proof ou trusted setup.
     * Para esta demonstração, verificamos apenas consistência do MAC.
     */
    
    return TAV_OK;
}

/* ============================================================================
 * CERTIFICADOS
 * ============================================================================ */

tav_result_t tav_cert_create_self_signed(tav_cert_t* cert,
                                         const char* identity,
                                         tav_sign_chain_t* keys,
                                         uint64_t validity_seconds) {
    if (!cert || !identity || !keys) return TAV_ERROR_NULL_POINTER;
    
    memset(cert, 0, sizeof(tav_cert_t));
    
    /* Copia identidade */
    size_t id_len = strlen(identity);
    if (id_len >= TAV_CERT_MAX_IDENTITY) id_len = TAV_CERT_MAX_IDENTITY - 1;
    memcpy(cert->identity, identity, id_len);
    
    /* Copia chave pública */
    memcpy(cert->public_key, keys->public_key, TAV_SIGN_HASH_SIZE);
    
    /* Validade */
    cert->valid_from = (uint64_t)time(NULL);
    cert->valid_until = cert->valid_from + validity_seconds;
    
    /* Auto-assinatura: assina os dados do certificado */
    uint8_t cert_data[TAV_CERT_MAX_SIZE];
    size_t cert_data_len = 0;
    
    /* Serializa dados a assinar */
    memcpy(cert_data + cert_data_len, cert->identity, id_len);
    cert_data_len += id_len;
    memcpy(cert_data + cert_data_len, cert->public_key, TAV_SIGN_HASH_SIZE);
    cert_data_len += TAV_SIGN_HASH_SIZE;
    for (int i = 0; i < 8; i++) {
        cert_data[cert_data_len++] = (cert->valid_from >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 8; i++) {
        cert_data[cert_data_len++] = (cert->valid_until >> (56 - i * 8)) & 0xFF;
    }
    
    /* Assina */
    size_t sig_len;
    tav_result_t res = tav_sign_chain_sign(keys, cert_data, cert_data_len,
                                           cert->issuer_sig, &sig_len);
    if (res != TAV_OK) return res;
    
    cert->issuer_sig_len = (uint8_t)sig_len;
    
    return TAV_OK;
}

tav_result_t tav_cert_serialize(const tav_cert_t* cert,
                                uint8_t* buffer,
                                size_t* buf_len) {
    if (!cert || !buffer || !buf_len) return TAV_ERROR_NULL_POINTER;
    
    size_t id_len = strlen(cert->identity);
    size_t needed = 2 + id_len + TAV_SIGN_HASH_SIZE + 8 + 8 + 1 + cert->issuer_sig_len;
    
    if (*buf_len < needed) {
        *buf_len = needed;
        return TAV_ERROR_BUFFER_TOO_SMALL;
    }
    
    size_t pos = 0;
    
    /* Tamanho da identidade (2 bytes) */
    buffer[pos++] = (id_len >> 8) & 0xFF;
    buffer[pos++] = id_len & 0xFF;
    
    /* Identidade */
    memcpy(buffer + pos, cert->identity, id_len);
    pos += id_len;
    
    /* Chave pública */
    memcpy(buffer + pos, cert->public_key, TAV_SIGN_HASH_SIZE);
    pos += TAV_SIGN_HASH_SIZE;
    
    /* Validade */
    for (int i = 0; i < 8; i++) {
        buffer[pos++] = (cert->valid_from >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 8; i++) {
        buffer[pos++] = (cert->valid_until >> (56 - i * 8)) & 0xFF;
    }
    
    /* Assinatura */
    buffer[pos++] = cert->issuer_sig_len;
    memcpy(buffer + pos, cert->issuer_sig, cert->issuer_sig_len);
    pos += cert->issuer_sig_len;
    
    *buf_len = pos;
    return TAV_OK;
}

tav_result_t tav_cert_deserialize(tav_cert_t* cert,
                                  const uint8_t* buffer,
                                  size_t buf_len) {
    if (!cert || !buffer) return TAV_ERROR_NULL_POINTER;
    if (buf_len < 4) return TAV_ERROR_INVALID_DATA;
    
    memset(cert, 0, sizeof(tav_cert_t));
    
    size_t pos = 0;
    
    /* Tamanho da identidade */
    size_t id_len = ((size_t)buffer[pos] << 8) | buffer[pos + 1];
    pos += 2;
    
    if (id_len >= TAV_CERT_MAX_IDENTITY) return TAV_ERROR_INVALID_DATA;
    if (pos + id_len + TAV_SIGN_HASH_SIZE + 16 + 1 > buf_len) {
        return TAV_ERROR_INVALID_DATA;
    }
    
    /* Identidade */
    memcpy(cert->identity, buffer + pos, id_len);
    pos += id_len;
    
    /* Chave pública */
    memcpy(cert->public_key, buffer + pos, TAV_SIGN_HASH_SIZE);
    pos += TAV_SIGN_HASH_SIZE;
    
    /* Validade */
    cert->valid_from = 0;
    for (int i = 0; i < 8; i++) {
        cert->valid_from = (cert->valid_from << 8) | buffer[pos++];
    }
    cert->valid_until = 0;
    for (int i = 0; i < 8; i++) {
        cert->valid_until = (cert->valid_until << 8) | buffer[pos++];
    }
    
    /* Assinatura */
    cert->issuer_sig_len = buffer[pos++];
    if (pos + cert->issuer_sig_len > buf_len) return TAV_ERROR_INVALID_DATA;
    memcpy(cert->issuer_sig, buffer + pos, cert->issuer_sig_len);
    
    return TAV_OK;
}

tav_result_t tav_cert_verify(const tav_cert_t* cert,
                             const uint8_t* issuer_public_key) {
    if (!cert || !issuer_public_key) return TAV_ERROR_NULL_POINTER;
    
    /* Verifica validade temporal */
    uint64_t now = (uint64_t)time(NULL);
    if (now < cert->valid_from || now > cert->valid_until) {
        return TAV_ERROR_INVALID_DATA;
    }
    
    /* Reconstrói dados assinados */
    uint8_t cert_data[TAV_CERT_MAX_SIZE];
    size_t cert_data_len = 0;
    
    size_t id_len = strlen(cert->identity);
    memcpy(cert_data + cert_data_len, cert->identity, id_len);
    cert_data_len += id_len;
    memcpy(cert_data + cert_data_len, cert->public_key, TAV_SIGN_HASH_SIZE);
    cert_data_len += TAV_SIGN_HASH_SIZE;
    for (int i = 0; i < 8; i++) {
        cert_data[cert_data_len++] = (cert->valid_from >> (56 - i * 8)) & 0xFF;
    }
    for (int i = 0; i < 8; i++) {
        cert_data[cert_data_len++] = (cert->valid_until >> (56 - i * 8)) & 0xFF;
    }
    
    /* Verifica assinatura */
    return tav_sign_chain_verify(issuer_public_key, cert_data, cert_data_len,
                                 cert->issuer_sig, cert->issuer_sig_len);
}
