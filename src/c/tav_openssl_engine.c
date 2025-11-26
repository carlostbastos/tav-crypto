/*
 * TAV Clock Cryptography v9.1
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/caterencio/tav-crypto
 */

/*
 * TAV OPENSSL ENGINE
 * ==================
 * 
 * Engine OpenSSL para integrar TAV como cipher provider.
 * 
 * Compilar:
 *   gcc -shared -fPIC -o libtav_engine.so tav_openssl_engine.c tav.c \
 *       -I/usr/include/openssl -lcrypto
 * 
 * Usar:
 *   openssl engine -t -c /path/to/libtav_engine.so
 *   openssl enc -engine libtav_engine.so -tav-consumer -in file.txt -out file.enc
 */

#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "tav.h"

/* ============================================================================
 * CONSTANTES
 * ============================================================================ */

static const char* ENGINE_ID = "tav";
static const char* ENGINE_NAME = "TAV Clock Cryptography Engine";

/* NIDs customizados para nossos ciphers */
static int tav_iot_nid = 0;
static int tav_consumer_nid = 0;
static int tav_enterprise_nid = 0;
static int tav_military_nid = 0;

/* ============================================================================
 * CONTEXTO DO CIPHER
 * ============================================================================ */

typedef struct {
    tav_ctx_t tav;
    int encrypting;
    unsigned char key[64];
    int key_len;
    unsigned char iv[16];
    int iv_len;
} tav_cipher_ctx_t;

/* ============================================================================
 * IMPLEMENTAÇÃO DO CIPHER
 * ============================================================================ */

static int tav_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc) {
    tav_cipher_ctx_t *tctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    
    if (!tctx) return 0;
    
    tctx->encrypting = enc;
    
    /* Determina nível baseado no cipher */
    int nid = EVP_CIPHER_CTX_nid(ctx);
    tav_level_t level;
    
    if (nid == tav_iot_nid) level = TAV_LEVEL_IOT;
    else if (nid == tav_consumer_nid) level = TAV_LEVEL_CONSUMER;
    else if (nid == tav_enterprise_nid) level = TAV_LEVEL_ENTERPRISE;
    else if (nid == tav_military_nid) level = TAV_LEVEL_MILITARY;
    else level = TAV_LEVEL_CONSUMER;
    
    /* Salva key/iv */
    if (key) {
        int key_size = EVP_CIPHER_CTX_key_length(ctx);
        memcpy(tctx->key, key, key_size);
        tctx->key_len = key_size;
    }
    
    if (iv) {
        int iv_size = EVP_CIPHER_CTX_iv_length(ctx);
        memcpy(tctx->iv, iv, iv_size);
        tctx->iv_len = iv_size;
    }
    
    /* Inicializa TAV */
    if (key) {
        /* Combina key + iv como seed */
        unsigned char seed[80];
        int seed_len = tctx->key_len;
        memcpy(seed, tctx->key, tctx->key_len);
        if (iv && tctx->iv_len > 0) {
            memcpy(seed + tctx->key_len, tctx->iv, tctx->iv_len);
            seed_len += tctx->iv_len;
        }
        
        tav_result_t res = tav_init(&tctx->tav, seed, seed_len, level);
        if (res != TAV_OK) return 0;
    }
    
    return 1;
}

static int tav_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                const unsigned char *in, size_t inl) {
    tav_cipher_ctx_t *tctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    
    if (!tctx || !tctx->tav.initialized) return 0;
    if (!in || inl == 0) return 0;
    
    if (tctx->encrypting) {
        size_t out_len;
        tav_result_t res = tav_encrypt(&tctx->tav, in, inl, out, &out_len, true);
        if (res != TAV_OK) return 0;
        return (int)out_len;
    } else {
        size_t out_len;
        tav_result_t res = tav_decrypt(&tctx->tav, in, inl, out, &out_len);
        if (res != TAV_OK) return 0;
        return (int)out_len;
    }
}

static int tav_cipher_cleanup(EVP_CIPHER_CTX *ctx) {
    tav_cipher_ctx_t *tctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (tctx) {
        tav_cleanup(&tctx->tav);
        OPENSSL_cleanse(tctx, sizeof(*tctx));
    }
    return 1;
}

static int tav_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
    switch (type) {
        case EVP_CTRL_INIT:
            return 1;
        default:
            return -1;
    }
}

/* ============================================================================
 * CRIAÇÃO DOS CIPHERS
 * ============================================================================ */

static EVP_CIPHER *tav_iot_cipher = NULL;
static EVP_CIPHER *tav_consumer_cipher = NULL;
static EVP_CIPHER *tav_enterprise_cipher = NULL;
static EVP_CIPHER *tav_military_cipher = NULL;

static EVP_CIPHER* create_tav_cipher(int nid, int key_len, int iv_len, int block_size) {
    EVP_CIPHER *cipher = EVP_CIPHER_meth_new(nid, block_size, key_len);
    
    if (!cipher) return NULL;
    
    EVP_CIPHER_meth_set_iv_length(cipher, iv_len);
    EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_STREAM_CIPHER | EVP_CIPH_VARIABLE_LENGTH);
    EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(tav_cipher_ctx_t));
    EVP_CIPHER_meth_set_init(cipher, tav_cipher_init);
    EVP_CIPHER_meth_set_do_cipher(cipher, tav_cipher_do_cipher);
    EVP_CIPHER_meth_set_cleanup(cipher, tav_cipher_cleanup);
    EVP_CIPHER_meth_set_ctrl(cipher, tav_cipher_ctrl);
    
    return cipher;
}

static void destroy_ciphers(void) {
    EVP_CIPHER_meth_free(tav_iot_cipher);
    EVP_CIPHER_meth_free(tav_consumer_cipher);
    EVP_CIPHER_meth_free(tav_enterprise_cipher);
    EVP_CIPHER_meth_free(tav_military_cipher);
    
    tav_iot_cipher = NULL;
    tav_consumer_cipher = NULL;
    tav_enterprise_cipher = NULL;
    tav_military_cipher = NULL;
}

/* ============================================================================
 * ENGINE CALLBACKS
 * ============================================================================ */

static int tav_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                       const int **nids, int nid) {
    static int cipher_nids[5] = {0, 0, 0, 0, 0};
    static int nids_initialized = 0;
    
    if (!nids_initialized) {
        /* Registra NIDs customizados */
        tav_iot_nid = OBJ_create("1.3.6.1.4.1.99999.1.1", "TAV-IOT", "TAV IoT Cipher");
        tav_consumer_nid = OBJ_create("1.3.6.1.4.1.99999.1.2", "TAV-CONSUMER", "TAV Consumer Cipher");
        tav_enterprise_nid = OBJ_create("1.3.6.1.4.1.99999.1.3", "TAV-ENTERPRISE", "TAV Enterprise Cipher");
        tav_military_nid = OBJ_create("1.3.6.1.4.1.99999.1.4", "TAV-MILITARY", "TAV Military Cipher");
        
        cipher_nids[0] = tav_iot_nid;
        cipher_nids[1] = tav_consumer_nid;
        cipher_nids[2] = tav_enterprise_nid;
        cipher_nids[3] = tav_military_nid;
        cipher_nids[4] = 0;
        
        /* Cria ciphers */
        tav_iot_cipher = create_tav_cipher(tav_iot_nid, 16, 8, 1);
        tav_consumer_cipher = create_tav_cipher(tav_consumer_nid, 24, 12, 1);
        tav_enterprise_cipher = create_tav_cipher(tav_enterprise_nid, 32, 16, 1);
        tav_military_cipher = create_tav_cipher(tav_military_nid, 32, 16, 1);
        
        nids_initialized = 1;
    }
    
    if (!cipher) {
        *nids = cipher_nids;
        return 4;
    }
    
    if (nid == tav_iot_nid) *cipher = tav_iot_cipher;
    else if (nid == tav_consumer_nid) *cipher = tav_consumer_cipher;
    else if (nid == tav_enterprise_nid) *cipher = tav_enterprise_cipher;
    else if (nid == tav_military_nid) *cipher = tav_military_cipher;
    else {
        *cipher = NULL;
        return 0;
    }
    
    return 1;
}

static int tav_engine_init(ENGINE *e) {
    return 1;
}

static int tav_engine_finish(ENGINE *e) {
    destroy_ciphers();
    return 1;
}

static int tav_engine_destroy(ENGINE *e) {
    destroy_ciphers();
    return 1;
}

/* ============================================================================
 * BIND ENGINE
 * ============================================================================ */

static int bind_helper(ENGINE *e) {
    if (!ENGINE_set_id(e, ENGINE_ID) ||
        !ENGINE_set_name(e, ENGINE_NAME) ||
        !ENGINE_set_init_function(e, tav_engine_init) ||
        !ENGINE_set_finish_function(e, tav_engine_finish) ||
        !ENGINE_set_destroy_function(e, tav_engine_destroy) ||
        !ENGINE_set_ciphers(e, tav_ciphers)) {
        return 0;
    }
    
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()

/* ============================================================================
 * STANDALONE API (para uso sem OpenSSL)
 * ============================================================================ */

#ifndef OPENSSL_NO_DYNAMIC_ENGINE

/* Permite uso como biblioteca standalone */
__attribute__((constructor))
static void tav_engine_constructor(void) {
    /* Auto-registra se carregado como shared library */
}

__attribute__((destructor))
static void tav_engine_destructor(void) {
    destroy_ciphers();
}

#endif /* OPENSSL_NO_DYNAMIC_ENGINE */
