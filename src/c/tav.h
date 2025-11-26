/*
 * TAV CLOCK CRYPTOGRAPHY V9.1 - Implementação C
 * ==============================================
 * 
 * Sistema criptográfico baseado em física de processador.
 * Operações: apenas XOR, AND, OR, ROT (portas lógicas)
 * 
 * Licença: MIT
 * Data: Novembro 2025
 */

#ifndef TAV_CRYPTO_H
#define TAV_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTES
 * ============================================================================ */

#define TAV_VERSION_MAJOR 9
#define TAV_VERSION_MINOR 1

/* Níveis de segurança */
typedef enum {
    TAV_LEVEL_IOT        = 1,
    TAV_LEVEL_CONSUMER   = 2,
    TAV_LEVEL_ENTERPRISE = 3,
    TAV_LEVEL_MILITARY   = 4
} tav_level_t;

/* Tamanhos máximos */
#define TAV_MAX_KEY_BYTES      32
#define TAV_MAX_MAC_BYTES      16
#define TAV_MAX_NONCE_BYTES    16
#define TAV_MAX_MASTER_ENTROPY 128
#define TAV_POOL_SIZE          32
#define TAV_MAX_PRIMES         500

/* Constantes do Mixer Feistel */
#define TAV_CONST_SIZE 32

extern const uint8_t TAV_CONST_AND[TAV_CONST_SIZE];
extern const uint8_t TAV_CONST_OR[TAV_CONST_SIZE];

/* ============================================================================
 * ESTRUTURAS
 * ============================================================================ */

/* Configuração por nível */
typedef struct {
    uint8_t  master_entropy_size;
    uint8_t  key_bytes;
    uint8_t  mac_bytes;
    uint8_t  nonce_bytes;
    uint8_t  n_xor;
    uint8_t  n_rounds_mixer;
    uint8_t  n_rounds_mac;
    uint8_t  initial_boxes[6];
    uint8_t  n_initial_boxes;
} tav_config_t;

/* Caixa de primos */
typedef struct {
    const uint32_t* primes;
    uint16_t        count;
    uint16_t        index;
    bool            active;
} tav_prime_box_t;

/* Relógio transacional */
typedef struct {
    uint8_t  id;
    uint8_t  tick_prime;
    uint8_t  boxes[3];
    uint8_t  n_boxes;
    uint32_t tick_count;
    uint32_t tx_count;
    bool     active;
} tav_clock_t;

/* Mixer Feistel */
typedef struct {
    uint8_t  pool[TAV_POOL_SIZE];
    uint8_t  n_rounds;
    uint64_t counter;
} tav_mixer_t;

/* MAC Feistel */
typedef struct {
    uint8_t n_rounds;
} tav_mac_t;

/* Gerador de entropia */
typedef struct {
    tav_mixer_t mixer;
    uint8_t     n_xor;
    uint64_t    nonce_counter;
    uint8_t     work_index;
} tav_entropy_t;

/* Perfil de hardware */
typedef struct {
    float   bias_bits[8];
    float   timing_mean;
    float   timing_std;
} tav_hw_profile_t;

/* Contexto principal TAV */
typedef struct {
    tav_level_t      level;
    tav_config_t     config;
    tav_entropy_t    entropy;
    tav_mac_t        mac;
    tav_prime_box_t  boxes[6];
    tav_clock_t      clocks[4];
    tav_hw_profile_t baseline;
    
    uint8_t          master_entropy[TAV_MAX_MASTER_ENTROPY];
    uint8_t          master_entropy_size;
    
    uint64_t         tx_count_global;
    uint64_t         last_tx;
    
    bool             initialized;
} tav_ctx_t;

/* Resultado de operações */
typedef enum {
    TAV_OK = 0,
    TAV_ERROR_NULL_POINTER,
    TAV_ERROR_BUFFER_TOO_SMALL,
    TAV_ERROR_NOT_INITIALIZED,
    TAV_ERROR_MAC_MISMATCH,
    TAV_ERROR_INVALID_LEVEL,
    TAV_ERROR_INVALID_DATA
} tav_result_t;

/* ============================================================================
 * API PRINCIPAL
 * ============================================================================ */

/**
 * Inicializa contexto TAV com seed.
 * 
 * @param ctx    Contexto a inicializar
 * @param seed   Seed (string de palavras ou bytes)
 * @param seed_len Tamanho do seed
 * @param level  Nível de segurança
 * @return TAV_OK em sucesso
 */
tav_result_t tav_init(tav_ctx_t* ctx, 
                      const uint8_t* seed, 
                      size_t seed_len,
                      tav_level_t level);

/**
 * Limpa contexto (zera dados sensíveis).
 */
void tav_cleanup(tav_ctx_t* ctx);

/**
 * Encripta dados.
 * 
 * @param ctx        Contexto inicializado
 * @param plaintext  Dados a encriptar
 * @param pt_len     Tamanho dos dados
 * @param ciphertext Buffer de saída (deve ter pt_len + overhead bytes)
 * @param ct_len     [out] Tamanho do ciphertext gerado
 * @param auto_tick  Se true, avança estado após encriptar
 * @return TAV_OK em sucesso
 */
tav_result_t tav_encrypt(tav_ctx_t* ctx,
                         const uint8_t* plaintext,
                         size_t pt_len,
                         uint8_t* ciphertext,
                         size_t* ct_len,
                         bool auto_tick);

/**
 * Decripta dados.
 * 
 * @param ctx        Contexto inicializado
 * @param ciphertext Dados a decriptar
 * @param ct_len     Tamanho do ciphertext
 * @param plaintext  Buffer de saída
 * @param pt_len     [out] Tamanho do plaintext
 * @return TAV_OK em sucesso, TAV_ERROR_MAC_MISMATCH se adulterado
 */
tav_result_t tav_decrypt(tav_ctx_t* ctx,
                         const uint8_t* ciphertext,
                         size_t ct_len,
                         uint8_t* plaintext,
                         size_t* pt_len);

/**
 * Avança estado (tick).
 * 
 * @param ctx Contexto
 * @param n   Número de ticks
 */
void tav_tick(tav_ctx_t* ctx, uint32_t n);

/**
 * Calcula overhead do ciphertext para dado nível.
 */
size_t tav_overhead(tav_level_t level);

/**
 * Verifica se hardware ainda é o mesmo (anti-clone).
 * 
 * @param ctx         Contexto
 * @param similarity  [out] Similaridade 0.0-1.0
 * @return true se hardware parece o mesmo
 */
bool tav_verify_hardware(tav_ctx_t* ctx, float* similarity);

/* ============================================================================
 * API DE ASSINATURA (TAV-SIGN)
 * ============================================================================ */

/* Opção 1: Hash Chain (Lamport-style) */

#define TAV_SIGN_CHAIN_LENGTH 1024
#define TAV_SIGN_HASH_SIZE    32

typedef struct {
    uint8_t  public_key[TAV_SIGN_HASH_SIZE];  /* Ponta da chain */
    uint8_t  private_seed[TAV_SIGN_HASH_SIZE]; /* Seed secreto */
    uint16_t current_index;                    /* Próximo índice a usar */
    uint16_t chain_length;
} tav_sign_chain_t;

/**
 * Gera par de chaves baseado em hash chain.
 */
tav_result_t tav_sign_chain_keygen(tav_sign_chain_t* keys,
                                   const uint8_t* seed,
                                   size_t seed_len);

/**
 * Assina mensagem (consome um índice da chain).
 * 
 * @param keys      Chaves
 * @param message   Mensagem a assinar
 * @param msg_len   Tamanho da mensagem
 * @param signature Buffer de saída (TAV_SIGN_HASH_SIZE + 2 bytes)
 * @param sig_len   [out] Tamanho da assinatura
 */
tav_result_t tav_sign_chain_sign(tav_sign_chain_t* keys,
                                 const uint8_t* message,
                                 size_t msg_len,
                                 uint8_t* signature,
                                 size_t* sig_len);

/**
 * Verifica assinatura.
 */
tav_result_t tav_sign_chain_verify(const uint8_t* public_key,
                                   const uint8_t* message,
                                   size_t msg_len,
                                   const uint8_t* signature,
                                   size_t sig_len);

/* Opção 2: Commitment-Reveal (estado TAV) */

typedef struct {
    uint8_t  public_commitment[TAV_SIGN_HASH_SIZE]; /* hash(master_entropy) */
    tav_ctx_t tav;                                   /* Contexto TAV completo */
} tav_sign_commit_t;

/**
 * Gera par de chaves baseado em commitment.
 */
tav_result_t tav_sign_commit_keygen(tav_sign_commit_t* keys,
                                    const uint8_t* seed,
                                    size_t seed_len,
                                    tav_level_t level);

/**
 * Assina mensagem com estado atual + prova.
 */
tav_result_t tav_sign_commit_sign(tav_sign_commit_t* keys,
                                  const uint8_t* message,
                                  size_t msg_len,
                                  uint8_t* signature,
                                  size_t* sig_len);

/**
 * Verifica assinatura.
 */
tav_result_t tav_sign_commit_verify(const uint8_t* public_commitment,
                                    const uint8_t* message,
                                    size_t msg_len,
                                    const uint8_t* signature,
                                    size_t sig_len);

/* ============================================================================
 * API DE CERTIFICADOS (TAV-CERT)
 * ============================================================================ */

#define TAV_CERT_MAX_IDENTITY 256
#define TAV_CERT_MAX_SIZE     1024

typedef struct {
    char     identity[TAV_CERT_MAX_IDENTITY];
    uint8_t  public_key[TAV_SIGN_HASH_SIZE];
    uint64_t valid_from;    /* Unix timestamp */
    uint64_t valid_until;
    uint8_t  issuer_sig[TAV_SIGN_HASH_SIZE + 16];
    uint8_t  issuer_sig_len;
} tav_cert_t;

/**
 * Cria certificado auto-assinado.
 */
tav_result_t tav_cert_create_self_signed(tav_cert_t* cert,
                                         const char* identity,
                                         tav_sign_chain_t* keys,
                                         uint64_t validity_seconds);

/**
 * Serializa certificado para bytes.
 */
tav_result_t tav_cert_serialize(const tav_cert_t* cert,
                                uint8_t* buffer,
                                size_t* buf_len);

/**
 * Deserializa certificado de bytes.
 */
tav_result_t tav_cert_deserialize(tav_cert_t* cert,
                                  const uint8_t* buffer,
                                  size_t buf_len);

/**
 * Verifica certificado.
 */
tav_result_t tav_cert_verify(const tav_cert_t* cert,
                             const uint8_t* issuer_public_key);

/* ============================================================================
 * FUNÇÕES AUXILIARES
 * ============================================================================ */

/* Rotação de bits */
static inline uint8_t tav_rot_left(uint8_t byte, uint8_t n) {
    n = n & 7;
    return (byte << n) | (byte >> (8 - n));
}

static inline uint8_t tav_rot_right(uint8_t byte, uint8_t n) {
    n = n & 7;
    return (byte >> n) | (byte << (8 - n));
}

/* Hash simples baseado em Feistel (para assinaturas) */
void tav_hash(const uint8_t* data, size_t len, uint8_t* out);

/* Comparação constant-time */
bool tav_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);

/* Timer de alta resolução (platform-specific) */
uint64_t tav_get_time_ns(void);

#ifdef __cplusplus
}
#endif

#endif /* TAV_CRYPTO_H */
