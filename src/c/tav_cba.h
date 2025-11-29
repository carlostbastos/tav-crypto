/*
 * TAV CAPABILITY-BASED AUTHENTICATION (CBA) V1.0 - C Implementation
 * ==================================================================
 * 
 * Protocolo híbrido combinando:
 * 1. Hash-Chain: Identidade forte (uso limitado)
 * 2. Commitment-Reveal: Sessões ilimitadas
 * 3. Capabilities: Controle de acesso granular
 * 
 * Características:
 * - Zero alocação dinâmica em operações críticas
 * - Constant-time comparisons
 * - Tamanhos fixos em compile-time
 * 
 * Licença: AGPL-3.0 | Uso comercial gratuito até maio de 2027
 * Data: Novembro 2025
 */

#ifndef TAV_CBA_H
#define TAV_CBA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTES
 * ============================================================================ */

#define CBA_VERSION             "1.0"
#define CBA_HASH_SIZE           32
#define CBA_MAC_SIZE            16
#define CBA_ID_SIZE             16
#define CBA_NONCE_SIZE          16
#define CBA_SESSION_ENTROPY     64
#define CBA_MAX_CHAIN_LENGTH    1000
#define CBA_MAX_RESOURCES       16
#define CBA_MAX_RESOURCE_LEN    64
#define CBA_MAX_OPERATION_LEN   16
#define CBA_SIGNATURE_SIZE      66  /* 2 + 32 + 32 */
#define CBA_MAX_DELEGATION      8

/* Tamanhos de estruturas serializadas */
#define CBA_CAPABILITY_MAX_SIZE 512
#define CBA_PROOF_MAX_SIZE      256

/* ============================================================================
 * PERMISSÕES (FLAGS)
 * ============================================================================ */

typedef enum {
    CBA_PERM_NONE       = 0,
    CBA_PERM_READ       = (1 << 0),
    CBA_PERM_WRITE      = (1 << 1),
    CBA_PERM_DELETE     = (1 << 2),
    CBA_PERM_ENCRYPT    = (1 << 3),
    CBA_PERM_DECRYPT    = (1 << 4),
    CBA_PERM_SIGN       = (1 << 5),
    CBA_PERM_VERIFY     = (1 << 6),
    CBA_PERM_DELEGATE   = (1 << 7),
    CBA_PERM_REVOKE     = (1 << 8),
    CBA_PERM_ADMIN      = (1 << 9),
    
    /* Combinações comuns */
    CBA_PERM_READ_ONLY   = CBA_PERM_READ | CBA_PERM_VERIFY,
    CBA_PERM_READ_WRITE  = CBA_PERM_READ | CBA_PERM_WRITE | CBA_PERM_ENCRYPT | CBA_PERM_DECRYPT,
    CBA_PERM_FULL_CRYPTO = CBA_PERM_ENCRYPT | CBA_PERM_DECRYPT | CBA_PERM_SIGN | CBA_PERM_VERIFY,
    CBA_PERM_DELEGATOR   = CBA_PERM_READ | CBA_PERM_WRITE | CBA_PERM_DELEGATE,
    CBA_PERM_FULL_ACCESS = 0x3FF
} cba_permission_t;

/* ============================================================================
 * CÓDIGOS DE RESULTADO
 * ============================================================================ */

typedef enum {
    CBA_OK = 0,
    CBA_ERROR_NULL_POINTER = -1,
    CBA_ERROR_INVALID_DATA = -2,
    CBA_ERROR_CHAIN_EXHAUSTED = -3,
    CBA_ERROR_SESSION_EXPIRED = -4,
    CBA_ERROR_CAPABILITY_EXPIRED = -5,
    CBA_ERROR_CAPABILITY_REVOKED = -6,
    CBA_ERROR_PERMISSION_DENIED = -7,
    CBA_ERROR_RESOURCE_DENIED = -8,
    CBA_ERROR_MAX_USES_EXCEEDED = -9,
    CBA_ERROR_MAX_DELEGATION = -10,
    CBA_ERROR_SIGNATURE_INVALID = -11,
    CBA_ERROR_PROOF_EXPIRED = -12,
    CBA_ERROR_PROOF_INVALID = -13,
    CBA_ERROR_BUFFER_TOO_SMALL = -14
} cba_result_t;

/* ============================================================================
 * ESTRUTURAS
 * ============================================================================ */

/* Chave de identidade (Hash-Chain) */
typedef struct {
    uint8_t public_key[CBA_HASH_SIZE];
    uint8_t private_seed[CBA_HASH_SIZE];
    uint16_t chain_length;
    uint16_t current_index;
    /* Cache opcional (pode ser NULL para economizar RAM) */
    uint8_t* chain_cache;
    uint16_t cache_size;
} cba_identity_t;

/* Chave de sessão (Commitment-Reveal) */
typedef struct {
    uint8_t commitment[CBA_HASH_SIZE];
    uint8_t session_id[CBA_ID_SIZE];
    uint8_t master_entropy[CBA_SESSION_ENTROPY];
    uint64_t created_at;
    uint64_t expires_at;
    uint32_t tx_count;
    bool active;
} cba_session_t;

/* Recurso */
typedef struct {
    char id[CBA_MAX_RESOURCE_LEN];
    uint8_t id_len;
} cba_resource_t;

/* Capability */
typedef struct {
    uint8_t id[CBA_ID_SIZE];
    uint8_t issuer_id[CBA_ID_SIZE];
    uint8_t holder_id[CBA_ID_SIZE];
    
    uint32_t permissions;
    cba_resource_t resources[CBA_MAX_RESOURCES];
    uint8_t n_resources;
    
    uint64_t created_at;
    uint64_t expires_at;
    int32_t max_uses;           /* -1 = ilimitado */
    uint32_t uses_count;
    
    uint8_t delegation_depth;
    uint8_t max_delegation_depth;
    uint8_t parent_id[CBA_ID_SIZE];
    bool has_parent;
    
    uint8_t signature[CBA_SIGNATURE_SIZE];
    uint8_t signature_len;
    
    bool revoked;
    uint64_t revoked_at;
} cba_capability_t;

/* Prova CBA */
typedef struct {
    uint8_t capability_id[CBA_ID_SIZE];
    uint8_t session_proof[CBA_HASH_SIZE];
    
    char operation[CBA_MAX_OPERATION_LEN];
    uint8_t operation_len;
    char resource_id[CBA_MAX_RESOURCE_LEN];
    uint8_t resource_id_len;
    
    uint64_t timestamp;
    uint8_t nonce[CBA_NONCE_SIZE];
    uint8_t proof_signature[CBA_HASH_SIZE];
    
    /* Prova de identidade (opcional) */
    bool has_identity_proof;
    uint8_t identity_proof[CBA_SIGNATURE_SIZE];
    uint16_t chain_index;
} cba_proof_t;

/* Lista de revogação (simples, tamanho fixo) */
#define CBA_REVOCATION_LIST_SIZE 64

typedef struct {
    uint8_t ids[CBA_REVOCATION_LIST_SIZE][CBA_ID_SIZE];
    uint16_t count;
} cba_revocation_list_t;

/* Contexto principal CBA */
typedef struct {
    cba_identity_t identity;
    cba_session_t session;
    cba_revocation_list_t revocation_list;
    uint32_t id_counter;
    bool initialized;
} cba_ctx_t;

/* ============================================================================
 * CONSTANTES CRIPTOGRÁFICAS
 * ============================================================================ */

extern const uint8_t CBA_CONST_AND[32];
extern const uint8_t CBA_CONST_OR[32];

/* ============================================================================
 * FUNÇÕES AUXILIARES
 * ============================================================================ */

/* Tempo atual (implemente para sua plataforma) */
uint64_t cba_get_time(void);

/* Bytes aleatórios (implemente para sua plataforma) */
void cba_get_random(uint8_t* out, size_t len);

/* Rotação à esquerda */
static inline uint8_t cba_rot_left(uint8_t b, uint8_t n) {
    n &= 7;
    return (uint8_t)((b << n) | (b >> (8 - n)));
}

/* Comparação em tempo constante */
bool cba_constant_compare(const uint8_t* a, const uint8_t* b, size_t len);

/* ============================================================================
 * FUNÇÕES DE HASH E MAC
 * ============================================================================ */

/**
 * Hash TAV (Feistel-based)
 */
void cba_hash(const uint8_t* data, size_t len, uint8_t* out, size_t out_len);

/**
 * MAC TAV
 */
void cba_mac(const uint8_t* key, size_t key_len,
             const uint8_t* data, size_t data_len,
             uint8_t* out, size_t out_len);

/* ============================================================================
 * API PRINCIPAL
 * ============================================================================ */

/**
 * Inicializa contexto CBA
 * 
 * @param ctx Contexto a inicializar
 * @param seed Seed secreta
 * @param seed_len Tamanho da seed
 * @param chain_length Tamanho da cadeia de identidade
 * @return CBA_OK em sucesso
 */
cba_result_t cba_init(cba_ctx_t* ctx, 
                      const uint8_t* seed, size_t seed_len,
                      uint16_t chain_length);

/**
 * Limpa contexto (zera dados sensíveis)
 */
void cba_cleanup(cba_ctx_t* ctx);

/* ============================================================================
 * IDENTIDADE (Hash-Chain)
 * ============================================================================ */

/**
 * Assina dados usando cadeia de identidade
 * ATENÇÃO: Consome uma posição da cadeia!
 * 
 * @param ctx Contexto
 * @param data Dados a assinar
 * @param data_len Tamanho dos dados
 * @param signature Buffer para assinatura (mín 66 bytes)
 * @param sig_len Tamanho da assinatura gerada
 * @param index_used Índice usado (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_identity_sign(cba_ctx_t* ctx,
                               const uint8_t* data, size_t data_len,
                               uint8_t* signature, size_t* sig_len,
                               uint16_t* index_used);

/**
 * Verifica assinatura de identidade
 * 
 * @param public_key Chave pública do assinante
 * @param data Dados assinados
 * @param data_len Tamanho dos dados
 * @param signature Assinatura
 * @param sig_len Tamanho da assinatura
 * @return CBA_OK se válida
 */
cba_result_t cba_identity_verify(const uint8_t* public_key,
                                 const uint8_t* data, size_t data_len,
                                 const uint8_t* signature, size_t sig_len);

/**
 * Retorna assinaturas restantes
 */
uint16_t cba_identity_remaining(const cba_ctx_t* ctx);

/* ============================================================================
 * SESSÃO (Commitment-Reveal)
 * ============================================================================ */

/**
 * Cria nova sessão
 * 
 * @param ctx Contexto
 * @param duration_seconds Duração em segundos
 * @return CBA_OK em sucesso
 */
cba_result_t cba_session_create(cba_ctx_t* ctx, uint32_t duration_seconds);

/**
 * Gera prova de sessão
 * 
 * @param ctx Contexto
 * @param proof Buffer para prova (32 bytes)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_session_proof(cba_ctx_t* ctx, uint8_t* proof);

/**
 * Verifica se sessão está ativa
 */
bool cba_session_is_active(const cba_ctx_t* ctx);

/* ============================================================================
 * CAPABILITIES
 * ============================================================================ */

/**
 * Emite nova capability
 * 
 * @param ctx Contexto do emissor
 * @param holder_public_key Chave pública do destinatário
 * @param permissions Permissões concedidas
 * @param resources Array de IDs de recursos
 * @param n_resources Número de recursos
 * @param duration_seconds Validade
 * @param max_uses Máximo de usos (-1 = ilimitado)
 * @param max_delegation Níveis de delegação permitidos
 * @param cap Capability gerada (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_capability_issue(cba_ctx_t* ctx,
                                  const uint8_t* holder_public_key,
                                  uint32_t permissions,
                                  const char** resources, uint8_t n_resources,
                                  uint32_t duration_seconds,
                                  int32_t max_uses,
                                  uint8_t max_delegation,
                                  cba_capability_t* cap);

/**
 * Delega capability existente (com restrições)
 * 
 * @param ctx Contexto do delegante
 * @param parent Capability parent
 * @param new_holder_public_key Chave pública do novo detentor
 * @param permissions Permissões (serão intersectadas com parent)
 * @param resources Recursos (serão intersectados com parent)
 * @param n_resources Número de recursos
 * @param duration_seconds Duração (limitada pelo parent)
 * @param delegated Capability delegada (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_capability_delegate(cba_ctx_t* ctx,
                                     const cba_capability_t* parent,
                                     const uint8_t* new_holder_public_key,
                                     uint32_t permissions,
                                     const char** resources, uint8_t n_resources,
                                     uint32_t duration_seconds,
                                     cba_capability_t* delegated);

/**
 * Revoga capability
 */
cba_result_t cba_capability_revoke(cba_ctx_t* ctx, const uint8_t* cap_id);

/**
 * Verifica se capability está revogada
 */
bool cba_capability_is_revoked(const cba_ctx_t* ctx, const uint8_t* cap_id);

/**
 * Verifica se recurso está na capability
 */
bool cba_capability_has_resource(const cba_capability_t* cap, const char* resource_id);

/**
 * Verifica se permissão está na capability
 */
bool cba_capability_has_permission(const cba_capability_t* cap, cba_permission_t perm);

/* ============================================================================
 * PROVA CBA
 * ============================================================================ */

/**
 * Gera prova de autenticação CBA
 * 
 * @param ctx Contexto
 * @param cap Capability sendo usada
 * @param operation Operação (ex: "READ", "WRITE")
 * @param resource_id ID do recurso
 * @param include_identity Se deve incluir prova de identidade
 * @param proof Prova gerada (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_proof_generate(cba_ctx_t* ctx,
                                cba_capability_t* cap,
                                const char* operation,
                                const char* resource_id,
                                bool include_identity,
                                cba_proof_t* proof);

/**
 * Verifica prova CBA
 * 
 * @param ctx Contexto (para lista de revogação)
 * @param proof Prova a verificar
 * @param cap Capability referenciada
 * @param issuer_public_key Chave pública do emissor da capability
 * @param max_age_seconds Idade máxima aceita
 * @return CBA_OK se válida
 */
cba_result_t cba_proof_verify(const cba_ctx_t* ctx,
                              const cba_proof_t* proof,
                              const cba_capability_t* cap,
                              const uint8_t* issuer_public_key,
                              uint32_t max_age_seconds);

/* ============================================================================
 * SERIALIZAÇÃO
 * ============================================================================ */

/**
 * Serializa capability para transmissão
 * 
 * @param cap Capability
 * @param buffer Buffer de saída
 * @param buffer_size Tamanho do buffer
 * @param out_len Tamanho serializado (output)
 * @return CBA_OK em sucesso
 */
cba_result_t cba_capability_serialize(const cba_capability_t* cap,
                                      uint8_t* buffer, size_t buffer_size,
                                      size_t* out_len);

/**
 * Deserializa capability
 */
cba_result_t cba_capability_deserialize(const uint8_t* buffer, size_t len,
                                        cba_capability_t* cap);

/**
 * Serializa prova
 */
cba_result_t cba_proof_serialize(const cba_proof_t* proof,
                                 uint8_t* buffer, size_t buffer_size,
                                 size_t* out_len);

/**
 * Deserializa prova
 */
cba_result_t cba_proof_deserialize(const uint8_t* buffer, size_t len,
                                   cba_proof_t* proof);

/* ============================================================================
 * UTILIDADES
 * ============================================================================ */

/**
 * Converte string de operação para permissão
 */
cba_permission_t cba_operation_to_permission(const char* operation);

/**
 * Retorna string descritiva do erro
 */
const char* cba_error_string(cba_result_t error);

#ifdef __cplusplus
}
#endif

#endif /* TAV_CBA_H */
