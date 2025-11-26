/*
 * TAV INTEROP TEST - Validador C
 * ===============================
 * 
 * Lê vetores JSON e valida com implementação C.
 * 
 * Compilar: gcc -O2 -I../../c interop_validate_c.c ../../c/tav.c ../../c/tav_sign.c -o validate_c -lm
 * Executar: ./validate_c vectors_from_js.json
 * 
 * NOTA: Este é um parser JSON simplificado. Para produção, use uma biblioteca JSON real.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tav.h"

/* ============================================================================
 * JSON PARSER SIMPLIFICADO
 * ============================================================================ */

#define MAX_LINE 4096
#define MAX_HEX 2048

static int passed = 0;
static int failed = 0;

/* Converte hex string para bytes */
static int hex_to_bytes(const char* hex, uint8_t* out, size_t max_len) {
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    
    if (byte_len > max_len) byte_len = max_len;
    
    for (size_t i = 0; i < byte_len; i++) {
        char byte_str[3] = {hex[i*2], hex[i*2+1], 0};
        out[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    
    return byte_len;
}

/* Converte bytes para hex string */
static void bytes_to_hex(const uint8_t* bytes, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i*2, "%02x", bytes[i]);
    }
    out[len*2] = '\0';
}

/* Extrai valor de string JSON: "key": "value" */
static int extract_string(const char* json, const char* key, char* out, size_t max_len) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    
    char* pos = strstr(json, pattern);
    if (!pos) return 0;
    
    pos += strlen(pattern);
    while (*pos && isspace(*pos)) pos++;
    
    if (*pos != '"') return 0;
    pos++;
    
    size_t i = 0;
    while (*pos && *pos != '"' && i < max_len - 1) {
        out[i++] = *pos++;
    }
    out[i] = '\0';
    
    return 1;
}

/* Extrai valor inteiro JSON: "key": 123 */
static int extract_int(const char* json, const char* key, int* out) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    
    char* pos = strstr(json, pattern);
    if (!pos) return 0;
    
    pos += strlen(pattern);
    while (*pos && isspace(*pos)) pos++;
    
    *out = atoi(pos);
    return 1;
}

/* Extrai valor boolean JSON: "key": true/false */
static int extract_bool(const char* json, const char* key, int* out) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    
    char* pos = strstr(json, pattern);
    if (!pos) return 0;
    
    pos += strlen(pattern);
    while (*pos && isspace(*pos)) pos++;
    
    *out = (strncmp(pos, "true", 4) == 0) ? 1 : 0;
    return 1;
}

/* ============================================================================
 * TESTES
 * ============================================================================ */

static void test(const char* name, int condition, const char* details) {
    if (condition) {
        printf("  ✅ %s\n", name);
        passed++;
    } else {
        printf("  ❌ %s\n", name);
        if (details && strlen(details) > 0) {
            printf("     %s\n", details);
        }
        failed++;
    }
}

/* Testa um vetor de hash */
static void test_hash_vector(const char* block) {
    char name[256] = "";
    char input_hex[MAX_HEX] = "";
    char input_utf8[MAX_HEX] = "";
    char expected_hex[256] = "";
    
    extract_string(block, "name", name, sizeof(name));
    extract_string(block, "input_hex", input_hex, sizeof(input_hex));
    extract_string(block, "input_utf8", input_utf8, sizeof(input_utf8));
    extract_string(block, "output_hex", expected_hex, sizeof(expected_hex));
    
    /* Prepara input */
    uint8_t input[MAX_HEX];
    size_t input_len;
    
    if (strlen(input_hex) > 0) {
        input_len = hex_to_bytes(input_hex, input, sizeof(input));
    } else {
        input_len = strlen(input_utf8);
        memcpy(input, input_utf8, input_len);
    }
    
    /* Calcula hash */
    uint8_t result[32];
    tav_hash(input, input_len, result);
    
    char result_hex[65];
    bytes_to_hex(result, 32, result_hex);
    
    /* Compara */
    int match = (strcmp(result_hex, expected_hex) == 0);
    
    char details[512] = "";
    if (!match) {
        snprintf(details, sizeof(details), "Expected: %s\nGot:      %s", expected_hex, result_hex);
    }
    
    char test_name[512];
    snprintf(test_name, sizeof(test_name), "hash: %s", name);
    test(test_name, match, details);
}

/* Testa um vetor de assinatura */
static void test_sign_chain_vector(const char* block) {
    char name[256] = "";
    char seed_utf8[256] = "";
    char message_utf8[1024] = "";
    char expected_pubkey[256] = "";
    char expected_privseed[256] = "";
    char expected_sig[512] = "";
    int chain_length = 0;
    int sig_len = 0;
    
    extract_string(block, "name", name, sizeof(name));
    extract_string(block, "seed_utf8", seed_utf8, sizeof(seed_utf8));
    extract_string(block, "message_utf8", message_utf8, sizeof(message_utf8));
    extract_string(block, "public_key_hex", expected_pubkey, sizeof(expected_pubkey));
    extract_string(block, "private_seed_hex", expected_privseed, sizeof(expected_privseed));
    extract_string(block, "signature_hex", expected_sig, sizeof(expected_sig));
    extract_int(block, "chain_length", &chain_length);
    extract_int(block, "signature_len", &sig_len);
    
    /* Gera chaves */
    tav_sign_chain_t keys;
    tav_sign_chain_keygen(&keys, (uint8_t*)seed_utf8, strlen(seed_utf8));
    
    /* Ajusta chain_length */
    keys.chain_length = chain_length;
    keys.current_index = 0;
    
    /* Regenera public key */
    uint8_t current[32];
    memcpy(current, keys.private_seed, 32);
    for (int i = 0; i < chain_length; i++) {
        uint8_t next[32];
        tav_hash(current, 32, next);
        memcpy(current, next, 32);
    }
    memcpy(keys.public_key, current, 32);
    
    /* Compara private seed */
    char privseed_hex[65];
    bytes_to_hex(keys.private_seed, 32, privseed_hex);
    
    int privseed_match = (strcmp(privseed_hex, expected_privseed) == 0);
    char test_name[512];
    snprintf(test_name, sizeof(test_name), "sign_chain: %s (priv_seed)", name);
    
    char details[512] = "";
    if (!privseed_match) {
        snprintf(details, sizeof(details), "Expected: %s\nGot:      %s", expected_privseed, privseed_hex);
    }
    test(test_name, privseed_match, details);
    
    /* Compara public key */
    char pubkey_hex[65];
    bytes_to_hex(keys.public_key, 32, pubkey_hex);
    
    int pubkey_match = (strcmp(pubkey_hex, expected_pubkey) == 0);
    snprintf(test_name, sizeof(test_name), "sign_chain: %s (pubkey)", name);
    
    if (!pubkey_match) {
        snprintf(details, sizeof(details), "Expected: %s\nGot:      %s", expected_pubkey, pubkey_hex);
    } else {
        details[0] = '\0';
    }
    test(test_name, pubkey_match, details);
    
    /* Gera assinatura */
    uint8_t sig[128];
    size_t actual_sig_len;
    tav_sign_chain_sign(&keys, (uint8_t*)message_utf8, strlen(message_utf8), sig, &actual_sig_len);
    
    char sig_hex[257];
    bytes_to_hex(sig, actual_sig_len, sig_hex);
    
    /* Compara assinatura */
    int sig_match = (strcmp(sig_hex, expected_sig) == 0);
    snprintf(test_name, sizeof(test_name), "sign_chain: %s (sig_match)", name);
    
    if (!sig_match) {
        snprintf(details, sizeof(details), "Expected: %s\nGot:      %s", expected_sig, sig_hex);
    } else {
        details[0] = '\0';
    }
    test(test_name, sig_match, details);
    
    /* Verifica assinatura da outra implementação */
    uint8_t other_sig[256];
    size_t other_sig_len = hex_to_bytes(expected_sig, other_sig, sizeof(other_sig));
    
    uint8_t pubkey_bytes[32];
    hex_to_bytes(expected_pubkey, pubkey_bytes, 32);
    
    tav_result_t verify_res = tav_sign_chain_verify(pubkey_bytes, 
                                                     (uint8_t*)message_utf8, 
                                                     strlen(message_utf8),
                                                     other_sig, other_sig_len);
    
    snprintf(test_name, sizeof(test_name), "sign_chain: %s (verify_other_sig)", name);
    test(test_name, verify_res == TAV_OK, "");
}

/* ============================================================================
 * PARSER DE ARQUIVO
 * ============================================================================ */

static void process_file(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s\n", filename);
        exit(1);
    }
    
    /* Lê arquivo inteiro */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* content = malloc(size + 1);
    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);
    
    /* Extrai info do gerador */
    char generator[64] = "";
    char version[32] = "";
    extract_string(content, "generator", generator, sizeof(generator));
    extract_string(content, "version", version, sizeof(version));
    
    printf("Generator: %s\n", generator);
    printf("Version: %s\n", version);
    
    /* Processa hash_tests */
    printf("\n🔹 HASH TESTS\n");
    char* pos = strstr(content, "\"hash_tests\"");
    if (pos) {
        char* start = strchr(pos, '[');
        if (start) {
            int depth = 0;
            char* block_start = NULL;
            
            for (char* p = start; *p; p++) {
                if (*p == '{') {
                    if (depth == 0) block_start = p;
                    depth++;
                } else if (*p == '}') {
                    depth--;
                    if (depth == 0 && block_start) {
                        size_t block_len = p - block_start + 1;
                        char* block = malloc(block_len + 1);
                        memcpy(block, block_start, block_len);
                        block[block_len] = '\0';
                        
                        test_hash_vector(block);
                        free(block);
                        block_start = NULL;
                    }
                } else if (*p == ']' && depth == 0) {
                    break;
                }
            }
        }
    }
    
    /* Processa sign_chain_tests */
    printf("\n🔹 SIGN CHAIN TESTS\n");
    pos = strstr(content, "\"sign_chain_tests\"");
    if (pos) {
        char* start = strchr(pos, '[');
        if (start) {
            int depth = 0;
            char* block_start = NULL;
            
            for (char* p = start; *p; p++) {
                if (*p == '{') {
                    if (depth == 0) block_start = p;
                    depth++;
                } else if (*p == '}') {
                    depth--;
                    if (depth == 0 && block_start) {
                        size_t block_len = p - block_start + 1;
                        char* block = malloc(block_len + 1);
                        memcpy(block, block_start, block_len);
                        block[block_len] = '\0';
                        
                        test_sign_chain_vector(block);
                        free(block);
                        block_start = NULL;
                    }
                } else if (*p == ']' && depth == 0) {
                    break;
                }
            }
        }
    }
    
    free(content);
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("TAV INTEROP TEST - C Validator\n");
        printf("\nUsage: %s <vectors.json>\n", argv[0]);
        printf("\nGenerate vectors first:\n");
        printf("  node interop_generate_js.js > vectors_from_js.json\n");
        printf("  %s vectors_from_js.json\n", argv[0]);
        return 1;
    }
    
    printf("═══════════════════════════════════════════════════\n");
    printf("TAV INTEROPERABILITY TEST - C Validator\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("Reading vectors from: %s\n", argv[1]);
    
    process_file(argv[1]);
    
    printf("\n═══════════════════════════════════════════════════\n");
    printf("RESULTS: %d passed, %d failed\n", passed, failed);
    printf("═══════════════════════════════════════════════════\n");
    
    return failed > 0 ? 1 : 0;
}
