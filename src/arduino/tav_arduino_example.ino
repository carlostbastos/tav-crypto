/*
 * TAV Clock Cryptography v0.9
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
 */
/*
 * TAV CRYPTO - Arduino/ESP32 Example
 * ===================================
 * 
 * Demonstra:
 * - Inicialização
 * - Encrypt/Decrypt
 * - Assinatura digital
 * - Sincronização entre dispositivos
 * 
 * Hardware testado:
 * - Arduino Uno/Mega (AVR)
 * - ESP32/ESP8266
 * - STM32 Blue Pill
 */

#include "tav_arduino.h"

// Contexto TAV global
tav_ctx_t tav;

// Buffer para mensagens
uint8_t plaintext[128];
uint8_t ciphertext[256];
uint8_t decrypted[128];

// Chaves de assinatura
tav_sign_t sign_keys;

void setup() {
    Serial.begin(115200);
    while (!Serial) delay(10);
    
    Serial.println("\n=== TAV Clock Cryptography Demo ===\n");
    
    // =========================================
    // 1. INICIALIZAÇÃO
    // =========================================
    Serial.println("1. Initializing TAV...");
    
    // Seed pode vir de:
    // - Senha do usuário
    // - Valor fixo compartilhado
    // - Derivado de troca de chaves
    const char* seed = "minha_senha_secreta_123";
    
    tav_result_t res = tav_init(&tav, (const uint8_t*)seed, strlen(seed));
    
    if (res == TAV_OK) {
        Serial.println("   TAV initialized successfully!");
        Serial.print("   Security level: ");
        Serial.println(TAV_SECURITY_LEVEL);
        Serial.print("   Key size: ");
        Serial.print(TAV_KEY_BYTES);
        Serial.println(" bytes");
        Serial.print("   Overhead: ");
        Serial.print(TAV_OVERHEAD);
        Serial.println(" bytes");
    } else {
        Serial.println("   ERROR: Failed to initialize TAV!");
        while(1) delay(1000);
    }
    
    // =========================================
    // 2. ENCRYPT/DECRYPT
    // =========================================
    Serial.println("\n2. Encrypt/Decrypt test...");
    
    const char* message = "Hello, TAV Crypto!";
    uint16_t msg_len = strlen(message);
    uint16_t ct_len, pt_len;
    
    Serial.print("   Original: ");
    Serial.println(message);
    
    // Encrypt
    res = tav_encrypt(&tav, (const uint8_t*)message, msg_len, 
                      ciphertext, &ct_len, 1);
    
    if (res == TAV_OK) {
        Serial.print("   Encrypted (");
        Serial.print(ct_len);
        Serial.print(" bytes): ");
        for (int i = 0; i < min(ct_len, 20); i++) {
            if (ciphertext[i] < 16) Serial.print("0");
            Serial.print(ciphertext[i], HEX);
        }
        if (ct_len > 20) Serial.print("...");
        Serial.println();
    } else {
        Serial.println("   ERROR: Encryption failed!");
    }
    
    // Decrypt
    res = tav_decrypt(&tav, ciphertext, ct_len, decrypted, &pt_len);
    
    if (res == TAV_OK) {
        decrypted[pt_len] = '\0';
        Serial.print("   Decrypted: ");
        Serial.println((char*)decrypted);
        
        if (memcmp(message, decrypted, msg_len) == 0) {
            Serial.println("   ✓ Encryption/Decryption successful!");
        } else {
            Serial.println("   ✗ Data mismatch!");
        }
    } else if (res == TAV_ERROR_MAC) {
        Serial.println("   ERROR: MAC verification failed!");
    }
    
    // =========================================
    // 3. TAMPER DETECTION
    // =========================================
    Serial.println("\n3. Tamper detection test...");
    
    // Adultera um byte
    ciphertext[ct_len / 2] ^= 0xFF;
    
    res = tav_decrypt(&tav, ciphertext, ct_len, decrypted, &pt_len);
    
    if (res == TAV_ERROR_MAC) {
        Serial.println("   ✓ Tampering detected correctly!");
    } else {
        Serial.println("   ✗ Tampering NOT detected (problem!)");
    }
    
    // =========================================
    // 4. ASSINATURA DIGITAL
    // =========================================
    Serial.println("\n4. Digital signature test...");
    
    // Inicializa chaves (chain de 100 assinaturas)
    res = tav_sign_init(&sign_keys, (const uint8_t*)"sign_seed", 9, 100);
    
    if (res == TAV_OK) {
        Serial.println("   Signing keys generated!");
        Serial.print("   Public key: ");
        for (int i = 0; i < 8; i++) {
            if (sign_keys.public_key[i] < 16) Serial.print("0");
            Serial.print(sign_keys.public_key[i], HEX);
        }
        Serial.println("...");
    }
    
    // Assina documento
    const char* document = "Important document v1.0";
    uint8_t signature[68];
    uint8_t sig_len;
    
    res = tav_sign_sign(&sign_keys, (const uint8_t*)document, strlen(document),
                        signature, &sig_len);
    
    if (res == TAV_OK) {
        Serial.print("   Signature (");
        Serial.print(sig_len);
        Serial.print(" bytes): ");
        for (int i = 0; i < 16; i++) {
            if (signature[i] < 16) Serial.print("0");
            Serial.print(signature[i], HEX);
        }
        Serial.println("...");
    }
    
    // Verifica assinatura
    res = tav_sign_verify(sign_keys.public_key, 
                          (const uint8_t*)document, strlen(document),
                          signature, sig_len);
    
    if (res == TAV_OK) {
        Serial.println("   ✓ Signature valid!");
    } else {
        Serial.println("   ✗ Signature invalid!");
    }
    
    // Tenta verificar documento alterado
    const char* tampered_doc = "Important document v1.1";
    res = tav_sign_verify(sign_keys.public_key,
                          (const uint8_t*)tampered_doc, strlen(tampered_doc),
                          signature, sig_len);
    
    if (res == TAV_ERROR_MAC) {
        Serial.println("   ✓ Tampered document detected!");
    } else {
        Serial.println("   ✗ Tampered document NOT detected!");
    }
    
    // =========================================
    // 5. MÚLTIPLAS MENSAGENS (SYNC)
    // =========================================
    Serial.println("\n5. Multiple messages (sync test)...");
    
    // Reinicializa para teste de sync
    tav_init(&tav, (const uint8_t*)seed, strlen(seed));
    
    for (int i = 0; i < 10; i++) {
        char msg[32];
        sprintf(msg, "Message #%d", i);
        
        res = tav_encrypt(&tav, (const uint8_t*)msg, strlen(msg),
                          ciphertext, &ct_len, 1);
        
        if (res == TAV_OK) {
            res = tav_decrypt(&tav, ciphertext, ct_len, decrypted, &pt_len);
            tav_tick(&tav, 1); // Sincroniza após decrypt
            
            if (res == TAV_OK && memcmp(msg, decrypted, strlen(msg)) == 0) {
                Serial.print("   ✓ ");
            } else {
                Serial.print("   ✗ ");
            }
            Serial.println(msg);
        }
    }
    
    // =========================================
    // 6. BENCHMARK
    // =========================================
    Serial.println("\n6. Performance benchmark...");
    
    uint8_t bench_data[64];
    memset(bench_data, 0x55, 64);
    
    // Encrypt benchmark
    unsigned long start = micros();
    for (int i = 0; i < 100; i++) {
        tav_encrypt(&tav, bench_data, 64, ciphertext, &ct_len, 0);
    }
    unsigned long elapsed = micros() - start;
    
    Serial.print("   Encrypt 64 bytes x 100: ");
    Serial.print(elapsed / 1000.0);
    Serial.println(" ms");
    Serial.print("   Throughput: ");
    Serial.print((64 * 100 * 1000000.0) / elapsed / 1024);
    Serial.println(" KB/s");
    
    // Hash benchmark
    uint8_t hash_out[32];
    start = micros();
    for (int i = 0; i < 100; i++) {
        tav_hash(bench_data, 64, hash_out);
    }
    elapsed = micros() - start;
    
    Serial.print("   Hash 64 bytes x 100: ");
    Serial.print(elapsed / 1000.0);
    Serial.println(" ms");
    
    // =========================================
    // RESUMO
    // =========================================
    Serial.println("\n=== Demo Complete ===");
    Serial.print("Free RAM: ");
    #ifdef ESP32
    Serial.print(ESP.getFreeHeap());
    #elif defined(__AVR__)
    extern int __heap_start, *__brkval;
    int v;
    Serial.print((int)&v - (__brkval == 0 ? (int)&__heap_start : (int)__brkval));
    #else
    Serial.print("N/A");
    #endif
    Serial.println(" bytes");
}

void loop() {
    // Exemplo de comunicação contínua
    static unsigned long last_msg = 0;
    
    if (millis() - last_msg > 5000) {
        last_msg = millis();
        
        // Envia heartbeat criptografado
        char heartbeat[32];
        sprintf(heartbeat, "HB:%lu", millis());
        
        uint16_t ct_len;
        tav_encrypt(&tav, (const uint8_t*)heartbeat, strlen(heartbeat),
                    ciphertext, &ct_len, 1);
        
        Serial.print("Encrypted heartbeat: ");
        Serial.print(ct_len);
        Serial.println(" bytes");
    }
}

/*
 * =========================================
 * COMUNICAÇÃO ENTRE DOIS DISPOSITIVOS
 * =========================================
 * 
 * Para comunicação entre dois Arduino/ESP32:
 * 
 * 1. Ambos inicializam com MESMO seed:
 *    tav_init(&tav, "shared_secret", 13);
 * 
 * 2. Dispositivo A envia:
 *    tav_encrypt(&tav, msg, len, ct, &ct_len, 1);
 *    Serial.write(ct, ct_len);
 * 
 * 3. Dispositivo B recebe:
 *    Serial.readBytes(ct, ct_len);
 *    tav_decrypt(&tav, ct, ct_len, pt, &pt_len);
 *    tav_tick(&tav, 1);  // IMPORTANTE: sincroniza estado
 * 
 * 4. Se perder sincronia:
 *    - Reimportar seed
 *    - Ou usar protocolo de resync com tx_count no metadata
 */

/*
 * =========================================
 * MEMÓRIA FLASH (PROGMEM) - AVR
 * =========================================
 * 
 * Se memória RAM for problema no AVR, as constantes
 * já estão em PROGMEM. Para economizar mais:
 * 
 * 1. Use TAV_LEVEL_IOT (menor overhead)
 * 2. Reduza buffers se mensagens forem pequenas
 * 3. Use chain_length menor para assinaturas
 */

/*
 * =========================================
 * ESP32 - RECURSOS ESPECIAIS
 * =========================================
 * 
 * O ESP32 tem:
 * - Hardware RNG: pode alimentar o mixer
 * - Dual core: encrypt em core separado
 * - WiFi: envio direto pela rede
 * 
 * Para usar hardware RNG do ESP32:
 * 
 * #include "esp_random.h"
 * 
 * uint32_t tav_platform_random() {
 *     return esp_random();
 * }
 * 
 * // Adicione ao mixer durante init:
 * tav_mixer_update(&ctx->mixer, tav_platform_random());
 */
