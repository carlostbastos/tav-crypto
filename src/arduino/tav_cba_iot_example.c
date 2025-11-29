/*
 * TAV CBA - Exemplo para Arduino/ESP32
 * =====================================
 * 
 * Este exemplo demonstra:
 * 1. Sensor IoT emitindo dados autenticados
 * 2. Gateway recebendo e verificando dados
 * 3. Delegação de capabilities
 * 4. Comunicação segura entre dispositivos
 * 
 * Plataformas testadas:
 * - ESP32 DevKit
 * - ESP8266 NodeMCU
 * - Arduino Mega 2560
 * 
 * Conexões (para teste com Serial):
 * - Apenas USB para debug
 * - Para comunicação real, usar WiFi/BLE/LoRa
 */

#include "tav_cba_iot.h"

/* ============================================================================
 * CONFIGURAÇÃO DA PLATAFORMA
 * ============================================================================ */

#ifdef ESP32
    #include "esp_timer.h"
    #include "esp_random.h"
    
    uint32_t cba_get_time(void) {
        return (uint32_t)(esp_timer_get_time() / 1000000ULL);
    }
    
    uint32_t cba_get_micros(void) {
        return (uint32_t)esp_timer_get_time();
    }
    
#elif defined(ESP8266)
    uint32_t cba_get_time(void) {
        return millis() / 1000;
    }
    
    uint32_t cba_get_micros(void) {
        return micros();
    }
    
#elif defined(ARDUINO)
    uint32_t cba_get_time(void) {
        return millis() / 1000;
    }
    
    uint32_t cba_get_micros(void) {
        return micros();
    }
    
#else
    /* Para teste em PC */
    #include <stdio.h>
    #include <stdlib.h>
    #include <time.h>
    #include <sys/time.h>
    
    uint32_t cba_get_time(void) {
        return (uint32_t)time(NULL);
    }
    
    uint32_t cba_get_micros(void) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (uint32_t)(tv.tv_sec * 1000000ULL + tv.tv_usec);
    }
    
    /* Simulação de Serial para PC */
    #define Serial_print(x) printf("%s", x)
    #define Serial_println(x) printf("%s\n", x)
    #define Serial_print_int(x) printf("%d", x)
    #define Serial_print_hex(x) printf("%02x", x)
#endif

/* ============================================================================
 * HELPERS PARA PRINT
 * ============================================================================ */

#ifdef ARDUINO
    #define PRINT(x) Serial.print(x)
    #define PRINTLN(x) Serial.println(x)
    #define PRINT_INT(x) Serial.print(x)
    #define PRINT_HEX(x) Serial.print(x, HEX)
#else
    #define PRINT(x) Serial_print(x)
    #define PRINTLN(x) Serial_println(x)
    #define PRINT_INT(x) Serial_print_int(x)
    #define PRINT_HEX(x) Serial_print_hex(x)
#endif

void print_hex(const uint8_t* data, uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        if (data[i] < 0x10) PRINT("0");
        PRINT_HEX(data[i]);
    }
}

void print_result(cba_result_t res) {
    switch (res) {
        case CBA_OK: PRINT("OK"); break;
        case CBA_ERR_CHAIN: PRINT("Chain exhausted"); break;
        case CBA_ERR_SESSION: PRINT("Session invalid"); break;
        case CBA_ERR_EXPIRED: PRINT("Expired"); break;
        case CBA_ERR_REVOKED: PRINT("Revoked"); break;
        case CBA_ERR_PERM: PRINT("Permission denied"); break;
        case CBA_ERR_RESOURCE: PRINT("Resource denied"); break;
        case CBA_ERR_USES: PRINT("Max uses exceeded"); break;
        case CBA_ERR_DELEG: PRINT("Max delegation exceeded"); break;
        case CBA_ERR_SIG: PRINT("Invalid signature"); break;
        case CBA_ERR_PROOF: PRINT("Invalid proof"); break;
        case CBA_ERR_DATA: PRINT("Invalid data"); break;
        default: PRINT("Unknown error"); break;
    }
}

/* ============================================================================
 * ESTRUTURA DE DADOS DO SENSOR
 * ============================================================================ */

typedef struct {
    uint32_t timestamp;
    int16_t temperature;    /* °C * 100 */
    uint16_t humidity;      /* % * 100 */
    uint16_t pressure;      /* hPa */
    uint8_t battery;        /* % */
} sensor_data_t;

/* ============================================================================
 * DEMONSTRAÇÃO 1: SENSOR SIMPLES
 * ============================================================================ */

void demo_sensor_simple(void) {
    PRINTLN("\n========================================");
    PRINTLN("DEMO 1: Sensor IoT Simples");
    PRINTLN("========================================\n");
    
    /* Contextos */
    cba_ctx_t sensor_ctx;
    cba_ctx_t gateway_ctx;
    
    /* Seeds (em produção, usar valores únicos por dispositivo) */
    const uint8_t sensor_seed[] = "sensor-temp-001-secret-key";
    const uint8_t gateway_seed[] = "gateway-main-secret-key";
    
    /* Inicializa */
    PRINT("1. Inicializando sensor... ");
    cba_result_t res = cba_init(&sensor_ctx, sensor_seed, sizeof(sensor_seed) - 1);
    print_result(res);
    PRINTLN("");
    
    PRINT("   Chave pública: ");
    print_hex(sensor_ctx.identity.public_key, 16);
    PRINTLN("...");
    
    PRINT("   Assinaturas disponíveis: ");
    PRINT_INT(cba_identity_remaining(&sensor_ctx));
    PRINTLN("");
    
    PRINT("2. Inicializando gateway... ");
    res = cba_init(&gateway_ctx, gateway_seed, sizeof(gateway_seed) - 1);
    print_result(res);
    PRINTLN("");
    
    /* Gateway cria sessão */
    PRINT("3. Gateway cria sessão (1 hora)... ");
    res = cba_session_create(&gateway_ctx, 3600);
    print_result(res);
    PRINTLN("");
    
    /* Gateway emite capability para sensor */
    PRINTLN("4. Gateway emite capability para sensor:");
    
    const char* resources[] = {"temp", "hum", "press"};
    cba_cap_t sensor_cap;
    
    res = cba_cap_issue(&gateway_ctx,
                        sensor_ctx.identity.public_key,
                        CBA_PERM_SENSOR,  /* READ | ENCRYPT */
                        resources, 3,
                        7200,             /* 2 horas */
                        100,              /* 100 leituras */
                        0,                /* Sem delegação */
                        &sensor_cap);
    
    PRINT("   Resultado: ");
    print_result(res);
    PRINTLN("");
    
    PRINT("   Cap ID: ");
    print_hex(sensor_cap.id, CBA_ID_SIZE);
    PRINTLN("");
    
    PRINT("   Permissões: 0x");
    PRINT_HEX(sensor_cap.permissions >> 8);
    PRINT_HEX(sensor_cap.permissions & 0xFF);
    PRINTLN("");
    
    /* Sensor cria sua sessão */
    PRINT("5. Sensor cria sessão... ");
    res = cba_session_create(&sensor_ctx, 3600);
    print_result(res);
    PRINTLN("");
    
    /* Sensor faz leituras e gera provas */
    PRINTLN("6. Sensor faz leituras:");
    
    for (int i = 0; i < 3; i++) {
        /* Simula dados do sensor */
        sensor_data_t data;
        data.timestamp = cba_get_time();
        data.temperature = 2350 + (i * 10);  /* 23.50°C + variação */
        data.humidity = 6500 - (i * 50);     /* 65.00% - variação */
        data.pressure = 1013;
        data.battery = 95 - i;
        
        /* Gera prova */
        cba_proof_t proof;
        res = cba_proof_generate(&sensor_ctx, &sensor_cap, 
                                 cba_op_to_code("READ"), 0,
                                 1,  /* Com identidade */
                                 &proof);
        
        PRINT("   Leitura ");
        PRINT_INT(i + 1);
        PRINT(": T=");
        PRINT_INT(data.temperature / 100);
        PRINT(".");
        PRINT_INT(data.temperature % 100);
        PRINT("C, H=");
        PRINT_INT(data.humidity / 100);
        PRINT("%, Prova: ");
        print_result(res);
        PRINTLN("");
        
        if (res == CBA_OK) {
            /* Serializa para transmissão */
            uint8_t buffer[200];
            uint16_t proof_len = cba_proof_serialize(&proof, buffer, sizeof(buffer));
            
            PRINT("      Prova serializada: ");
            PRINT_INT(proof_len);
            PRINTLN(" bytes");
            
            /* Gateway verifica */
            cba_proof_t recv_proof;
            cba_proof_deserialize(buffer, proof_len, &recv_proof);
            
            res = cba_proof_verify(&gateway_ctx, &recv_proof, &sensor_cap,
                                   sensor_ctx.identity.public_key,
                                   CBA_IOT_CHAIN_LENGTH,
                                   60);  /* Max 60s de idade */
            
            PRINT("      Verificação: ");
            print_result(res);
            PRINTLN("");
        }
    }
    
    PRINT("\n7. Assinaturas restantes - Sensor: ");
    PRINT_INT(cba_identity_remaining(&sensor_ctx));
    PRINT(", Gateway: ");
    PRINT_INT(cba_identity_remaining(&gateway_ctx));
    PRINTLN("");
    
    /* Cleanup */
    cba_cleanup(&sensor_ctx);
    cba_cleanup(&gateway_ctx);
    
    PRINTLN("\nDemo 1 concluída!");
}

/* ============================================================================
 * DEMONSTRAÇÃO 2: DELEGAÇÃO (GATEWAY -> HUB -> SENSOR)
 * ============================================================================ */

void demo_delegation(void) {
    PRINTLN("\n========================================");
    PRINTLN("DEMO 2: Delegação de Capabilities");
    PRINTLN("========================================\n");
    
    cba_ctx_t cloud_ctx;
    cba_ctx_t hub_ctx;
    cba_ctx_t sensor_ctx;
    
    /* Seeds */
    const uint8_t cloud_seed[] = "cloud-master-key-2025";
    const uint8_t hub_seed[] = "hub-local-key-001";
    const uint8_t sensor_seed[] = "sensor-motion-001";
    
    /* Inicializa todos */
    cba_init(&cloud_ctx, cloud_seed, sizeof(cloud_seed) - 1);
    cba_init(&hub_ctx, hub_seed, sizeof(hub_seed) - 1);
    cba_init(&sensor_ctx, sensor_seed, sizeof(sensor_seed) - 1);
    
    cba_session_create(&cloud_ctx, 86400);  /* 24h */
    cba_session_create(&hub_ctx, 3600);     /* 1h */
    cba_session_create(&sensor_ctx, 3600);  /* 1h */
    
    PRINTLN("1. Hierarquia criada:");
    PRINTLN("   Cloud -> Hub -> Sensor");
    
    /* Cloud emite capability para Hub */
    PRINTLN("\n2. Cloud emite capability para Hub:");
    
    const char* hub_resources[] = {"zone:living", "zone:bedroom", "*:motion"};
    cba_cap_t hub_cap;
    
    cba_result_t res = cba_cap_issue(&cloud_ctx,
                                     hub_ctx.identity.public_key,
                                     CBA_PERM_GATEWAY,  /* READ | WRITE | DELEGATE */
                                     hub_resources, 3,
                                     86400,     /* 24h */
                                     -1,        /* Ilimitado */
                                     2,         /* Pode delegar 2 níveis */
                                     &hub_cap);
    
    PRINT("   Resultado: ");
    print_result(res);
    PRINTLN("");
    PRINT("   Permissões: 0x");
    PRINT_HEX(hub_cap.permissions >> 8);
    PRINT_HEX(hub_cap.permissions & 0xFF);
    PRINT(" (");
    if (hub_cap.permissions & CBA_PERM_READ) PRINT("R");
    if (hub_cap.permissions & CBA_PERM_WRITE) PRINT("W");
    if (hub_cap.permissions & CBA_PERM_DELEGATE) PRINT("D");
    PRINTLN(")");
    PRINT("   Max delegação: ");
    PRINT_INT(hub_cap.max_delegation_depth);
    PRINTLN("");
    
    /* Hub delega para Sensor (apenas READ em zone:living) */
    PRINTLN("\n3. Hub delega para Sensor (restrito):");
    
    const char* sensor_resources[] = {"zone:living"};
    cba_cap_t sensor_cap;
    
    res = cba_cap_delegate(&hub_ctx,
                           &hub_cap,
                           sensor_ctx.identity.public_key,
                           CBA_PERM_READ,           /* Apenas READ */
                           sensor_resources, 1,     /* Apenas living */
                           3600,                    /* 1h (menor que hub) */
                           &sensor_cap);
    
    PRINT("   Resultado: ");
    print_result(res);
    PRINTLN("");
    PRINT("   Permissões delegadas: 0x");
    PRINT_HEX(sensor_cap.permissions >> 8);
    PRINT_HEX(sensor_cap.permissions & 0xFF);
    PRINTLN("");
    PRINT("   Nível de delegação: ");
    PRINT_INT(sensor_cap.delegation_depth);
    PRINTLN("");
    PRINT("   Parent ID: ");
    print_hex(sensor_cap.parent_id, 8);
    PRINTLN("...");
    
    /* Sensor usa capability */
    PRINTLN("\n4. Sensor usa capability:");
    
    cba_proof_t proof;
    
    /* READ em zone:living - deve funcionar */
    PRINT("   READ zone:living: ");
    res = cba_proof_generate(&sensor_ctx, &sensor_cap,
                             cba_op_to_code("READ"), 0,
                             0, &proof);
    print_result(res);
    PRINTLN("");
    
    /* WRITE - deve falhar (não tem permissão) */
    PRINT("   WRITE zone:living: ");
    res = cba_proof_generate(&sensor_ctx, &sensor_cap,
                             cba_op_to_code("WRITE"), 0,
                             0, &proof);
    print_result(res);
    PRINTLN("");
    
    /* Sensor tenta delegar - deve falhar */
    PRINTLN("\n5. Sensor tenta delegar (sem permissão):");
    cba_ctx_t other_ctx;
    const uint8_t other_seed[] = "other-device";
    cba_init(&other_ctx, other_seed, sizeof(other_seed) - 1);
    
    cba_cap_t other_cap;
    res = cba_cap_delegate(&sensor_ctx,
                           &sensor_cap,
                           other_ctx.identity.public_key,
                           CBA_PERM_READ,
                           sensor_resources, 1,
                           1800,
                           &other_cap);
    
    PRINT("   Resultado: ");
    print_result(res);
    PRINTLN(" (esperado: Permission denied)");
    
    /* Hub revoga capability do sensor */
    PRINTLN("\n6. Hub revoga capability do sensor:");
    
    res = cba_cap_revoke(&hub_ctx, sensor_cap.id);
    PRINT("   Revogação: ");
    print_result(res);
    PRINTLN("");
    
    /* Sensor tenta usar após revogação */
    PRINT("   Sensor tenta usar: ");
    res = cba_proof_generate(&sensor_ctx, &sensor_cap,
                             cba_op_to_code("READ"), 0,
                             0, &proof);
    print_result(res);
    PRINTLN(" (esperado: Revoked)");
    
    /* Cleanup */
    cba_cleanup(&cloud_ctx);
    cba_cleanup(&hub_ctx);
    cba_cleanup(&sensor_ctx);
    cba_cleanup(&other_ctx);
    
    PRINTLN("\nDemo 2 concluída!");
}

/* ============================================================================
 * DEMONSTRAÇÃO 3: USO DE MEMÓRIA
 * ============================================================================ */

void demo_memory(void) {
    PRINTLN("\n========================================");
    PRINTLN("DEMO 3: Uso de Memória");
    PRINTLN("========================================\n");
    
    PRINT("Tamanho das estruturas:\n");
    
    PRINT("   cba_ctx_t:      ");
    PRINT_INT(sizeof(cba_ctx_t));
    PRINTLN(" bytes");
    
    PRINT("   cba_cap_t:      ");
    PRINT_INT(sizeof(cba_cap_t));
    PRINTLN(" bytes");
    
    PRINT("   cba_proof_t:    ");
    PRINT_INT(sizeof(cba_proof_t));
    PRINTLN(" bytes");
    
    PRINT("   cba_identity_t: ");
    PRINT_INT(sizeof(cba_identity_t));
    PRINTLN(" bytes");
    
    PRINT("   cba_session_t:  ");
    PRINT_INT(sizeof(cba_session_t));
    PRINTLN(" bytes");
    
    PRINTLN("\nConfiguração:");
    PRINT("   Tamanho da cadeia: ");
    PRINT_INT(CBA_IOT_CHAIN_LENGTH);
    PRINTLN(" assinaturas");
    
    PRINT("   Max recursos/cap: ");
    PRINT_INT(CBA_IOT_MAX_RESOURCES);
    PRINTLN("");
    
    PRINT("   Tamanho recurso:  ");
    PRINT_INT(CBA_IOT_RESOURCE_LEN);
    PRINTLN(" bytes");
    
    PRINT("   Lista revogação:  ");
    PRINT_INT(CBA_IOT_REVOKE_LIST);
    PRINTLN(" entradas");
    
    /* Serialização */
    PRINTLN("\nTamanhos serializados (típicos):");
    
    cba_ctx_t ctx;
    const uint8_t seed[] = "test";
    cba_init(&ctx, seed, 4);
    cba_session_create(&ctx, 3600);
    
    const char* res[] = {"sensor:temp"};
    cba_cap_t cap;
    cba_cap_issue(&ctx, ctx.identity.public_key, CBA_PERM_READ, res, 1, 
                  3600, 10, 1, &cap);
    
    uint8_t buffer[256];
    uint16_t len = cba_cap_serialize(&cap, buffer, sizeof(buffer));
    PRINT("   Capability (1 recurso): ");
    PRINT_INT(len);
    PRINTLN(" bytes");
    
    cba_proof_t proof;
    cba_proof_generate(&ctx, &cap, 1, 0, 0, &proof);
    len = cba_proof_serialize(&proof, buffer, sizeof(buffer));
    PRINT("   Prova (sem identidade): ");
    PRINT_INT(len);
    PRINTLN(" bytes");
    
    cba_proof_generate(&ctx, &cap, 1, 0, 1, &proof);
    len = cba_proof_serialize(&proof, buffer, sizeof(buffer));
    PRINT("   Prova (com identidade): ");
    PRINT_INT(len);
    PRINTLN(" bytes");
    
    cba_cleanup(&ctx);
    
    PRINTLN("\nDemo 3 concluída!");
}

/* ============================================================================
 * DEMONSTRAÇÃO 4: BENCHMARK
 * ============================================================================ */

void demo_benchmark(void) {
    PRINTLN("\n========================================");
    PRINTLN("DEMO 4: Benchmark");
    PRINTLN("========================================\n");
    
    cba_ctx_t ctx;
    const uint8_t seed[] = "benchmark-seed-2025";
    
    uint32_t start, elapsed;
    const int ITERATIONS = 10;
    
    /* Init */
    PRINT("1. Inicialização (");
    PRINT_INT(ITERATIONS);
    PRINT("x): ");
    
    start = cba_get_micros();
    for (int i = 0; i < ITERATIONS; i++) {
        cba_init(&ctx, seed, sizeof(seed) - 1);
        cba_cleanup(&ctx);
    }
    elapsed = cba_get_micros() - start;
    
    PRINT_INT(elapsed / ITERATIONS);
    PRINTLN(" us/op");
    
    /* Setup para outros testes */
    cba_init(&ctx, seed, sizeof(seed) - 1);
    cba_session_create(&ctx, 3600);
    
    /* Sessão */
    PRINT("2. Criar sessão (");
    PRINT_INT(ITERATIONS);
    PRINT("x): ");
    
    start = cba_get_micros();
    for (int i = 0; i < ITERATIONS; i++) {
        cba_session_create(&ctx, 3600);
    }
    elapsed = cba_get_micros() - start;
    
    PRINT_INT(elapsed / ITERATIONS);
    PRINTLN(" us/op");
    
    /* Emissão de capability */
    const char* res[] = {"test"};
    cba_cap_t cap;
    
    PRINT("3. Emitir capability (");
    PRINT_INT(ITERATIONS);
    PRINT("x): ");
    
    start = cba_get_micros();
    for (int i = 0; i < ITERATIONS; i++) {
        cba_cap_issue(&ctx, ctx.identity.public_key, CBA_PERM_READ,
                      res, 1, 3600, -1, 1, &cap);
    }
    elapsed = cba_get_micros() - start;
    
    PRINT_INT(elapsed / ITERATIONS);
    PRINTLN(" us/op");
    
    /* Gerar prova */
    cba_proof_t proof;
    
    PRINT("4. Gerar prova (");
    PRINT_INT(ITERATIONS);
    PRINT("x): ");
    
    /* Reset para ter assinaturas suficientes */
    cba_init(&ctx, seed, sizeof(seed) - 1);
    cba_session_create(&ctx, 3600);
    cba_cap_issue(&ctx, ctx.identity.public_key, CBA_PERM_READ,
                  res, 1, 3600, -1, 1, &cap);
    
    start = cba_get_micros();
    for (int i = 0; i < ITERATIONS; i++) {
        cba_proof_generate(&ctx, &cap, 1, 0, 1, &proof);
    }
    elapsed = cba_get_micros() - start;
    
    PRINT_INT(elapsed / ITERATIONS);
    PRINTLN(" us/op");
    
    /* Hash */
    uint8_t data[64] = {0};
    uint8_t hash[32];
    
    PRINT("5. Hash 64 bytes (");
    PRINT_INT(ITERATIONS * 10);
    PRINT("x): ");
    
    start = cba_get_micros();
    for (int i = 0; i < ITERATIONS * 10; i++) {
        cba_hash(data, 64, hash, 32);
    }
    elapsed = cba_get_micros() - start;
    
    PRINT_INT(elapsed / (ITERATIONS * 10));
    PRINTLN(" us/op");
    
    /* Verificação de assinatura */
    uint8_t sig[66];
    uint16_t idx;
    
    cba_init(&ctx, seed, sizeof(seed) - 1);
    cba_identity_sign(&ctx, data, 32, sig, &idx);
    
    PRINT("6. Verificar assinatura (");
    PRINT_INT(ITERATIONS);
    PRINT("x): ");
    
    start = cba_get_micros();
    for (int i = 0; i < ITERATIONS; i++) {
        cba_identity_verify(ctx.identity.public_key, CBA_IOT_CHAIN_LENGTH,
                            data, 32, sig);
    }
    elapsed = cba_get_micros() - start;
    
    PRINT_INT(elapsed / ITERATIONS);
    PRINTLN(" us/op");
    
    cba_cleanup(&ctx);
    
    PRINTLN("\nDemo 4 concluída!");
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

#ifdef ARDUINO

void setup() {
    Serial.begin(115200);
    while (!Serial) { delay(10); }
    
    delay(1000);
    
    Serial.println("\n");
    Serial.println("╔════════════════════════════════════════╗");
    Serial.println("║  TAV CBA - Capability-Based Auth       ║");
    Serial.println("║  Versão IoT para Arduino/ESP32         ║");
    Serial.println("╚════════════════════════════════════════╝");
    
    demo_sensor_simple();
    demo_delegation();
    demo_memory();
    demo_benchmark();
    
    Serial.println("\n========================================");
    Serial.println("Todas as demonstrações concluídas!");
    Serial.println("========================================");
}

void loop() {
    /* Nada no loop - demos são one-shot */
    delay(10000);
}

#else

/* Main para teste em PC */
int main(void) {
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║  TAV CBA - Capability-Based Auth       ║\n");
    printf("║  Versão IoT (teste em PC)              ║\n");
    printf("╚════════════════════════════════════════╝\n");
    
    demo_sensor_simple();
    demo_delegation();
    demo_memory();
    demo_benchmark();
    
    printf("\n========================================\n");
    printf("Todas as demonstrações concluídas!\n");
    printf("========================================\n");
    
    return 0;
}

#endif
