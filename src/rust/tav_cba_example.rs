//! TAV Clock Cryptography v0.9
//! Copyright (C) 2025 Carlos Alberto Terencio de Bastos
//! License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
//!
//! # TAV CBA - Capability-Based Authorization - EXAMPLE
//!
//!
//! ## Compile and run
//! ```bash
//! rustc --edition 2021 tav_cba.rs --crate-type=lib -o libtav_cba.rlib
//! rustc --edition 2021 tav_cba_example.rs --extern tav_cba=libtav_cba.rlib -o cba_demo
//! ./cba_demo
//! ```

//! If compiling as a single file, include the module.
#[path = "tav_cba.rs"]
mod tav_cba;

use tav_cba::{
    CbaContext, Capability, Identity, Proof, Resource, Signature,
    permissions, CbaError, CBA_VERSION,
};

fn main() {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║         TAV CBA - Capability-Based Authorization              ║");
    println!("║                     Rust Implementation                        ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    demo_basic_usage();
    demo_delegation();
    demo_proof_generation();
    demo_serialization();
    demo_revocation();
    demo_memory_sizes();

    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                    TODAS AS DEMOS CONCLUÍDAS!");
    println!("═══════════════════════════════════════════════════════════════");
}

/// Demo 1: Uso básico de identidade e assinaturas
fn demo_basic_usage() {
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ DEMO 1: Identidade e Assinaturas Hash-Chain                 │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // Cria identidade
    let mut alice = Identity::new(b"alice secret seed phrase", 50);
    
    println!("  Identidade criada:");
    println!("    Chave pública: {:02x}{:02x}{:02x}{:02x}...", 
             alice.public_key[0], alice.public_key[1], 
             alice.public_key[2], alice.public_key[3]);
    println!("    Cadeia: {} assinaturas", alice.chain_length);
    println!("    Restantes: {}", alice.remaining());
    println!();

    // Assina mensagem
    let message = b"Hello, TAV CBA!";
    let signature = alice.sign(message).expect("Falha ao assinar");
    
    println!("  Mensagem assinada:");
    println!("    Índice: {}", signature.index);
    println!("    Tamanho: {} bytes", std::mem::size_of::<Signature>());
    println!("    Serializado: {} bytes", signature.to_bytes().len());
    println!();

    // Verifica assinatura
    let is_valid = Identity::verify_signature(
        &alice.public_key,
        alice.chain_length,
        message,
        &signature,
    );
    
    println!("  Verificação: {}", if is_valid { "✓ VÁLIDA" } else { "✗ INVÁLIDA" });
    println!("  Assinaturas restantes: {}", alice.remaining());
    println!();
}

/// Demo 2: Emissão e delegação de capabilities
fn demo_delegation() {
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ DEMO 2: Emissão e Delegação de Capabilities                 │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // Cria hierarquia: Cloud -> Gateway -> Sensor
    let mut cloud = CbaContext::new("cloud master seed", 100);
    let mut gateway = CbaContext::new("gateway seed", 50);
    let sensor = CbaContext::new("sensor seed", 50);

    println!("  Hierarquia:");
    println!("    Cloud   -> Gateway -> Sensor");
    println!();

    // Cloud emite capability para Gateway
    let cap_gateway = cloud.issue_capability(
        gateway.public_key(),
        permissions::READ | permissions::WRITE | permissions::DELEGATE,
        &["zone:living", "zone:bedroom", "zone:kitchen"],
        7200, // 2 horas
        0,    // Ilimitado
        2,    // Pode delegar até 2 níveis
    ).expect("Falha ao emitir capability");

    println!("  Capability Cloud -> Gateway:");
    println!("    ID: {:02x}{:02x}{:02x}{:02x}...", 
             cap_gateway.id[0], cap_gateway.id[1],
             cap_gateway.id[2], cap_gateway.id[3]);
    println!("    Permissões: 0x{:04x} (READ|WRITE|DELEGATE)", cap_gateway.permissions);
    println!("    Recursos: {:?}", cap_gateway.resources.iter()
             .map(|r| r.as_str()).collect::<Vec<_>>());
    println!("    Nível delegação: {}", cap_gateway.delegation_level);
    println!("    Max delegação: {}", cap_gateway.max_delegation);
    println!();

    // Gateway delega para Sensor (com restrições)
    let cap_sensor = gateway.delegate_capability(
        &cap_gateway,
        sensor.public_key(),
        permissions::READ, // Apenas READ (não WRITE, não DELEGATE)
        &["zone:living"],  // Apenas living (não bedroom, não kitchen)
        3600,              // 1 hora (menos que parent)
    ).expect("Falha ao delegar capability");

    println!("  Capability Gateway -> Sensor (delegada):");
    println!("    ID: {:02x}{:02x}{:02x}{:02x}...", 
             cap_sensor.id[0], cap_sensor.id[1],
             cap_sensor.id[2], cap_sensor.id[3]);
    println!("    Permissões: 0x{:04x} (apenas READ)", cap_sensor.permissions);
    println!("    Recursos: {:?}", cap_sensor.resources.iter()
             .map(|r| r.as_str()).collect::<Vec<_>>());
    println!("    Nível delegação: {} (era {})", 
             cap_sensor.delegation_level, cap_gateway.delegation_level);
    println!("    Parent ID: {:02x}{:02x}...", 
             cap_sensor.parent_id.unwrap()[0],
             cap_sensor.parent_id.unwrap()[1]);
    println!();

    // Testa restrições
    println!("  Verificando restrições:");
    println!("    has_permission(READ):     {}", cap_sensor.has_permission(permissions::READ));
    println!("    has_permission(WRITE):    {} (restrito)", cap_sensor.has_permission(permissions::WRITE));
    println!("    has_permission(DELEGATE): {} (restrito)", cap_sensor.has_permission(permissions::DELEGATE));
    println!("    has_resource(zone:living):  {}", cap_sensor.has_resource("zone:living"));
    println!("    has_resource(zone:bedroom): {} (restrito)", cap_sensor.has_resource("zone:bedroom"));
    println!();
}

/// Demo 3: Geração e verificação de provas
fn demo_proof_generation() {
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ DEMO 3: Geração e Verificação de Provas                     │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    let mut issuer = CbaContext::new("issuer seed", 100);
    let mut holder = CbaContext::new("holder seed", 50);

    // Emite capability
    let cap = issuer.issue_capability(
        holder.public_key(),
        permissions::SENSOR, // READ | ENCRYPT
        &["temp", "humidity", "pressure"],
        3600,
        100,
        0,
    ).expect("Falha ao emitir");

    println!("  Capability emitida:");
    println!("    Permissões: SENSOR (READ | ENCRYPT)");
    println!("    Recursos: temp, humidity, pressure");
    println!("    Max usos: 100");
    println!();

    // Cria sessão
    holder.create_session(3600).expect("Falha ao criar sessão");
    println!("  Sessão criada: {} segundos", 3600);
    println!();

    // Gera provas
    println!("  Gerando provas:");
    
    for (i, (op, resource)) in [
        ("READ", "temp"),
        ("READ", "humidity"),
        ("ENCRYPT", "pressure"),
    ].iter().enumerate() {
        let proof = holder.generate_proof(&cap, op, resource, i == 0)
            .expect("Falha ao gerar prova");
        
        let proof_bytes = proof.to_bytes();
        println!("    Prova {}: {} {} -> {} bytes {}", 
                 i + 1, op, resource, proof_bytes.len(),
                 if proof.identity_proof.is_some() { "(com identidade)" } else { "(sem identidade)" });
    }
    println!();

    // Testa operação não permitida
    println!("  Testando operação não permitida:");
    match holder.generate_proof(&cap, "WRITE", "temp", false) {
        Ok(_) => println!("    WRITE temp: ✓ (erro - deveria falhar!)"),
        Err(CbaError::PermissionDenied) => println!("    WRITE temp: ✗ Permission denied (correto!)"),
        Err(e) => println!("    WRITE temp: Erro inesperado: {:?}", e),
    }

    // Testa recurso não autorizado
    match holder.generate_proof(&cap, "READ", "battery", false) {
        Ok(_) => println!("    READ battery: ✓ (erro - deveria falhar!)"),
        Err(CbaError::ResourceDenied) => println!("    READ battery: ✗ Resource denied (correto!)"),
        Err(e) => println!("    READ battery: Erro inesperado: {:?}", e),
    }
    println!();
}

/// Demo 4: Serialização e deserialização
fn demo_serialization() {
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ DEMO 4: Serialização e Deserialização                       │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    let mut issuer = CbaContext::new("issuer", 50);
    let holder = CbaContext::new("holder", 50);

    // Capability com múltiplos recursos
    let cap = issuer.issue_capability(
        holder.public_key(),
        permissions::FULL,
        &["r1", "resource_two", "third_resource"],
        86400,
        1000,
        3,
    ).expect("Falha ao emitir");

    // Serializa
    let cap_bytes = cap.to_bytes();
    println!("  Capability serializada: {} bytes", cap_bytes.len());

    // Deserializa
    let cap2 = Capability::from_bytes(&cap_bytes).expect("Falha ao deserializar");

    // Verifica
    println!("  Verificando integridade:");
    println!("    ID match: {}", cap.id == cap2.id);
    println!("    Permissions match: {}", cap.permissions == cap2.permissions);
    println!("    Resources count: {} == {}", cap.resources.len(), cap2.resources.len());
    println!("    Delegation level: {} == {}", cap.delegation_level, cap2.delegation_level);
    println!();

    // Prova
    let mut holder_ctx = CbaContext::new("holder", 50);
    holder_ctx.create_session(3600).unwrap();
    
    let proof = holder_ctx.generate_proof(&cap2, "READ", "r1", true)
        .expect("Falha ao gerar prova");
    
    let proof_bytes = proof.to_bytes();
    println!("  Prova serializada: {} bytes", proof_bytes.len());

    let proof2 = Proof::from_bytes(&proof_bytes).expect("Falha ao deserializar prova");
    println!("    Capability ID match: {}", proof.capability_id == proof2.capability_id);
    println!("    Operation match: {}", proof.operation == proof2.operation);
    println!("    Has identity: {}", proof2.identity_proof.is_some());
    println!();
}

/// Demo 5: Revogação
fn demo_revocation() {
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ DEMO 5: Revogação de Capabilities                           │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    let mut issuer = CbaContext::new("issuer", 50);
    let holder = CbaContext::new("holder", 50);

    let cap = issuer.issue_capability(
        holder.public_key(),
        permissions::READ,
        &["data"],
        3600,
        0,
        0,
    ).expect("Falha ao emitir");

    println!("  Capability emitida: {:02x}{:02x}...", cap.id[0], cap.id[1]);
    println!("  Revogada: {}", issuer.is_revoked(&cap.id));

    issuer.revoke(&cap.id);
    println!("  Após revoke(): {}", issuer.is_revoked(&cap.id));
    println!();

    // Status
    let status = issuer.status();
    println!("  Status do contexto:");
    println!("    Versão: {}", status.version);
    println!("    Assinaturas restantes: {}", status.signatures_remaining);
    println!("    Capabilities revogadas: {}", status.revoked_count);
    println!();
}

/// Demo 6: Tamanhos de memória
fn demo_memory_sizes() {
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ DEMO 6: Uso de Memória                                      │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("  Tamanhos das estruturas (stack):");
    println!("    Identity:   {} bytes", std::mem::size_of::<Identity>());
    println!("    Signature:  {} bytes", std::mem::size_of::<Signature>());
    println!("    Resource:   {} bytes", std::mem::size_of::<Resource>());
    println!("    Capability: {} bytes (+ Vec heap)", std::mem::size_of::<Capability>());
    println!("    Proof:      {} bytes", std::mem::size_of::<Proof>());
    println!("    CbaContext: {} bytes (+ Vec heap)", std::mem::size_of::<CbaContext>());
    println!();

    println!("  Tamanhos serializados:");
    println!("    Assinatura:           {} bytes (fixo)", 66);
    
    let mut ctx = CbaContext::new("test", 50);
    let holder = CbaContext::new("holder", 50);
    
    let cap1 = ctx.issue_capability(
        holder.public_key(),
        permissions::READ,
        &["r1"],
        3600, 0, 0,
    ).unwrap();
    println!("    Capability (1 recurso): {} bytes", cap1.to_bytes().len());

    let cap4 = ctx.issue_capability(
        holder.public_key(),
        permissions::FULL,
        &["resource1", "resource2", "resource3", "resource4"],
        3600, 0, 0,
    ).unwrap();
    println!("    Capability (4 recursos): {} bytes", cap4.to_bytes().len());

    let mut holder_ctx = CbaContext::new("holder", 50);
    holder_ctx.create_session(3600).unwrap();
    
    let proof_no_id = holder_ctx.generate_proof(&cap1, "READ", "r1", false).unwrap();
    println!("    Prova (sem identidade): {} bytes", proof_no_id.to_bytes().len());

    let proof_with_id = holder_ctx.generate_proof(&cap1, "READ", "r1", true).unwrap();
    println!("    Prova (com identidade): {} bytes", proof_with_id.to_bytes().len());
    println!();

    println!("  Comparação com outros protocolos:");
    println!("    ┌─────────────────┬─────────────┬────────────┐");
    println!("    │ Protocolo       │ Auth Token  │ Assinatura │");
    println!("    ├─────────────────┼─────────────┼────────────┤");
    println!("    │ TAV CBA         │ ~150 bytes  │ 66 bytes   │");
    println!("    │ JWT             │ 300-800 B   │ N/A        │");
    println!("    │ ML-DSA-44       │ N/A         │ 2420 bytes │");
    println!("    │ ECDSA P-256     │ N/A         │ 64 bytes   │");
    println!("    └─────────────────┴─────────────┴────────────┘");
    println!();
}
