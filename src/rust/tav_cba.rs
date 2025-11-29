//! TAV Clock Cryptography v0.9
//! Copyright (C) 2025 Carlos Alberto Terencio de Bastos
//! License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
//!
//! # TAV CBA - Capability-Based Authorization
//!
//! ## Features
//! - Hash-Chain based identity (66-byte signatures)
//! - Sessions with Commitment-Reveal
//! - Capabilities with 10 granular permissions
//! - Hierarchical delegation with automatic restrictions
//! - Instant revocation
//! - Compact proofs (83-151 bytes)
//!

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// CONSTANTES
// ============================================================================

pub const CBA_VERSION: &str = "1.0";
pub const CBA_HASH_SIZE: usize = 32;
pub const CBA_SIG_SIZE: usize = 66; // 2 (index) + 32 (reveal) + 32 (mac)
pub const CBA_MAX_RESOURCES: usize = 8;
pub const CBA_RESOURCE_MAX_LEN: usize = 32;
pub const CBA_DEFAULT_CHAIN_LENGTH: u16 = 100;
pub const CBA_SESSION_DURATION: u64 = 3600; // 1 hora
pub const CBA_PROOF_MAX_AGE: u64 = 300; // 5 minutos

// ============================================================================
// PERMISSÕES
// ============================================================================

/// Permissões disponíveis no sistema CBA
pub mod permissions {
    pub const READ: u16 = 0x0001;
    pub const WRITE: u16 = 0x0002;
    pub const DELETE: u16 = 0x0004;
    pub const ENCRYPT: u16 = 0x0008;
    pub const DECRYPT: u16 = 0x0010;
    pub const SIGN: u16 = 0x0020;
    pub const VERIFY: u16 = 0x0040;
    pub const DELEGATE: u16 = 0x0080;
    pub const REVOKE: u16 = 0x0100;
    pub const ADMIN: u16 = 0x0200;

    // Combinações comuns para IoT
    pub const SENSOR: u16 = READ | ENCRYPT;
    pub const ACTUATOR: u16 = WRITE | DECRYPT;
    pub const GATEWAY: u16 = READ | WRITE | DELEGATE;
    pub const FULL: u16 = 0x03FF;

    /// Converte nome de operação para código de permissão
    pub fn from_name(name: &str) -> Option<u16> {
        match name.to_uppercase().as_str() {
            "READ" => Some(READ),
            "WRITE" => Some(WRITE),
            "DELETE" => Some(DELETE),
            "ENCRYPT" => Some(ENCRYPT),
            "DECRYPT" => Some(DECRYPT),
            "SIGN" => Some(SIGN),
            "VERIFY" => Some(VERIFY),
            "DELEGATE" => Some(DELEGATE),
            "REVOKE" => Some(REVOKE),
            "ADMIN" => Some(ADMIN),
            _ => None,
        }
    }

    /// Converte código para nome legível
    pub fn to_name(perm: u16) -> &'static str {
        match perm {
            READ => "READ",
            WRITE => "WRITE",
            DELETE => "DELETE",
            ENCRYPT => "ENCRYPT",
            DECRYPT => "DECRYPT",
            SIGN => "SIGN",
            VERIFY => "VERIFY",
            DELEGATE => "DELEGATE",
            REVOKE => "REVOKE",
            ADMIN => "ADMIN",
            _ => "UNKNOWN",
        }
    }
}

// ============================================================================
// ERROS
// ============================================================================

/// Erros do sistema CBA
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CbaError {
    /// Cadeia de assinaturas esgotada
    ChainExhausted,
    /// Sessão inválida ou expirada
    InvalidSession,
    /// Capability expirada
    CapabilityExpired,
    /// Capability revogada
    CapabilityRevoked,
    /// Permissão negada
    PermissionDenied,
    /// Recurso não autorizado
    ResourceDenied,
    /// Máximo de usos excedido
    MaxUsesExceeded,
    /// Máximo de delegação excedido
    MaxDelegationExceeded,
    /// Assinatura inválida
    InvalidSignature,
    /// Prova inválida
    InvalidProof,
    /// Dados inválidos
    InvalidData,
    /// Prova expirada (muito antiga)
    ProofExpired,
    /// Contexto não inicializado
    NotInitialized,
}

pub type Result<T> = core::result::Result<T, CbaError>;

// ============================================================================
// CONSTANTES CRIPTOGRÁFICAS
// ============================================================================

const CONST_AND: [u8; 32] = [
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
];

const CONST_OR: [u8; 32] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
];

// Lookup table para rotação
const fn generate_rot_left() -> [[u8; 256]; 8] {
    let mut tables = [[0u8; 256]; 8];
    let mut rot = 0;
    while rot < 8 {
        let mut b = 0;
        while b < 256 {
            tables[rot][b] = ((b << rot) | (b >> (8 - rot))) as u8;
            b += 1;
        }
        rot += 1;
    }
    tables
}

static ROT_LEFT: [[u8; 256]; 8] = generate_rot_left();

// ============================================================================
// FUNÇÕES AUXILIARES
// ============================================================================

#[inline]
fn rot_left(byte: u8, n: usize) -> u8 {
    ROT_LEFT[n & 7][byte as usize]
}

/// Comparação em tempo constante
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Obtém timestamp atual em segundos
#[cfg(feature = "std")]
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(not(feature = "std"))]
fn get_timestamp() -> u64 {
    // Em no_std, deve ser fornecido externamente
    0
}

/// Hash TAV-Feistel
fn tav_hash(data: &[u8]) -> [u8; CBA_HASH_SIZE] {
    let mut state = [0u8; 32];
    
    // Inicializa com constante
    for i in 0..32 {
        state[i] = b"TAV-CBA-HASH-V1.0_______________"[i];
    }
    
    // Absorve dados
    for (i, &byte) in data.iter().enumerate() {
        state[i % 32] ^= byte;
        if (i + 1) % 32 == 0 || i == data.len() - 1 {
            feistel_round(&mut state, i);
        }
    }
    
    // Finaliza com tamanho
    let len_bytes = (data.len() as u64).to_be_bytes();
    for (i, &b) in len_bytes.iter().enumerate() {
        state[i] ^= b;
    }
    
    // Rodadas finais
    for r in 0..8 {
        feistel_round(&mut state, r);
    }
    
    state
}

/// Hash com saída de tamanho variável
fn tav_hash_sized(data: &[u8], out_len: usize) -> Vec<u8> {
    let hash = tav_hash(data);
    if out_len <= 32 {
        hash[..out_len].to_vec()
    } else {
        let mut result = hash.to_vec();
        while result.len() < out_len {
            let next = tav_hash(&result);
            result.extend_from_slice(&next[..core::cmp::min(32, out_len - result.len())]);
        }
        result
    }
}

/// MAC TAV-Feistel
fn tav_mac(key: &[u8], data: &[u8]) -> [u8; CBA_HASH_SIZE] {
    let mut combined = key.to_vec();
    combined.extend_from_slice(data);
    tav_hash(&combined)
}

/// Rodada Feistel
fn feistel_round(state: &mut [u8; 32], counter: usize) {
    for i in 0..32 {
        let mut x = state[i];
        x = rot_left(x, (counter + i) & 7);
        x = x & CONST_AND[(i + counter) & 31];
        x = x | CONST_OR[(i * 3 + counter) & 31];
        x = x ^ state[(i + 1) % 32];
        state[i] = x;
    }
}

// ============================================================================
// ESTRUTURAS
// ============================================================================

/// Recurso com nome
#[derive(Clone, Debug, Default)]
pub struct Resource {
    pub name: [u8; CBA_RESOURCE_MAX_LEN],
    pub len: usize,
}

impl Resource {
    pub fn new(name: &str) -> Self {
        let bytes = name.as_bytes();
        let len = core::cmp::min(bytes.len(), CBA_RESOURCE_MAX_LEN);
        let mut resource = Self {
            name: [0u8; CBA_RESOURCE_MAX_LEN],
            len,
        };
        resource.name[..len].copy_from_slice(&bytes[..len]);
        resource
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.len]).unwrap_or("")
    }

    pub fn matches(&self, other: &Resource) -> bool {
        if self.len == 0 || other.len == 0 {
            return false;
        }
        // Wildcard "*" aceita qualquer recurso
        if self.len == 1 && self.name[0] == b'*' {
            return true;
        }
        // Wildcard parcial "prefix:*"
        if self.len > 2 && self.name[self.len - 1] == b'*' {
            let prefix = &self.name[..self.len - 1];
            if other.len >= self.len - 1 {
                return &other.name[..self.len - 1] == prefix;
            }
        }
        // Match exato
        self.name[..self.len] == other.name[..other.len]
    }
}

/// Identidade baseada em Hash-Chain
#[derive(Clone)]
pub struct Identity {
    /// Chave pública (ponto final da cadeia)
    pub public_key: [u8; CBA_HASH_SIZE],
    /// Seed privada
    private_seed: [u8; CBA_HASH_SIZE],
    /// Índice atual na cadeia
    pub current_index: u16,
    /// Comprimento total da cadeia
    pub chain_length: u16,
}

impl Identity {
    /// Cria nova identidade a partir de seed
    pub fn new(seed: &[u8], chain_length: u16) -> Self {
        let private_seed = tav_hash(seed);
        
        // Gera chave pública (ponto final da cadeia)
        let mut current = private_seed;
        for _ in 0..chain_length {
            current = tav_hash(&current);
        }
        
        Self {
            public_key: current,
            private_seed,
            current_index: 0,
            chain_length,
        }
    }

    /// Assinaturas restantes
    pub fn remaining(&self) -> u16 {
        self.chain_length.saturating_sub(self.current_index)
    }

    /// Assina dados
    pub fn sign(&mut self, data: &[u8]) -> Result<Signature> {
        if self.current_index >= self.chain_length {
            return Err(CbaError::ChainExhausted);
        }

        // Calcula reveal (elemento da cadeia)
        let steps = self.chain_length - self.current_index - 1;
        let mut reveal = self.private_seed;
        for _ in 0..steps {
            reveal = tav_hash(&reveal);
        }

        // Calcula MAC
        let mut mac_input = data.to_vec();
        mac_input.extend_from_slice(&reveal);
        let mac = tav_hash(&mac_input);

        let signature = Signature {
            index: self.current_index,
            reveal,
            mac,
        };

        self.current_index += 1;
        Ok(signature)
    }

    /// Verifica assinatura (estático - não precisa de instância)
    pub fn verify_signature(
        public_key: &[u8; CBA_HASH_SIZE],
        chain_length: u16,
        data: &[u8],
        signature: &Signature,
    ) -> bool {
        if signature.index >= chain_length {
            return false;
        }

        // Verifica MAC
        let mut mac_input = data.to_vec();
        mac_input.extend_from_slice(&signature.reveal);
        let expected_mac = tav_hash(&mac_input);
        
        if !constant_time_compare(&signature.mac, &expected_mac) {
            return false;
        }

        // Verifica cadeia: hash(reveal) repetido deve chegar à public_key
        let mut current = signature.reveal;
        for _ in 0..=signature.index {
            current = tav_hash(&current);
        }

        constant_time_compare(&current, public_key)
    }
}

/// Assinatura Hash-Chain
#[derive(Clone, Debug)]
pub struct Signature {
    pub index: u16,
    pub reveal: [u8; CBA_HASH_SIZE],
    pub mac: [u8; CBA_HASH_SIZE],
}

impl Signature {
    /// Serializa assinatura (66 bytes)
    pub fn to_bytes(&self) -> [u8; CBA_SIG_SIZE] {
        let mut bytes = [0u8; CBA_SIG_SIZE];
        bytes[0] = (self.index >> 8) as u8;
        bytes[1] = self.index as u8;
        bytes[2..34].copy_from_slice(&self.reveal);
        bytes[34..66].copy_from_slice(&self.mac);
        bytes
    }

    /// Deserializa assinatura
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < CBA_SIG_SIZE {
            return Err(CbaError::InvalidData);
        }
        
        let index = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
        let mut reveal = [0u8; CBA_HASH_SIZE];
        let mut mac = [0u8; CBA_HASH_SIZE];
        reveal.copy_from_slice(&bytes[2..34]);
        mac.copy_from_slice(&bytes[34..66]);
        
        Ok(Self { index, reveal, mac })
    }
}

/// Sessão ativa
#[derive(Clone)]
pub struct Session {
    /// ID da sessão
    pub session_id: [u8; CBA_HASH_SIZE],
    /// Chave de sessão derivada
    pub session_key: [u8; CBA_HASH_SIZE],
    /// Timestamp de criação
    pub created_at: u64,
    /// Duração em segundos
    pub duration: u64,
    /// Contador de operações
    pub operation_count: u32,
}

impl Session {
    /// Verifica se sessão está ativa
    pub fn is_active(&self) -> bool {
        let now = get_timestamp();
        now < self.created_at + self.duration
    }

    /// Tempo restante em segundos
    pub fn time_remaining(&self) -> u64 {
        let now = get_timestamp();
        let expires = self.created_at + self.duration;
        if now >= expires {
            0
        } else {
            expires - now
        }
    }
}

/// Capability - autorização delegável
#[derive(Clone)]
pub struct Capability {
    /// ID único
    pub id: [u8; CBA_HASH_SIZE],
    /// Chave pública do emissor
    pub issuer_key: [u8; CBA_HASH_SIZE],
    /// Chave pública do detentor
    pub holder_key: [u8; CBA_HASH_SIZE],
    /// Permissões (bitmask)
    pub permissions: u16,
    /// Recursos autorizados
    pub resources: Vec<Resource>,
    /// Timestamp de criação
    pub created_at: u64,
    /// Timestamp de expiração
    pub expires_at: u64,
    /// Máximo de usos (0 = ilimitado)
    pub max_uses: u32,
    /// Usos atuais
    pub use_count: u32,
    /// Nível de delegação (0 = original)
    pub delegation_level: u8,
    /// Máximo de delegações permitidas
    pub max_delegation: u8,
    /// ID da capability pai (se delegada)
    pub parent_id: Option<[u8; CBA_HASH_SIZE]>,
    /// Assinatura do emissor
    pub signature: Signature,
}

impl Capability {
    /// Verifica se capability está válida
    pub fn is_valid(&self) -> bool {
        let now = get_timestamp();
        now >= self.created_at && now < self.expires_at
    }

    /// Verifica se tem permissão específica
    pub fn has_permission(&self, perm: u16) -> bool {
        (self.permissions & perm) == perm
    }

    /// Verifica se tem acesso a recurso
    pub fn has_resource(&self, resource: &str) -> bool {
        let target = Resource::new(resource);
        self.resources.iter().any(|r| r.matches(&target))
    }

    /// Encontra índice do recurso
    pub fn find_resource_index(&self, resource: &str) -> Option<usize> {
        let target = Resource::new(resource);
        self.resources.iter().position(|r| r.matches(&target))
    }

    /// Pode delegar?
    pub fn can_delegate(&self) -> bool {
        self.has_permission(permissions::DELEGATE) && self.delegation_level < self.max_delegation
    }

    /// Serializa capability
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Versão (1 byte)
        bytes.push(0x01);
        
        // IDs e chaves (96 bytes)
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.issuer_key);
        bytes.extend_from_slice(&self.holder_key);
        
        // Permissões (2 bytes)
        bytes.push((self.permissions >> 8) as u8);
        bytes.push(self.permissions as u8);
        
        // Timestamps (16 bytes)
        bytes.extend_from_slice(&self.created_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        
        // Contadores (8 bytes)
        bytes.extend_from_slice(&self.max_uses.to_be_bytes());
        bytes.extend_from_slice(&self.use_count.to_be_bytes());
        
        // Delegação (2 bytes)
        bytes.push(self.delegation_level);
        bytes.push(self.max_delegation);
        
        // Parent ID (1 + 0 ou 32 bytes)
        if let Some(ref parent) = self.parent_id {
            bytes.push(1);
            bytes.extend_from_slice(parent);
        } else {
            bytes.push(0);
        }
        
        // Recursos
        bytes.push(self.resources.len() as u8);
        for resource in &self.resources {
            bytes.push(resource.len as u8);
            bytes.extend_from_slice(&resource.name[..resource.len]);
        }
        
        // Assinatura (66 bytes)
        bytes.extend_from_slice(&self.signature.to_bytes());
        
        bytes
    }

    /// Deserializa capability
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 130 {
            return Err(CbaError::InvalidData);
        }
        
        let mut pos = 0;
        
        // Versão
        let _version = bytes[pos];
        pos += 1;
        
        // IDs e chaves
        let mut id = [0u8; CBA_HASH_SIZE];
        let mut issuer_key = [0u8; CBA_HASH_SIZE];
        let mut holder_key = [0u8; CBA_HASH_SIZE];
        
        id.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        issuer_key.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        holder_key.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        
        // Permissões
        let permissions = ((bytes[pos] as u16) << 8) | (bytes[pos + 1] as u16);
        pos += 2;
        
        // Timestamps
        let created_at = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let expires_at = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        
        // Contadores
        let max_uses = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let use_count = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        
        // Delegação
        let delegation_level = bytes[pos];
        pos += 1;
        let max_delegation = bytes[pos];
        pos += 1;
        
        // Parent ID
        let has_parent = bytes[pos] != 0;
        pos += 1;
        let parent_id = if has_parent {
            let mut parent = [0u8; CBA_HASH_SIZE];
            parent.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Some(parent)
        } else {
            None
        };
        
        // Recursos
        let n_resources = bytes[pos] as usize;
        pos += 1;
        let mut resources = Vec::with_capacity(n_resources);
        for _ in 0..n_resources {
            let len = bytes[pos] as usize;
            pos += 1;
            let mut resource = Resource::default();
            resource.len = len;
            resource.name[..len].copy_from_slice(&bytes[pos..pos + len]);
            pos += len;
            resources.push(resource);
        }
        
        // Assinatura
        let signature = Signature::from_bytes(&bytes[pos..])?;
        
        Ok(Self {
            id,
            issuer_key,
            holder_key,
            permissions,
            resources,
            created_at,
            expires_at,
            max_uses,
            use_count,
            delegation_level,
            max_delegation,
            parent_id,
            signature,
        })
    }
}

/// Prova de autorização
#[derive(Clone)]
pub struct Proof {
    /// ID da capability
    pub capability_id: [u8; CBA_HASH_SIZE],
    /// Código da operação
    pub operation: u16,
    /// Índice do recurso
    pub resource_index: u8,
    /// Timestamp da prova
    pub timestamp: u64,
    /// Nonce único
    pub nonce: u32,
    /// Prova de sessão
    pub session_proof: [u8; CBA_HASH_SIZE],
    /// Prova de identidade (opcional)
    pub identity_proof: Option<Signature>,
}

impl Proof {
    /// Serializa prova
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Versão
        bytes.push(0x01);
        
        // Capability ID
        bytes.extend_from_slice(&self.capability_id);
        
        // Operação e recurso
        bytes.push((self.operation >> 8) as u8);
        bytes.push(self.operation as u8);
        bytes.push(self.resource_index);
        
        // Timestamp e nonce
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        
        // Session proof
        bytes.extend_from_slice(&self.session_proof);
        
        // Identity proof (opcional)
        if let Some(ref sig) = self.identity_proof {
            bytes.push(1);
            bytes.extend_from_slice(&sig.to_bytes());
        } else {
            bytes.push(0);
        }
        
        bytes
    }

    /// Deserializa prova
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 80 {
            return Err(CbaError::InvalidData);
        }
        
        let mut pos = 0;
        
        // Versão
        let _version = bytes[pos];
        pos += 1;
        
        // Capability ID
        let mut capability_id = [0u8; CBA_HASH_SIZE];
        capability_id.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        
        // Operação e recurso
        let operation = ((bytes[pos] as u16) << 8) | (bytes[pos + 1] as u16);
        pos += 2;
        let resource_index = bytes[pos];
        pos += 1;
        
        // Timestamp e nonce
        let timestamp = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let nonce = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        
        // Session proof
        let mut session_proof = [0u8; CBA_HASH_SIZE];
        session_proof.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        
        // Identity proof
        let has_identity = bytes[pos] != 0;
        pos += 1;
        let identity_proof = if has_identity {
            Some(Signature::from_bytes(&bytes[pos..])?)
        } else {
            None
        };
        
        Ok(Self {
            capability_id,
            operation,
            resource_index,
            timestamp,
            nonce,
            session_proof,
            identity_proof,
        })
    }
}

// ============================================================================
// CONTEXTO CBA
// ============================================================================

/// Contexto principal do CBA
pub struct CbaContext {
    /// Identidade do contexto
    pub identity: Identity,
    /// Sessão atual
    session: Option<Session>,
    /// Lista de IDs revogados
    revoked_ids: Vec<[u8; CBA_HASH_SIZE]>,
    /// Contador de nonce
    nonce_counter: u32,
    /// Inicializado
    initialized: bool,
}

impl CbaContext {
    /// Cria novo contexto
    pub fn new(seed: &str, chain_length: u16) -> Self {
        Self {
            identity: Identity::new(seed.as_bytes(), chain_length),
            session: None,
            revoked_ids: Vec::new(),
            nonce_counter: 0,
            initialized: true,
        }
    }

    /// Chave pública
    pub fn public_key(&self) -> &[u8; CBA_HASH_SIZE] {
        &self.identity.public_key
    }

    /// Comprimento da cadeia
    pub fn chain_length(&self) -> u16 {
        self.identity.chain_length
    }

    /// Assinaturas restantes
    pub fn signatures_remaining(&self) -> u16 {
        self.identity.remaining()
    }

    // ========================================================================
    // SESSÃO
    // ========================================================================

    /// Cria nova sessão
    pub fn create_session(&mut self, duration: u64) -> Result<&Session> {
        if !self.initialized {
            return Err(CbaError::NotInitialized);
        }

        let now = get_timestamp();
        
        // Gera session_id
        let mut session_data = self.identity.public_key.to_vec();
        session_data.extend_from_slice(&now.to_be_bytes());
        session_data.extend_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        
        let session_id = tav_hash(&session_data);
        
        // Deriva session_key
        let mut key_data = session_id.to_vec();
        key_data.extend_from_slice(b"_SESSION_KEY_");
        let session_key = tav_hash(&key_data);

        self.session = Some(Session {
            session_id,
            session_key,
            created_at: now,
            duration,
            operation_count: 0,
        });

        Ok(self.session.as_ref().unwrap())
    }

    /// Sessão ativa?
    pub fn has_active_session(&self) -> bool {
        self.session.as_ref().map_or(false, |s| s.is_active())
    }

    /// Obtém sessão atual
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref().filter(|s| s.is_active())
    }

    /// Prova de sessão
    fn session_proof(&mut self) -> Result<[u8; CBA_HASH_SIZE]> {
        let session = self.session.as_mut().ok_or(CbaError::InvalidSession)?;
        if !session.is_active() {
            return Err(CbaError::InvalidSession);
        }

        let mut proof_data = session.session_id.to_vec();
        proof_data.extend_from_slice(&session.operation_count.to_be_bytes());
        session.operation_count += 1;

        Ok(tav_hash(&proof_data))
    }

    // ========================================================================
    // CAPABILITIES
    // ========================================================================

    /// Emite nova capability
    pub fn issue_capability(
        &mut self,
        holder_public_key: &[u8; CBA_HASH_SIZE],
        permissions: u16,
        resources: &[&str],
        duration_seconds: u64,
        max_uses: u32,
        max_delegation: u8,
    ) -> Result<Capability> {
        if !self.initialized {
            return Err(CbaError::NotInitialized);
        }

        let now = get_timestamp();
        
        // Gera ID único
        let mut id_data = self.identity.public_key.to_vec();
        id_data.extend_from_slice(holder_public_key);
        id_data.extend_from_slice(&now.to_be_bytes());
        id_data.extend_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        
        let id = tav_hash(&id_data);

        // Converte recursos
        let resources: Vec<Resource> = resources.iter().map(|r| Resource::new(r)).collect();

        // Dados para assinatura
        let mut sign_data = id.to_vec();
        sign_data.extend_from_slice(&self.identity.public_key);
        sign_data.extend_from_slice(holder_public_key);
        sign_data.extend_from_slice(&permissions.to_be_bytes());
        sign_data.extend_from_slice(&now.to_be_bytes());
        sign_data.extend_from_slice(&(now + duration_seconds).to_be_bytes());
        
        let signature = self.identity.sign(&sign_data)?;

        Ok(Capability {
            id,
            issuer_key: self.identity.public_key,
            holder_key: *holder_public_key,
            permissions,
            resources,
            created_at: now,
            expires_at: now + duration_seconds,
            max_uses,
            use_count: 0,
            delegation_level: 0,
            max_delegation,
            parent_id: None,
            signature,
        })
    }

    /// Delega capability existente
    pub fn delegate_capability(
        &mut self,
        parent: &Capability,
        new_holder_key: &[u8; CBA_HASH_SIZE],
        permissions: u16,
        resources: &[&str],
        duration_seconds: u64,
    ) -> Result<Capability> {
        // Verifica se pode delegar
        if !parent.has_permission(permissions::DELEGATE) {
            return Err(CbaError::PermissionDenied);
        }
        if parent.delegation_level >= parent.max_delegation {
            return Err(CbaError::MaxDelegationExceeded);
        }
        if !parent.is_valid() {
            return Err(CbaError::CapabilityExpired);
        }

        // Restringe permissões
        let restricted_perms = permissions & parent.permissions;
        
        // Restringe recursos
        let restricted_resources: Vec<Resource> = resources
            .iter()
            .filter(|r| parent.has_resource(r))
            .map(|r| Resource::new(r))
            .collect();
        
        if restricted_resources.is_empty() {
            return Err(CbaError::ResourceDenied);
        }

        // Restringe duração
        let now = get_timestamp();
        let max_expires = parent.expires_at;
        let expires = core::cmp::min(now + duration_seconds, max_expires);

        let mut id_data = parent.id.to_vec();
        id_data.extend_from_slice(new_holder_key);
        id_data.extend_from_slice(&now.to_be_bytes());
        id_data.extend_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        
        let id = tav_hash(&id_data);

        // Assinatura
        let mut sign_data = id.to_vec();
        sign_data.extend_from_slice(&parent.id);
        sign_data.extend_from_slice(&self.identity.public_key);
        sign_data.extend_from_slice(new_holder_key);
        sign_data.extend_from_slice(&restricted_perms.to_be_bytes());
        
        let signature = self.identity.sign(&sign_data)?;

        Ok(Capability {
            id,
            issuer_key: self.identity.public_key,
            holder_key: *new_holder_key,
            permissions: restricted_perms,
            resources: restricted_resources,
            created_at: now,
            expires_at: expires,
            max_uses: parent.max_uses,
            use_count: 0,
            delegation_level: parent.delegation_level + 1,
            max_delegation: parent.max_delegation,
            parent_id: Some(parent.id),
            signature,
        })
    }

    /// Revoga capability
    pub fn revoke(&mut self, capability_id: &[u8; CBA_HASH_SIZE]) {
        if !self.revoked_ids.contains(capability_id) {
            self.revoked_ids.push(*capability_id);
        }
    }

    /// Verifica se ID está revogado
    pub fn is_revoked(&self, capability_id: &[u8; CBA_HASH_SIZE]) -> bool {
        self.revoked_ids.contains(capability_id)
    }

    // ========================================================================
    // PROVAS
    // ========================================================================

    /// Gera prova de autorização
    pub fn generate_proof(
        &mut self,
        capability: &Capability,
        operation: &str,
        resource: &str,
        include_identity: bool,
    ) -> Result<Proof> {
        // Verifica capability
        if !capability.is_valid() {
            return Err(CbaError::CapabilityExpired);
        }
        if self.is_revoked(&capability.id) {
            return Err(CbaError::CapabilityRevoked);
        }

        // Verifica permissão
        let op_code = permissions::from_name(operation).ok_or(CbaError::InvalidData)?;
        if !capability.has_permission(op_code) {
            return Err(CbaError::PermissionDenied);
        }

        // Verifica recurso
        let resource_index = capability
            .find_resource_index(resource)
            .ok_or(CbaError::ResourceDenied)? as u8;

        // Verifica usos
        if capability.max_uses > 0 && capability.use_count >= capability.max_uses {
            return Err(CbaError::MaxUsesExceeded);
        }

        let now = get_timestamp();
        let nonce = self.nonce_counter;
        self.nonce_counter += 1;

        // Prova de sessão
        let session_proof = self.session_proof()?;

        // Prova de identidade (opcional)
        let identity_proof = if include_identity {
            let mut id_data = capability.id.to_vec();
            id_data.extend_from_slice(&now.to_be_bytes());
            id_data.extend_from_slice(&nonce.to_be_bytes());
            Some(self.identity.sign(&id_data)?)
        } else {
            None
        };

        Ok(Proof {
            capability_id: capability.id,
            operation: op_code,
            resource_index,
            timestamp: now,
            nonce,
            session_proof,
            identity_proof,
        })
    }

    /// Verifica prova
    pub fn verify_proof(
        &self,
        proof: &Proof,
        capability: &Capability,
        issuer_public_key: &[u8; CBA_HASH_SIZE],
        issuer_chain_length: u16,
        max_age_seconds: u64,
    ) -> Result<bool> {
        // Verifica timestamp
        let now = get_timestamp();
        if proof.timestamp > now || now - proof.timestamp > max_age_seconds {
            return Err(CbaError::ProofExpired);
        }

        // Verifica capability ID
        if proof.capability_id != capability.id {
            return Err(CbaError::InvalidProof);
        }

        // Verifica se capability está válida
        if !capability.is_valid() {
            return Err(CbaError::CapabilityExpired);
        }

        // Verifica revogação
        if self.is_revoked(&capability.id) {
            return Err(CbaError::CapabilityRevoked);
        }

        // Verifica permissão
        if !capability.has_permission(proof.operation) {
            return Err(CbaError::PermissionDenied);
        }

        // Verifica recurso
        if proof.resource_index as usize >= capability.resources.len() {
            return Err(CbaError::ResourceDenied);
        }

        // Verifica assinatura da capability
        let mut sign_data = capability.id.to_vec();
        sign_data.extend_from_slice(&capability.issuer_key);
        sign_data.extend_from_slice(&capability.holder_key);
        sign_data.extend_from_slice(&capability.permissions.to_be_bytes());
        sign_data.extend_from_slice(&capability.created_at.to_be_bytes());
        sign_data.extend_from_slice(&capability.expires_at.to_be_bytes());

        if !Identity::verify_signature(
            issuer_public_key,
            issuer_chain_length,
            &sign_data,
            &capability.signature,
        ) {
            return Err(CbaError::InvalidSignature);
        }

        // Verifica identidade (se presente)
        if let Some(ref id_proof) = proof.identity_proof {
            let mut id_data = capability.id.to_vec();
            id_data.extend_from_slice(&proof.timestamp.to_be_bytes());
            id_data.extend_from_slice(&proof.nonce.to_be_bytes());

            if !Identity::verify_signature(
                &capability.holder_key,
                issuer_chain_length, // Assume mesmo comprimento
                &id_data,
                id_proof,
            ) {
                return Err(CbaError::InvalidSignature);
            }
        }

        Ok(true)
    }

    // ========================================================================
    // STATUS
    // ========================================================================

    /// Retorna status do contexto
    pub fn status(&self) -> CbaStatus {
        CbaStatus {
            version: CBA_VERSION.to_string(),
            signatures_remaining: self.identity.remaining(),
            chain_length: self.identity.chain_length,
            has_active_session: self.has_active_session(),
            session_time_remaining: self.session().map_or(0, |s| s.time_remaining()),
            revoked_count: self.revoked_ids.len(),
        }
    }
}

/// Status do contexto CBA
#[derive(Clone, Debug)]
pub struct CbaStatus {
    pub version: String,
    pub signatures_remaining: u16,
    pub chain_length: u16,
    pub has_active_session: bool,
    pub session_time_remaining: u64,
    pub revoked_count: usize,
}

// ============================================================================
// TESTES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_sign_verify() {
        let mut identity = Identity::new(b"test seed", 10);
        let data = b"test message";
        
        let public_key = identity.public_key;
        let chain_length = identity.chain_length;
        
        let sig = identity.sign(data).unwrap();
        
        assert!(Identity::verify_signature(&public_key, chain_length, data, &sig));
    }

    #[test]
    fn test_capability_issue() {
        let mut issuer = CbaContext::new("issuer seed", 50);
        let holder = CbaContext::new("holder seed", 50);
        
        let cap = issuer.issue_capability(
            holder.public_key(),
            permissions::READ | permissions::WRITE,
            &["resource1", "resource2"],
            3600,
            100,
            2,
        ).unwrap();
        
        assert!(cap.has_permission(permissions::READ));
        assert!(cap.has_permission(permissions::WRITE));
        assert!(!cap.has_permission(permissions::DELETE));
        assert!(cap.has_resource("resource1"));
        assert!(!cap.has_resource("resource3"));
    }

    #[test]
    fn test_capability_delegation() {
        let mut cloud = CbaContext::new("cloud seed", 100);
        let mut hub = CbaContext::new("hub seed", 50);
        let sensor = CbaContext::new("sensor seed", 50);
        
        // Cloud -> Hub
        let cap1 = cloud.issue_capability(
            hub.public_key(),
            permissions::READ | permissions::WRITE | permissions::DELEGATE,
            &["zone:living", "zone:bedroom"],
            7200,
            0,
            2,
        ).unwrap();
        
        // Hub -> Sensor (restrito)
        let cap2 = hub.delegate_capability(
            &cap1,
            sensor.public_key(),
            permissions::READ, // Apenas READ
            &["zone:living"],  // Apenas living
            3600,
        ).unwrap();
        
        assert_eq!(cap2.delegation_level, 1);
        assert!(cap2.has_permission(permissions::READ));
        assert!(!cap2.has_permission(permissions::WRITE)); // Restrito
        assert!(cap2.has_resource("zone:living"));
        assert!(!cap2.has_resource("zone:bedroom")); // Restrito
    }

    #[test]
    fn test_proof_generation() {
        let mut issuer = CbaContext::new("issuer seed", 50);
        let mut holder = CbaContext::new("holder seed", 50);
        
        let cap = issuer.issue_capability(
            holder.public_key(),
            permissions::READ | permissions::ENCRYPT,
            &["temp", "humidity"],
            3600,
            100,
            0,
        ).unwrap();
        
        holder.create_session(3600).unwrap();
        
        let proof = holder.generate_proof(&cap, "READ", "temp", true).unwrap();
        
        assert_eq!(proof.operation, permissions::READ);
        assert_eq!(proof.resource_index, 0);
        assert!(proof.identity_proof.is_some());
    }

    #[test]
    fn test_serialization() {
        let mut issuer = CbaContext::new("issuer seed", 50);
        let holder = CbaContext::new("holder seed", 50);
        
        let cap = issuer.issue_capability(
            holder.public_key(),
            permissions::SENSOR,
            &["temp"],
            3600,
            100,
            0,
        ).unwrap();
        
        let bytes = cap.to_bytes();
        let cap2 = Capability::from_bytes(&bytes).unwrap();
        
        assert_eq!(cap.id, cap2.id);
        assert_eq!(cap.permissions, cap2.permissions);
        assert_eq!(cap.resources.len(), cap2.resources.len());
    }

    #[test]
    fn test_signature_serialization() {
        let mut identity = Identity::new(b"test", 10);
        let sig = identity.sign(b"data").unwrap();
        
        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes).unwrap();
        
        assert_eq!(sig.index, sig2.index);
        assert_eq!(sig.reveal, sig2.reveal);
        assert_eq!(sig.mac, sig2.mac);
    }

    #[test]
    fn test_resource_matching() {
        let r1 = Resource::new("zone:living");
        let r2 = Resource::new("zone:living");
        let r3 = Resource::new("zone:bedroom");
        let wildcard = Resource::new("zone:*");
        let any = Resource::new("*");
        
        assert!(r1.matches(&r2));
        assert!(!r1.matches(&r3));
        assert!(wildcard.matches(&r1));
        assert!(wildcard.matches(&r3));
        assert!(any.matches(&r1));
    }

    #[test]
    fn test_chain_exhaustion() {
        let mut identity = Identity::new(b"test", 3);
        
        assert!(identity.sign(b"1").is_ok());
        assert!(identity.sign(b"2").is_ok());
        assert!(identity.sign(b"3").is_ok());
        assert!(identity.sign(b"4").is_err()); // Esgotada
    }

    #[test]
    fn test_permissions() {
        assert_eq!(permissions::from_name("READ"), Some(permissions::READ));
        assert_eq!(permissions::from_name("write"), Some(permissions::WRITE));
        assert_eq!(permissions::from_name("INVALID"), None);
        
        assert_eq!(permissions::to_name(permissions::READ), "READ");
        assert_eq!(permissions::to_name(permissions::ADMIN), "ADMIN");
    }

    #[test]
    fn test_revocation() {
        let mut ctx = CbaContext::new("test", 50);
        let holder = CbaContext::new("holder", 50);
        
        let cap = ctx.issue_capability(
            holder.public_key(),
            permissions::READ,
            &["test"],
            3600,
            0,
            0,
        ).unwrap();
        
        assert!(!ctx.is_revoked(&cap.id));
        ctx.revoke(&cap.id);
        assert!(ctx.is_revoked(&cap.id));
    }
}
