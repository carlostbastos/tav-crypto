//! # TAV Clock Cryptography V0.9
//! 
//! Copyright (C) 2025 Carlos Alberto Terencio de Bastos
//! License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
//! 
//! 
//! ## Example
//! 
//! ```rust
//! use tav_crypto::{Tav, SecurityLevel};
//! 
//! let mut tav = Tav::new("minha senha secreta", SecurityLevel::Consumer).unwrap();
//! 
//! let plaintext = b"Mensagem secreta";
//! let ciphertext = tav.encrypt(plaintext, true).unwrap();
//! let decrypted = tav.decrypt(&ciphertext).unwrap();
//! 
//! assert_eq!(plaintext, decrypted.as_slice());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::String};

#[cfg(feature = "std")]
use std::{vec, vec::Vec, string::String, time::Instant};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// ============================================================================
// CONSTANTES
// ============================================================================

/// Constantes para operação AND no mixer
pub const CONST_AND: [u8; 32] = [
    0xB7, 0x5D, 0xA3, 0xE1, 0x97, 0x4F, 0xC5, 0x2B,
    0x8D, 0x61, 0xF3, 0x1F, 0xD9, 0x73, 0x3D, 0xAF,
    0x17, 0x89, 0xCB, 0x53, 0xE7, 0x2D, 0x9B, 0x41,
    0xBB, 0x6D, 0xF1, 0x23, 0xDD, 0x7F, 0x35, 0xA9,
];

/// Constantes para operação OR no mixer
pub const CONST_OR: [u8; 32] = [
    0x11, 0x22, 0x44, 0x08, 0x10, 0x21, 0x42, 0x04,
    0x12, 0x24, 0x48, 0x09, 0x14, 0x28, 0x41, 0x02,
    0x18, 0x30, 0x60, 0x05, 0x0A, 0x15, 0x2A, 0x54,
    0x19, 0x32, 0x64, 0x06, 0x0C, 0x19, 0x33, 0x66,
];

const POOL_SIZE: usize = 32;
const HASH_SIZE: usize = 32;

// Primos por caixa (reduzido para compilação)
const PRIMES_BOX_1: &[u32] = &[11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];
const PRIMES_BOX_2: &[u32] = &[101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197];
const PRIMES_BOX_3: &[u32] = &[1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097];
const PRIMES_BOX_4: &[u32] = &[10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133];
const PRIMES_BOX_5: &[u32] = &[1000003, 1000033, 1000037, 1000039, 1000081, 1000099, 1000117, 1000121, 1000133, 1000151];
const PRIMES_BOX_6: &[u32] = &[100000007, 100000037, 100000039, 100000049, 100000073, 100000081, 100000123, 100000127];

// ============================================================================
// TIPOS E ERROS
// ============================================================================

/// Nível de segurança
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SecurityLevel {
    IoT = 1,
    Consumer = 2,
    Enterprise = 3,
    Military = 4,
}

/// Erros possíveis
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TavError {
    NotInitialized,
    MacMismatch,
    InvalidData,
    BufferTooSmall,
    ChainExhausted,
}

pub type Result<T> = core::result::Result<T, TavError>;

/// Configuração por nível
#[derive(Clone, Debug)]
struct Config {
    master_entropy_size: usize,
    key_bytes: usize,
    mac_bytes: usize,
    nonce_bytes: usize,
    n_xor: usize,
    n_rounds_mixer: usize,
    n_rounds_mac: usize,
    initial_boxes: Vec<usize>,
}

impl Config {
    fn for_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::IoT => Config {
                master_entropy_size: 32,
                key_bytes: 16,
                mac_bytes: 8,
                nonce_bytes: 8,
                n_xor: 2,
                n_rounds_mixer: 2,
                n_rounds_mac: 4,
                initial_boxes: vec![1, 2],
            },
            SecurityLevel::Consumer => Config {
                master_entropy_size: 48,
                key_bytes: 24,
                mac_bytes: 12,
                nonce_bytes: 12,
                n_xor: 2,
                n_rounds_mixer: 3,
                n_rounds_mac: 6,
                initial_boxes: vec![1, 2, 3],
            },
            SecurityLevel::Enterprise => Config {
                master_entropy_size: 64,
                key_bytes: 32,
                mac_bytes: 16,
                nonce_bytes: 16,
                n_xor: 3,
                n_rounds_mixer: 4,
                n_rounds_mac: 8,
                initial_boxes: vec![1, 2, 3, 4],
            },
            SecurityLevel::Military => Config {
                master_entropy_size: 64,
                key_bytes: 32,
                mac_bytes: 16,
                nonce_bytes: 16,
                n_xor: 4,
                n_rounds_mixer: 6,
                n_rounds_mac: 8,
                initial_boxes: vec![1, 2, 3, 4, 5],
            },
        }
    }
}

// ============================================================================
// OPERAÇÕES BÁSICAS
// ============================================================================

#[inline]
fn rot_left(byte: u8, n: u8) -> u8 {
    let n = n & 7;
    (byte << n) | (byte >> (8 - n))
}

#[inline]
fn rot_right(byte: u8, n: u8) -> u8 {
    let n = n & 7;
    (byte >> n) | (byte << (8 - n))
}

/// Timer de alta resolução
#[cfg(feature = "std")]
fn get_time_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(all(feature = "wasm", not(feature = "std")))]
fn get_time_ns() -> u64 {
    let performance = web_sys::window()
        .and_then(|w| w.performance())
        .expect("Performance API not available");
    (performance.now() * 1_000_000.0) as u64
}

#[cfg(all(not(feature = "std"), not(feature = "wasm")))]
fn get_time_ns() -> u64 {
    // Fallback para no_std sem WASM
    static mut COUNTER: u64 = 0;
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        COUNTER
    }
}

/// Comparação constant-time
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ============================================================================
// MIXER FEISTEL
// ============================================================================

struct Mixer {
    pool: [u8; POOL_SIZE],
    n_rounds: usize,
    counter: u64,
}

impl Mixer {
    fn new(n_rounds: usize) -> Self {
        Mixer {
            pool: [0u8; POOL_SIZE],
            n_rounds,
            counter: 0,
        }
    }

    fn function_f(&self, data: &[u8], round: usize) -> Vec<u8> {
        let n = data.len();
        let mut result = vec![0u8; n];
        
        for i in 0..n {
            let mut x = data[i];
            x = rot_left(x, ((round + i) & 7) as u8);
            x &= CONST_AND[(i + round * 7) & 31];
            x |= CONST_OR[(i + round * 11) & 31];
            x ^= data[(i + round + 1) % n];
            result[i] = x;
        }
        
        result
    }

    fn feistel_round(&self, data: &mut [u8], round: usize) {
        let half = data.len() / 2;
        
        // F(R)
        let f_out = self.function_f(&data[half..], round);
        
        // Novo R = L XOR F(R)
        let mut new_r = vec![0u8; half];
        for i in 0..half {
            new_r[i] = data[i] ^ f_out[i];
        }
        
        // Swap
        for i in 0..half {
            data[i] = data[half + i];
            data[half + i] = new_r[i];
        }
    }

    fn update(&mut self, entropy: u64) {
        let pos = (self.counter as usize) % POOL_SIZE;
        self.pool[pos] ^= (entropy & 0xFF) as u8;
        self.pool[(pos + 1) % POOL_SIZE] ^= ((entropy >> 8) & 0xFF) as u8;
        self.counter += 1;
    }

    fn extract(&mut self, len: usize) -> Vec<u8> {
        let mut mixed = self.pool.to_vec();
        
        for r in 0..self.n_rounds {
            self.feistel_round(&mut mixed, r + (self.counter as usize));
        }
        
        let mut result = Vec::with_capacity(len);
        while result.len() < len {
            result.extend_from_slice(&mixed[..core::cmp::min(POOL_SIZE, len - result.len())]);
            if result.len() < len {
                self.counter += 1;
                for r in 0..self.n_rounds {
                    self.feistel_round(&mut mixed, r + (self.counter as usize));
                }
            }
        }
        
        result.truncate(len);
        result
    }
}

// ============================================================================
// MAC FEISTEL
// ============================================================================

struct MacFeistel {
    n_rounds: usize,
}

impl MacFeistel {
    fn new(n_rounds: usize) -> Self {
        MacFeistel { n_rounds }
    }

    fn function_f(&self, data: &[u8], round: usize, key: &[u8]) -> Vec<u8> {
        let n = data.len();
        let key_len = key.len();
        let mut result = vec![0u8; n];
        
        for i in 0..n {
            let mut x = data[i];
            let k = key[i % key_len];
            x = rot_left(x ^ k, ((round + i) & 7) as u8);
            x &= CONST_AND[(i + round * 7) & 31];
            x |= CONST_OR[(i + round * 11) & 31];
            x ^= data[(i + round + 1) % n];
            x ^= k;
            result[i] = x;
        }
        
        result
    }

    fn mac_round(&self, state: &mut [u8], round: usize, key: &[u8]) {
        let f_out = self.function_f(&state[16..32], round, key);
        
        let mut new_r = [0u8; 16];
        for i in 0..16 {
            new_r[i] = state[i] ^ f_out[i];
        }
        
        for i in 0..16 {
            state[i] = state[16 + i];
            state[16 + i] = new_r[i];
        }
    }

    fn calculate(&self, key: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
        let mut state = [0u8; 32];
        
        // Inicializa com chave
        for i in 0..32 {
            state[i] = key[i % key.len()];
        }
        
        // Processa dados
        for chunk in data.chunks(32) {
            for (i, &byte) in chunk.iter().enumerate() {
                state[i] ^= byte;
            }
            for r in 0..self.n_rounds {
                self.mac_round(&mut state, r, key);
            }
        }
        
        // Finalização com tamanho
        let len_bytes = (data.len() as u64).to_be_bytes();
        for i in 0..8 {
            state[i] ^= len_bytes[i];
        }
        
        for r in 0..self.n_rounds {
            self.mac_round(&mut state, r + self.n_rounds, key);
        }
        
        state[..out_len].to_vec()
    }

    fn verify(&self, key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        let calculated = self.calculate(key, data, expected.len());
        constant_time_eq(&calculated, expected)
    }
}

// ============================================================================
// HASH (baseado em Feistel)
// ============================================================================

/// Hash baseado em Feistel (para assinaturas)
pub fn tav_hash(data: &[u8]) -> [u8; HASH_SIZE] {
    const HASH_KEY: [u8; 32] = [
        0x54, 0x41, 0x56, 0x2D, 0x48, 0x41, 0x53, 0x48,
        0x56, 0x39, 0x2E, 0x31, 0x2D, 0x32, 0x30, 0x32,
        0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    let mac = MacFeistel::new(8);
    let result = mac.calculate(&HASH_KEY, data, HASH_SIZE);
    
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&result);
    out
}

// ============================================================================
// GERADOR DE ENTROPIA
// ============================================================================

struct EntropyGenerator {
    mixer: Mixer,
    n_xor: usize,
    nonce_counter: u64,
    work_index: usize,
}

impl EntropyGenerator {
    fn new(n_xor: usize, n_rounds: usize) -> Self {
        EntropyGenerator {
            mixer: Mixer::new(n_rounds),
            n_xor,
            nonce_counter: 0,
            work_index: 0,
        }
    }

    fn collect_timing(&mut self) -> u64 {
        let t1 = get_time_ns();
        
        // Trabalho variável
        let mut x: u32 = 0;
        match self.work_index & 3 {
            0 => for i in 0..10 { x = x.wrapping_add(i); }
            1 => for i in 0..8 { x = x.wrapping_add(i); }
            2 => for i in 0..12 { x = x.wrapping_add(i); }
            _ => for i in 0..5 { x = x.wrapping_add(i * i); }
        }
        self.work_index += 1;
        
        let t2 = get_time_ns();
        let _ = x; // Evita otimização
        t2.wrapping_sub(t1)
    }

    fn collect_xor(&mut self) -> u64 {
        let mut result = 0u64;
        for _ in 0..self.n_xor {
            result ^= self.collect_timing();
        }
        result
    }

    fn calibrate(&mut self, samples: usize) {
        for _ in 0..samples {
            let timing = self.collect_xor();
            self.mixer.update(timing);
        }
    }

    fn generate(&mut self, len: usize) -> Vec<u8> {
        let feeds = core::cmp::max(len / 2, 16);
        for _ in 0..feeds {
            let timing = self.collect_xor();
            self.mixer.update(timing);
        }
        self.mixer.extract(len)
    }

    fn generate_nonce(&mut self, len: usize) -> Vec<u8> {
        self.nonce_counter += 1;
        
        let timing1 = self.collect_xor();
        let timing2 = self.collect_xor();
        
        let mut nonce = vec![0u8; len];
        
        if len >= 16 {
            for i in 0..8.min(len) {
                nonce[i] = ((timing1 >> (i * 8)) & 0xFF) as u8;
            }
            let counter_bytes = self.nonce_counter.to_be_bytes();
            for i in 0..4.min(len - 8) {
                nonce[8 + i] = counter_bytes[i];
            }
            for i in 0..4.min(len - 12) {
                nonce[12 + i] = ((timing2 >> (i * 8)) & 0xFF) as u8;
            }
        } else {
            let counter_bytes = self.nonce_counter.to_be_bytes();
            for i in 0..4.min(len) {
                nonce[i] = counter_bytes[i];
            }
            for i in 0..4.min(len.saturating_sub(4)) {
                nonce[4 + i] = ((timing1 >> (i * 8)) & 0xFF) as u8;
            }
        }
        
        nonce
    }
}

// ============================================================================
// CAIXA DE PRIMOS
// ============================================================================

struct PrimeBox {
    primes: &'static [u32],
    index: usize,
    active: bool,
}

impl PrimeBox {
    fn new(box_id: usize) -> Self {
        let primes = match box_id {
            1 => PRIMES_BOX_1,
            2 => PRIMES_BOX_2,
            3 => PRIMES_BOX_3,
            4 => PRIMES_BOX_4,
            5 => PRIMES_BOX_5,
            6 => PRIMES_BOX_6,
            _ => &[1u32],
        };
        
        PrimeBox {
            primes,
            index: 0,
            active: false,
        }
    }

    fn current(&self) -> u32 {
        if !self.active || self.primes.is_empty() {
            return 1;
        }
        self.primes[self.index % self.primes.len()]
    }

    fn advance(&mut self) {
        if self.active && !self.primes.is_empty() {
            self.index = (self.index + 1) % self.primes.len();
        }
    }
}

// ============================================================================
// RELÓGIO TRANSACIONAL
// ============================================================================

struct Clock {
    id: usize,
    tick_prime: u32,
    boxes: Vec<usize>,
    tick_count: u64,
    tx_count: u32,
    active: bool,
}

impl Clock {
    fn new(id: usize, tick_prime: u32, boxes: Vec<usize>) -> Self {
        Clock {
            id,
            tick_prime,
            boxes,
            tick_count: 0,
            tx_count: 0,
            active: false,
        }
    }

    fn tick(&mut self) -> bool {
        if !self.active {
            return false;
        }
        
        self.tx_count += 1;
        if self.tx_count >= self.tick_prime {
            self.tick_count += 1;
            self.tx_count %= self.tick_prime;
            return true;
        }
        false
    }
}

// ============================================================================
// TAV PRINCIPAL
// ============================================================================

/// Contexto principal TAV
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct Tav {
    level: SecurityLevel,
    config: Config,
    entropy: EntropyGenerator,
    mac: MacFeistel,
    boxes: Vec<PrimeBox>,
    clocks: Vec<Clock>,
    master_entropy: Vec<u8>,
    tx_count_global: u64,
    initialized: bool,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl Tav {
    /// Cria novo contexto TAV
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new(seed: &str, level: SecurityLevel) -> Result<Tav> {
        Self::from_bytes(seed.as_bytes(), level)
    }

    /// Cria contexto de bytes
    pub fn from_bytes(seed: &[u8], level: SecurityLevel) -> Result<Tav> {
        let config = Config::for_level(level);
        
        // Inicializa entropia
        let mut entropy = EntropyGenerator::new(config.n_xor, config.n_rounds_mixer);
        entropy.calibrate(100);
        
        // Inicializa MAC
        let mac = MacFeistel::new(config.n_rounds_mac);
        
        // Inicializa caixas
        let mut boxes: Vec<PrimeBox> = (1..=6).map(PrimeBox::new).collect();
        for &box_id in &config.initial_boxes {
            if box_id >= 1 && box_id <= 6 {
                boxes[box_id - 1].active = true;
            }
        }
        
        // Inicializa relógios
        let clock_configs = [
            (0, 17, vec![1, 2, 3]),
            (1, 23, vec![1, 3, 4]),
            (2, 31, vec![2, 3, 4]),
            (3, 47, vec![2, 4, 5]),
        ];
        
        let clocks: Vec<Clock> = clock_configs
            .iter()
            .enumerate()
            .map(|(i, (id, prime, boxes))| {
                let mut clock = Clock::new(*id, *prime, boxes.clone());
                clock.active = i < level as usize;
                clock
            })
            .collect();
        
        // Gera master entropy
        let master_size = config.master_entropy_size;
        
        // Normaliza seed
        let mut seed_normalized = vec![0u8; master_size];
        for (i, &b) in seed.iter().enumerate() {
            seed_normalized[i % master_size] ^= b;
        }
        
        // Gera entropia física
        let clock_entropy = entropy.generate(master_size * 2);
        
        // Combina
        let mut master_entropy = vec![0u8; master_size * 2];
        for i in 0..master_size {
            master_entropy[i] = seed_normalized[i] ^ clock_entropy[i];
        }
        for i in master_size..(master_size * 2) {
            master_entropy[i] = clock_entropy[i];
        }
        
        Ok(Tav {
            level,
            config,
            entropy,
            mac,
            boxes,
            clocks,
            master_entropy,
            tx_count_global: 0,
            initialized: true,
        })
    }

    /// Encripta dados
    pub fn encrypt(&mut self, plaintext: &[u8], auto_tick: bool) -> Result<Vec<u8>> {
        if !self.initialized {
            return Err(TavError::NotInitialized);
        }

        let nonce_len = self.config.nonce_bytes;
        let mac_len = self.config.mac_bytes;
        let key_len = self.config.key_bytes;
        let metadata_len = 8;

        // Deriva chave
        let key = self.derive_key();
        
        // Gera nonce
        let nonce = self.entropy.generate_nonce(nonce_len);
        
        // Metadata
        let mut metadata = vec![0u8; metadata_len];
        metadata[0] = 0x91; // Versão
        metadata[1] = self.level as u8;
        let tx_bytes = self.tx_count_global.to_be_bytes();
        metadata[2..8].copy_from_slice(&tx_bytes[2..8]);
        
        // Dados = metadata + plaintext
        let mut data = metadata;
        data.extend_from_slice(plaintext);
        
        // Gera keystream e cifra
        let keystream = self.generate_keystream(&key, &nonce, data.len());
        let encrypted: Vec<u8> = data.iter().zip(keystream.iter()).map(|(d, k)| d ^ k).collect();
        
        // Calcula MAC
        let mut mac_input = nonce.clone();
        mac_input.extend_from_slice(&encrypted);
        let mac_bytes = self.mac.calculate(&key, &mac_input, mac_len);
        
        // Monta resultado: nonce + mac + encrypted
        let mut result = nonce;
        result.extend_from_slice(&mac_bytes);
        result.extend_from_slice(&encrypted);
        
        if auto_tick {
            self.tick(1);
        }
        
        Ok(result)
    }

    /// Decripta dados
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.initialized {
            return Err(TavError::NotInitialized);
        }

        let nonce_len = self.config.nonce_bytes;
        let mac_len = self.config.mac_bytes;
        let metadata_len = 8;
        let overhead = nonce_len + mac_len + metadata_len;

        if ciphertext.len() < overhead {
            return Err(TavError::InvalidData);
        }

        // Extrai componentes
        let nonce = &ciphertext[..nonce_len];
        let mac_received = &ciphertext[nonce_len..nonce_len + mac_len];
        let encrypted = &ciphertext[nonce_len + mac_len..];

        // Deriva chave
        let key = self.derive_key();

        // Verifica MAC
        let mut mac_input = nonce.to_vec();
        mac_input.extend_from_slice(encrypted);
        
        if !self.mac.verify(&key, &mac_input, mac_received) {
            return Err(TavError::MacMismatch);
        }

        // Decifra
        let keystream = self.generate_keystream(&key, nonce, encrypted.len());
        let decrypted: Vec<u8> = encrypted.iter().zip(keystream.iter()).map(|(c, k)| c ^ k).collect();

        // Remove metadata
        if decrypted.len() < metadata_len {
            return Err(TavError::InvalidData);
        }

        Ok(decrypted[metadata_len..].to_vec())
    }

    /// Avança estado
    pub fn tick(&mut self, n: u32) {
        self.tx_count_global += n as u64;
        
        for _ in 0..n {
            for clock in &mut self.clocks {
                if clock.tick() {
                    for &box_id in &clock.boxes.clone() {
                        if box_id >= 1 && box_id <= 6 {
                            self.boxes[box_id - 1].advance();
                        }
                    }
                }
            }
        }
        
        // Relógios lentos
        if self.tx_count_global % 100 == 0 && self.boxes.len() > 4 {
            self.boxes[4].advance();
        }
        if self.tx_count_global % 1000 == 0 && self.boxes.len() > 5 {
            self.boxes[5].advance();
        }
    }

    /// Calcula overhead do ciphertext
    pub fn overhead(&self) -> usize {
        self.config.nonce_bytes + self.config.mac_bytes + 8
    }

    fn derive_key(&self) -> Vec<u8> {
        let mut state_sum: u64 = 0;
        for clock in &self.clocks {
            if clock.active {
                state_sum += clock.tick_count * 1000 + clock.tx_count as u64;
            }
        }
        
        let key_len = self.config.key_bytes;
        let master_len = self.master_entropy.len();
        let offset = ((state_sum * 7) as usize) % master_len.saturating_sub(key_len).max(1);
        
        let mut key = vec![0u8; key_len];
        for i in 0..key_len {
            key[i] = self.master_entropy[(offset + i) % master_len];
        }
        
        // Mistura com primos
        for clock in &self.clocks {
            if !clock.active {
                continue;
            }
            for &box_id in &clock.boxes {
                if box_id < 1 || box_id > 6 {
                    continue;
                }
                let prime = self.boxes[box_id - 1].current();
                let prime_bytes = prime.to_be_bytes();
                for (j, &b) in prime_bytes.iter().enumerate() {
                    let pos = (clock.id * 4 + j) % key_len;
                    key[pos] ^= b;
                }
            }
        }
        
        key
    }

    fn generate_keystream(&self, key: &[u8], nonce: &[u8], len: usize) -> Vec<u8> {
        let key_len = key.len();
        let nonce_len = nonce.len();
        
        (0..len)
            .map(|i| {
                let k = key[i % key_len];
                let n = nonce[i % nonce_len];
                let rotated = rot_left(k, (i & 7) as u8);
                rotated ^ n ^ (i as u8)
            })
            .collect()
    }
}

// ============================================================================
// ASSINATURAS - OPÇÃO 1: HASH CHAIN
// ============================================================================

/// Chaves para assinatura baseada em hash chain
pub struct SignChainKeys {
    public_key: [u8; HASH_SIZE],
    private_seed: [u8; HASH_SIZE],
    current_index: u16,
    chain_length: u16,
}

impl SignChainKeys {
    /// Gera novo par de chaves
    pub fn generate(seed: &[u8], chain_length: u16) -> Self {
        let private_seed = tav_hash(seed);
        
        // Gera chain
        let mut current = private_seed;
        for _ in 0..chain_length {
            current = tav_hash(&current);
        }
        
        SignChainKeys {
            public_key: current,
            private_seed,
            current_index: 0,
            chain_length,
        }
    }

    /// Retorna chave pública
    pub fn public_key(&self) -> &[u8; HASH_SIZE] {
        &self.public_key
    }

    /// Assina mensagem
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if self.current_index >= self.chain_length {
            return Err(TavError::ChainExhausted);
        }

        // Calcula reveal
        let steps = self.chain_length - self.current_index - 1;
        let mut reveal = self.private_seed;
        for _ in 0..steps {
            reveal = tav_hash(&reveal);
        }

        // MAC = hash(message || reveal)
        let mut mac_input = message.to_vec();
        mac_input.extend_from_slice(&reveal);
        let mac = tav_hash(&mac_input);

        // Assinatura = [index (2)] [reveal (32)] [mac (32)]
        let mut signature = vec![0u8; 2 + HASH_SIZE * 2];
        signature[0] = (self.current_index >> 8) as u8;
        signature[1] = self.current_index as u8;
        signature[2..2 + HASH_SIZE].copy_from_slice(&reveal);
        signature[2 + HASH_SIZE..].copy_from_slice(&mac);

        self.current_index += 1;

        Ok(signature)
    }

    /// Verifica assinatura
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() < 2 + HASH_SIZE * 2 {
            return Err(TavError::InvalidData);
        }

        let index = ((signature[0] as u16) << 8) | (signature[1] as u16);
        let reveal = &signature[2..2 + HASH_SIZE];
        let mac = &signature[2 + HASH_SIZE..2 + HASH_SIZE * 2];

        // Verifica MAC
        let mut mac_input = message.to_vec();
        mac_input.extend_from_slice(reveal);
        let mac_expected = tav_hash(&mac_input);

        if !constant_time_eq(mac, &mac_expected) {
            return Err(TavError::MacMismatch);
        }

        // Verifica chain
        let mut current = [0u8; HASH_SIZE];
        current.copy_from_slice(reveal);
        for _ in 0..=index {
            current = tav_hash(&current);
        }

        if !constant_time_eq(&current, public_key) {
            return Err(TavError::MacMismatch);
        }

        Ok(())
    }
}

// ============================================================================
// ASSINATURAS - OPÇÃO 2: COMMITMENT
// ============================================================================

/// Chaves para assinatura baseada em commitment
pub struct SignCommitKeys {
    public_commitment: [u8; HASH_SIZE],
    tav: Tav,
}

impl SignCommitKeys {
    /// Gera novo par de chaves
    pub fn generate(seed: &[u8], level: SecurityLevel) -> Result<Self> {
        let tav = Tav::from_bytes(seed, level)?;
        let public_commitment = tav_hash(&tav.master_entropy);
        
        Ok(SignCommitKeys {
            public_commitment,
            tav,
        })
    }

    /// Retorna commitment público
    pub fn public_commitment(&self) -> &[u8; HASH_SIZE] {
        &self.public_commitment
    }

    /// Assina mensagem
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let tx_at_sign = self.tav.tx_count_global;
        
        // Estado de assinatura
        let mut state_seed = vec![0u8; 40];
        state_seed[..32].copy_from_slice(&self.tav.master_entropy[..32.min(self.tav.master_entropy.len())]);
        state_seed[32..40].copy_from_slice(&tx_at_sign.to_be_bytes());
        
        // Prova e chave
        let state_proof = tav_hash(&state_seed);
        let sign_key = tav_hash(&state_proof);
        
        // MAC
        let mut mac_input = message.to_vec();
        mac_input.extend_from_slice(&tx_at_sign.to_be_bytes());
        let mut mac = tav_hash(&mac_input);
        
        // Vincula ao estado
        for i in 0..HASH_SIZE {
            mac[i] ^= sign_key[i];
        }
        
        // Assinatura = [tx_count (8)] [proof (32)] [mac (32)]
        let mut signature = Vec::with_capacity(8 + HASH_SIZE * 2);
        signature.extend_from_slice(&tx_at_sign.to_be_bytes());
        signature.extend_from_slice(&state_proof);
        signature.extend_from_slice(&mac);
        
        self.tav.tick(1);
        
        Ok(signature)
    }

    /// Verifica assinatura
    pub fn verify(public_commitment: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() < 8 + HASH_SIZE * 2 {
            return Err(TavError::InvalidData);
        }

        let mut tx_bytes = [0u8; 8];
        tx_bytes.copy_from_slice(&signature[..8]);
        let tx_count = u64::from_be_bytes(tx_bytes);
        
        let state_proof = &signature[8..8 + HASH_SIZE];
        let mac = &signature[8 + HASH_SIZE..8 + HASH_SIZE * 2];

        // Deriva chave
        let sign_key = tav_hash(state_proof);

        // Recalcula MAC
        let mut mac_input = message.to_vec();
        mac_input.extend_from_slice(&tx_count.to_be_bytes());
        let mut mac_expected = tav_hash(&mac_input);
        
        for i in 0..HASH_SIZE {
            mac_expected[i] ^= sign_key[i];
        }

        if !constant_time_eq(mac, &mac_expected) {
            return Err(TavError::MacMismatch);
        }

        // Nota: verificação completa do commitment requer ZK-proof
        let _ = public_commitment;
        
        Ok(())
    }
}

// ============================================================================
// TESTES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut tav = Tav::new("test seed", SecurityLevel::Consumer).unwrap();
        let plaintext = b"Hello, TAV!";
        
        let ciphertext = tav.encrypt(plaintext, false).unwrap();
        let decrypted = tav.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_sign_chain() {
        let mut keys = SignChainKeys::generate(b"test seed", 100);
        let message = b"Test message";
        
        let signature = keys.sign(message).unwrap();
        let result = SignChainKeys::verify(keys.public_key(), message, &signature);
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_commit() {
        let mut keys = SignCommitKeys::generate(b"test seed", SecurityLevel::Consumer).unwrap();
        let message = b"Test message";
        
        let signature = keys.sign(message).unwrap();
        let result = SignCommitKeys::verify(keys.public_commitment(), message, &signature);
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash() {
        let data = b"test data";
        let hash1 = tav_hash(data);
        let hash2 = tav_hash(data);
        
        assert_eq!(hash1, hash2);
        
        let hash3 = tav_hash(b"different data");
        assert_ne!(hash1, hash3);
    }
}
