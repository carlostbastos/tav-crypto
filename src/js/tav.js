/*
 * TAV Clock Cryptography v9.1
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/caterencio/tav-crypto
 */

/**
 * TAV Clock Cryptography V9.1 - JavaScript Implementation
 * ========================================================
 * 
 * Sistema criptográfico baseado em física de processador.
 * Operações: apenas XOR, AND, OR, ROT (portas lógicas)
 * 
 */

// ============================================================================
// CONSTANTES
// ============================================================================

const CONST_AND = new Uint8Array([
    0xB7, 0x5D, 0xA3, 0xE1, 0x97, 0x4F, 0xC5, 0x2B,
    0x8D, 0x61, 0xF3, 0x1F, 0xD9, 0x73, 0x3D, 0xAF,
    0x17, 0x89, 0xCB, 0x53, 0xE7, 0x2D, 0x9B, 0x41,
    0xBB, 0x6D, 0xF1, 0x23, 0xDD, 0x7F, 0x35, 0xA9
]);

const CONST_OR = new Uint8Array([
    0x11, 0x22, 0x44, 0x08, 0x10, 0x21, 0x42, 0x04,
    0x12, 0x24, 0x48, 0x09, 0x14, 0x28, 0x41, 0x02,
    0x18, 0x30, 0x60, 0x05, 0x0A, 0x15, 0x2A, 0x54,
    0x19, 0x32, 0x64, 0x06, 0x0C, 0x19, 0x33, 0x66
]);

const POOL_SIZE = 32;
const HASH_SIZE = 32;

// Primos por caixa
const PRIMES = {
    1: [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97],
    2: [101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197],
    3: [1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097],
    4: [10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133],
    5: [1000003, 1000033, 1000037, 1000039, 1000081, 1000099, 1000117, 1000121, 1000133, 1000151],
    6: [100000007, 100000037, 100000039, 100000049, 100000073, 100000081, 100000123, 100000127]
};

// Configurações por nível
const CONFIGS = {
    1: { // IoT
        masterEntropySize: 32, keyBytes: 16, macBytes: 8, nonceBytes: 8,
        nXor: 2, nRoundsMixer: 2, nRoundsMac: 4, initialBoxes: [1, 2]
    },
    2: { // Consumer
        masterEntropySize: 48, keyBytes: 24, macBytes: 12, nonceBytes: 12,
        nXor: 2, nRoundsMixer: 3, nRoundsMac: 6, initialBoxes: [1, 2, 3]
    },
    3: { // Enterprise
        masterEntropySize: 64, keyBytes: 32, macBytes: 16, nonceBytes: 16,
        nXor: 3, nRoundsMixer: 4, nRoundsMac: 8, initialBoxes: [1, 2, 3, 4]
    },
    4: { // Military
        masterEntropySize: 64, keyBytes: 32, macBytes: 16, nonceBytes: 16,
        nXor: 4, nRoundsMixer: 6, nRoundsMac: 8, initialBoxes: [1, 2, 3, 4, 5]
    }
};

const CLOCK_CONFIGS = [
    { id: 0, tickPrime: 17, boxes: [1, 2, 3] },
    { id: 1, tickPrime: 23, boxes: [1, 3, 4] },
    { id: 2, tickPrime: 31, boxes: [2, 3, 4] },
    { id: 3, tickPrime: 47, boxes: [2, 4, 5] }
];

// ============================================================================
// NÍVEIS DE SEGURANÇA
// ============================================================================

const SecurityLevel = {
    IoT: 1,
    Consumer: 2,
    Enterprise: 3,
    Military: 4
};

// ============================================================================
// FUNÇÕES AUXILIARES
// ============================================================================

function rotLeft(byte, n) {
    n = n & 7;
    return ((byte << n) | (byte >>> (8 - n))) & 0xFF;
}

function rotRight(byte, n) {
    n = n & 7;
    return ((byte >>> n) | (byte << (8 - n))) & 0xFF;
}

function getTimeNs() {
    if (typeof performance !== 'undefined') {
        return BigInt(Math.floor(performance.now() * 1000000));
    }
    return BigInt(Date.now() * 1000000);
}

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

function bytesToString(bytes) {
    return new TextDecoder().decode(bytes);
}

function concatBytes(...arrays) {
    const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

function numberToBytes(num, len = 8) {
    const bytes = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) {
        bytes[i] = num & 0xFF;
        num = Math.floor(num / 256);
    }
    return bytes;
}

function bytesToNumber(bytes) {
    let num = 0;
    for (let i = 0; i < bytes.length; i++) {
        num = num * 256 + bytes[i];
    }
    return num;
}

// ============================================================================
// MIXER FEISTEL
// ============================================================================

class MixerFeistel {
    constructor(nRounds = 3) {
        this.pool = new Uint8Array(POOL_SIZE);
        this.nRounds = nRounds;
        this.counter = 0n;
    }

    functionF(data, round) {
        const n = data.length;
        const result = new Uint8Array(n);
        
        for (let i = 0; i < n; i++) {
            let x = data[i];
            x = rotLeft(x, (round + i) & 7);
            x = x & CONST_AND[(i + round * 7) & 31];
            x = x | CONST_OR[(i + round * 11) & 31];
            x = x ^ data[(i + round + 1) % n];
            result[i] = x;
        }
        
        return result;
    }

    feistelRound(data, round) {
        const half = data.length / 2;
        const L = data.slice(0, half);
        const R = data.slice(half);
        
        const fOut = this.functionF(R, round);
        
        const newR = new Uint8Array(half);
        for (let i = 0; i < half; i++) {
            newR[i] = L[i] ^ fOut[i];
        }
        
        // Swap
        data.set(R, 0);
        data.set(newR, half);
    }

    update(entropy) {
        const pos = Number(this.counter % BigInt(POOL_SIZE));
        this.pool[pos] ^= Number(entropy & 0xFFn);
        this.pool[(pos + 1) % POOL_SIZE] ^= Number((entropy >> 8n) & 0xFFn);
        this.counter++;
    }

    extract(len) {
        const mixed = new Uint8Array(this.pool);
        
        for (let r = 0; r < this.nRounds; r++) {
            this.feistelRound(mixed, r + Number(this.counter & 0xFFFFFFFFn));
        }
        
        const result = new Uint8Array(len);
        let offset = 0;
        while (offset < len) {
            const chunk = Math.min(POOL_SIZE, len - offset);
            result.set(mixed.slice(0, chunk), offset);
            offset += chunk;
            
            if (offset < len) {
                this.counter++;
                for (let r = 0; r < this.nRounds; r++) {
                    this.feistelRound(mixed, r + Number(this.counter & 0xFFFFFFFFn));
                }
            }
        }
        
        return result;
    }
}

// ============================================================================
// MAC FEISTEL
// ============================================================================

class MacFeistel {
    constructor(nRounds = 6) {
        this.nRounds = nRounds;
    }

    functionF(data, round, key) {
        const n = data.length;
        const keyLen = key.length;
        const result = new Uint8Array(n);
        
        for (let i = 0; i < n; i++) {
            let x = data[i];
            const k = key[i % keyLen];
            x = rotLeft(x ^ k, (round + i) & 7);
            x = x & CONST_AND[(i + round * 7) & 31];
            x = x | CONST_OR[(i + round * 11) & 31];
            x = x ^ data[(i + round + 1) % n];
            x = x ^ k;
            result[i] = x;
        }
        
        return result;
    }

    macRound(state, round, key) {
        const fOut = this.functionF(state.slice(16, 32), round, key);
        
        const newR = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            newR[i] = state[i] ^ fOut[i];
        }
        
        state.set(state.slice(16, 32), 0);
        state.set(newR, 16);
    }

    calculate(key, data, outLen) {
        const state = new Uint8Array(32);
        
        // Inicializa com chave
        for (let i = 0; i < 32; i++) {
            state[i] = key[i % key.length];
        }
        
        // Processa dados em blocos de 32
        for (let offset = 0; offset < data.length; offset += 32) {
            const chunk = data.slice(offset, Math.min(offset + 32, data.length));
            for (let i = 0; i < chunk.length; i++) {
                state[i] ^= chunk[i];
            }
            for (let r = 0; r < this.nRounds; r++) {
                this.macRound(state, r, key);
            }
        }
        
        // Finalização com tamanho
        const lenBytes = numberToBytes(data.length, 8);
        for (let i = 0; i < 8; i++) {
            state[i] ^= lenBytes[i];
        }
        
        for (let r = 0; r < this.nRounds; r++) {
            this.macRound(state, r + this.nRounds, key);
        }
        
        return state.slice(0, outLen);
    }

    verify(key, data, expected) {
        const calculated = this.calculate(key, data, expected.length);
        return constantTimeEqual(calculated, expected);
    }
}

// ============================================================================
// HASH
// ============================================================================

const HASH_KEY = new Uint8Array([
    0x54, 0x41, 0x56, 0x2D, 0x48, 0x41, 0x53, 0x48,
    0x56, 0x39, 0x2E, 0x31, 0x2D, 0x32, 0x30, 0x32,
    0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]);

function tavHash(data) {
    const mac = new MacFeistel(8);
    return mac.calculate(HASH_KEY, data, HASH_SIZE);
}

// ============================================================================
// GERADOR DE ENTROPIA
// ============================================================================

class EntropyGenerator {
    constructor(nXor, nRounds) {
        this.mixer = new MixerFeistel(nRounds);
        this.nXor = nXor;
        this.nonceCounter = 0n;
        this.workIndex = 0;
    }

    collectTiming() {
        const t1 = getTimeNs();
        
        // Trabalho variável
        let x = 0;
        switch (this.workIndex & 3) {
            case 0: for (let i = 0; i < 10; i++) x += i; break;
            case 1: for (let i = 0; i < 8; i++) x += i; break;
            case 2: for (let i = 0; i < 12; i++) x += i; break;
            default: for (let i = 0; i < 5; i++) x += i * i; break;
        }
        this.workIndex++;
        
        const t2 = getTimeNs();
        return t2 - t1;
    }

    collectXor() {
        let result = 0n;
        for (let i = 0; i < this.nXor; i++) {
            result ^= this.collectTiming();
        }
        return result;
    }

    calibrate(samples = 100) {
        for (let i = 0; i < samples; i++) {
            const timing = this.collectXor();
            this.mixer.update(timing);
        }
    }

    generate(len) {
        const feeds = Math.max(Math.floor(len / 2), 16);
        for (let i = 0; i < feeds; i++) {
            const timing = this.collectXor();
            this.mixer.update(timing);
        }
        return this.mixer.extract(len);
    }

    generateNonce(len) {
        this.nonceCounter++;
        
        const timing1 = this.collectXor();
        const timing2 = this.collectXor();
        
        const nonce = new Uint8Array(len);
        
        if (len >= 16) {
            for (let i = 0; i < 8 && i < len; i++) {
                nonce[i] = Number((timing1 >> BigInt(i * 8)) & 0xFFn);
            }
            const counterBytes = numberToBytes(Number(this.nonceCounter & 0xFFFFFFFFn), 4);
            for (let i = 0; i < 4 && 8 + i < len; i++) {
                nonce[8 + i] = counterBytes[i];
            }
            for (let i = 0; i < 4 && 12 + i < len; i++) {
                nonce[12 + i] = Number((timing2 >> BigInt(i * 8)) & 0xFFn);
            }
        } else {
            const counterBytes = numberToBytes(Number(this.nonceCounter & 0xFFFFFFFFn), 4);
            for (let i = 0; i < 4 && i < len; i++) {
                nonce[i] = counterBytes[i];
            }
            for (let i = 0; i < 4 && 4 + i < len; i++) {
                nonce[4 + i] = Number((timing1 >> BigInt(i * 8)) & 0xFFn);
            }
        }
        
        return nonce;
    }
}

// ============================================================================
// CAIXA DE PRIMOS
// ============================================================================

class PrimeBox {
    constructor(boxId) {
        this.primes = PRIMES[boxId] || [1];
        this.index = 0;
        this.active = false;
    }

    current() {
        if (!this.active || this.primes.length === 0) return 1;
        return this.primes[this.index % this.primes.length];
    }

    advance() {
        if (this.active && this.primes.length > 0) {
            this.index = (this.index + 1) % this.primes.length;
        }
    }
}

// ============================================================================
// RELÓGIO
// ============================================================================

class Clock {
    constructor(id, tickPrime, boxes) {
        this.id = id;
        this.tickPrime = tickPrime;
        this.boxes = boxes;
        this.tickCount = 0;
        this.txCount = 0;
        this.active = false;
    }

    tick() {
        if (!this.active) return false;
        
        this.txCount++;
        if (this.txCount >= this.tickPrime) {
            this.tickCount++;
            this.txCount = this.txCount % this.tickPrime;
            return true;
        }
        return false;
    }
}

// ============================================================================
// TAV PRINCIPAL
// ============================================================================

class Tav {
    /**
     * Cria nova instância TAV
     * @param {string|Uint8Array} seed - Seed (string ou bytes)
     * @param {number} level - Nível de segurança (1-4)
     */
    constructor(seed, level = SecurityLevel.Consumer) {
        if (typeof seed === 'string') {
            seed = stringToBytes(seed);
        }
        
        this.level = level;
        this.config = CONFIGS[level];
        
        // Entropia
        this.entropy = new EntropyGenerator(this.config.nXor, this.config.nRoundsMixer);
        this.entropy.calibrate(100);
        
        // MAC
        this.mac = new MacFeistel(this.config.nRoundsMac);
        
        // Caixas
        this.boxes = {};
        for (let i = 1; i <= 6; i++) {
            this.boxes[i] = new PrimeBox(i);
        }
        for (const boxId of this.config.initialBoxes) {
            this.boxes[boxId].active = true;
        }
        
        // Relógios
        this.clocks = CLOCK_CONFIGS.map((cfg, i) => {
            const clock = new Clock(cfg.id, cfg.tickPrime, cfg.boxes);
            clock.active = i < level;
            return clock;
        });
        
        // Master entropy
        const masterSize = this.config.masterEntropySize;
        
        const seedNormalized = new Uint8Array(masterSize);
        for (let i = 0; i < seed.length; i++) {
            seedNormalized[i % masterSize] ^= seed[i];
        }
        
        const clockEntropy = this.entropy.generate(masterSize * 2);
        
        this.masterEntropy = new Uint8Array(masterSize * 2);
        for (let i = 0; i < masterSize; i++) {
            this.masterEntropy[i] = seedNormalized[i] ^ clockEntropy[i];
        }
        for (let i = masterSize; i < masterSize * 2; i++) {
            this.masterEntropy[i] = clockEntropy[i];
        }
        
        this.txCountGlobal = 0;
        this.initialized = true;
    }

    /**
     * Encripta dados
     * @param {Uint8Array|string} plaintext - Dados a encriptar
     * @param {boolean} autoTick - Se deve avançar estado após encrypt
     * @returns {Uint8Array} Ciphertext
     */
    encrypt(plaintext, autoTick = true) {
        if (typeof plaintext === 'string') {
            plaintext = stringToBytes(plaintext);
        }
        
        const nonceLen = this.config.nonceBytes;
        const macLen = this.config.macBytes;
        const keyLen = this.config.keyBytes;
        const metadataLen = 8;
        
        // Deriva chave
        const key = this.deriveKey();
        
        // Gera nonce
        const nonce = this.entropy.generateNonce(nonceLen);
        
        // Metadata
        const metadata = new Uint8Array(metadataLen);
        metadata[0] = 0x91;
        metadata[1] = this.level;
        const txBytes = numberToBytes(this.txCountGlobal, 6);
        metadata.set(txBytes, 2);
        
        // Dados = metadata + plaintext
        const data = concatBytes(metadata, plaintext);
        
        // Keystream e cifra
        const keystream = this.generateKeystream(key, nonce, data.length);
        const encrypted = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            encrypted[i] = data[i] ^ keystream[i];
        }
        
        // MAC
        const macInput = concatBytes(nonce, encrypted);
        const macBytes = this.mac.calculate(key, macInput, macLen);
        
        // Resultado
        const result = concatBytes(nonce, macBytes, encrypted);
        
        if (autoTick) {
            this.tick(1);
        }
        
        return result;
    }

    /**
     * Decripta dados
     * @param {Uint8Array} ciphertext - Dados a decriptar
     * @returns {Uint8Array} Plaintext
     */
    decrypt(ciphertext) {
        const nonceLen = this.config.nonceBytes;
        const macLen = this.config.macBytes;
        const metadataLen = 8;
        const overhead = nonceLen + macLen + metadataLen;
        
        if (ciphertext.length < overhead) {
            throw new Error('Invalid ciphertext');
        }
        
        const nonce = ciphertext.slice(0, nonceLen);
        const macReceived = ciphertext.slice(nonceLen, nonceLen + macLen);
        const encrypted = ciphertext.slice(nonceLen + macLen);
        
        // Deriva chave
        const key = this.deriveKey();
        
        // Verifica MAC
        const macInput = concatBytes(nonce, encrypted);
        if (!this.mac.verify(key, macInput, macReceived)) {
            throw new Error('MAC mismatch - data may be corrupted');
        }
        
        // Decifra
        const keystream = this.generateKeystream(key, nonce, encrypted.length);
        const decrypted = new Uint8Array(encrypted.length);
        for (let i = 0; i < encrypted.length; i++) {
            decrypted[i] = encrypted[i] ^ keystream[i];
        }
        
        // Remove metadata
        return decrypted.slice(metadataLen);
    }

    /**
     * Avança estado
     * @param {number} n - Número de ticks
     */
    tick(n = 1) {
        this.txCountGlobal += n;
        
        for (let t = 0; t < n; t++) {
            for (const clock of this.clocks) {
                if (clock.tick()) {
                    for (const boxId of clock.boxes) {
                        if (this.boxes[boxId]) {
                            this.boxes[boxId].advance();
                        }
                    }
                }
            }
        }
        
        // Relógios lentos
        if (this.txCountGlobal % 100 === 0 && this.boxes[5]) {
            this.boxes[5].advance();
        }
        if (this.txCountGlobal % 1000 === 0 && this.boxes[6]) {
            this.boxes[6].advance();
        }
    }

    /**
     * Retorna overhead do ciphertext
     */
    overhead() {
        return this.config.nonceBytes + this.config.macBytes + 8;
    }

    deriveKey() {
        let stateSum = 0;
        for (const clock of this.clocks) {
            if (clock.active) {
                stateSum += clock.tickCount * 1000 + clock.txCount;
            }
        }
        
        const keyLen = this.config.keyBytes;
        const masterLen = this.masterEntropy.length;
        const offset = (stateSum * 7) % Math.max(1, masterLen - keyLen);
        
        const key = new Uint8Array(keyLen);
        for (let i = 0; i < keyLen; i++) {
            key[i] = this.masterEntropy[(offset + i) % masterLen];
        }
        
        // Mistura com primos
        for (const clock of this.clocks) {
            if (!clock.active) continue;
            for (const boxId of clock.boxes) {
                if (!this.boxes[boxId] || !this.boxes[boxId].active) continue;
                const prime = this.boxes[boxId].current();
                const primeBytes = numberToBytes(prime, 4);
                for (let j = 0; j < 4; j++) {
                    const pos = (clock.id * 4 + j) % keyLen;
                    key[pos] ^= primeBytes[j];
                }
            }
        }
        
        return key;
    }

    generateKeystream(key, nonce, len) {
        const keyLen = key.length;
        const nonceLen = nonce.length;
        const result = new Uint8Array(len);
        
        for (let i = 0; i < len; i++) {
            const k = key[i % keyLen];
            const n = nonce[i % nonceLen];
            const rotated = rotLeft(k, i & 7);
            result[i] = rotated ^ n ^ (i & 0xFF);
        }
        
        return result;
    }
}

// ============================================================================
// ASSINATURAS - HASH CHAIN
// ============================================================================

class SignChainKeys {
    /**
     * Gera par de chaves
     * @param {Uint8Array|string} seed - Seed
     * @param {number} chainLength - Tamanho da chain
     */
    constructor(seed, chainLength = 1024) {
        if (typeof seed === 'string') {
            seed = stringToBytes(seed);
        }
        
        this.chainLength = chainLength;
        this.currentIndex = 0;
        this.privateSeed = tavHash(seed);
        
        // Gera chain
        let current = new Uint8Array(this.privateSeed);
        for (let i = 0; i < chainLength; i++) {
            current = tavHash(current);
        }
        this.publicKey = current;
    }

    /**
     * Retorna chave pública
     */
    getPublicKey() {
        return this.publicKey;
    }

    /**
     * Assina mensagem
     * @param {Uint8Array|string} message - Mensagem
     * @returns {Uint8Array} Assinatura
     */
    sign(message) {
        if (typeof message === 'string') {
            message = stringToBytes(message);
        }
        
        if (this.currentIndex >= this.chainLength) {
            throw new Error('Chain exhausted');
        }
        
        // Calcula reveal
        const steps = this.chainLength - this.currentIndex - 1;
        let reveal = new Uint8Array(this.privateSeed);
        for (let i = 0; i < steps; i++) {
            reveal = tavHash(reveal);
        }
        
        // MAC
        const macInput = concatBytes(message, reveal);
        const mac = tavHash(macInput);
        
        // Assinatura
        const signature = new Uint8Array(2 + HASH_SIZE * 2);
        signature[0] = (this.currentIndex >> 8) & 0xFF;
        signature[1] = this.currentIndex & 0xFF;
        signature.set(reveal, 2);
        signature.set(mac, 2 + HASH_SIZE);
        
        this.currentIndex++;
        
        return signature;
    }

    /**
     * Verifica assinatura
     * @param {Uint8Array} publicKey - Chave pública
     * @param {Uint8Array|string} message - Mensagem
     * @param {Uint8Array} signature - Assinatura
     * @returns {boolean} Válida?
     */
    static verify(publicKey, message, signature) {
        if (typeof message === 'string') {
            message = stringToBytes(message);
        }
        
        if (signature.length < 2 + HASH_SIZE * 2) {
            return false;
        }
        
        const index = (signature[0] << 8) | signature[1];
        const reveal = signature.slice(2, 2 + HASH_SIZE);
        const mac = signature.slice(2 + HASH_SIZE, 2 + HASH_SIZE * 2);
        
        // Verifica MAC
        const macInput = concatBytes(message, reveal);
        const macExpected = tavHash(macInput);
        
        if (!constantTimeEqual(mac, macExpected)) {
            return false;
        }
        
        // Verifica chain
        let current = new Uint8Array(reveal);
        for (let i = 0; i <= index; i++) {
            current = tavHash(current);
        }
        
        return constantTimeEqual(current, publicKey);
    }
}

// ============================================================================
// ASSINATURAS - COMMITMENT
// ============================================================================

class SignCommitKeys {
    /**
     * Gera par de chaves
     * @param {Uint8Array|string} seed - Seed
     * @param {number} level - Nível de segurança
     */
    constructor(seed, level = SecurityLevel.Consumer) {
        if (typeof seed === 'string') {
            seed = stringToBytes(seed);
        }
        
        this.tav = new Tav(seed, level);
        this.publicCommitment = tavHash(this.tav.masterEntropy);
    }

    /**
     * Retorna commitment público
     */
    getPublicCommitment() {
        return this.publicCommitment;
    }

    /**
     * Assina mensagem
     * @param {Uint8Array|string} message - Mensagem
     * @returns {Uint8Array} Assinatura
     */
    sign(message) {
        if (typeof message === 'string') {
            message = stringToBytes(message);
        }
        
        const txAtSign = this.tav.txCountGlobal;
        
        // Estado de assinatura
        const stateSeed = new Uint8Array(40);
        stateSeed.set(this.tav.masterEntropy.slice(0, 32), 0);
        stateSeed.set(numberToBytes(txAtSign, 8), 32);
        
        // Prova e chave
        const stateProof = tavHash(stateSeed);
        const signKey = tavHash(stateProof);
        
        // MAC
        const macInput = concatBytes(message, numberToBytes(txAtSign, 8));
        const mac = new Uint8Array(tavHash(macInput));
        
        // Vincula ao estado
        for (let i = 0; i < HASH_SIZE; i++) {
            mac[i] ^= signKey[i];
        }
        
        // Assinatura
        const signature = concatBytes(numberToBytes(txAtSign, 8), stateProof, mac);
        
        this.tav.tick(1);
        
        return signature;
    }

    /**
     * Verifica assinatura
     * @param {Uint8Array} publicCommitment - Commitment público
     * @param {Uint8Array|string} message - Mensagem
     * @param {Uint8Array} signature - Assinatura
     * @returns {boolean} Válida?
     */
    static verify(publicCommitment, message, signature) {
        if (typeof message === 'string') {
            message = stringToBytes(message);
        }
        
        if (signature.length < 8 + HASH_SIZE * 2) {
            return false;
        }
        
        const txCount = bytesToNumber(signature.slice(0, 8));
        const stateProof = signature.slice(8, 8 + HASH_SIZE);
        const mac = signature.slice(8 + HASH_SIZE, 8 + HASH_SIZE * 2);
        
        // Deriva chave
        const signKey = tavHash(stateProof);
        
        // Recalcula MAC
        const macInput = concatBytes(message, numberToBytes(txCount, 8));
        const macExpected = new Uint8Array(tavHash(macInput));
        
        for (let i = 0; i < HASH_SIZE; i++) {
            macExpected[i] ^= signKey[i];
        }
        
        return constantTimeEqual(mac, macExpected);
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

// Para Node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        Tav,
        SecurityLevel,
        SignChainKeys,
        SignCommitKeys,
        tavHash,
        stringToBytes,
        bytesToString
    };
}

// Para ES Modules
export {
    Tav,
    SecurityLevel,
    SignChainKeys,
    SignCommitKeys,
    tavHash,
    stringToBytes,
    bytesToString
};
