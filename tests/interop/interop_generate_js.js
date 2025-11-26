#!/usr/bin/env node
/*
 * TAV INTEROP TEST - Gerador de Vetores (JavaScript)
 * ===================================================
 * 
 * Gera vetores de teste para validação por outras implementações.
 * 
 * Uso: node interop_generate_js.js > vectors_from_js.json
 */

const path = require('path');
const tavPath = path.join(__dirname, '../../js/tav.js');
const { Tav, SecurityLevel, tavHash, SignChainKeys } = require(tavPath);

/* ============================================================================
 * HELPERS
 * ============================================================================ */

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

/* ============================================================================
 * TESTES
 * ============================================================================ */

function generateHashVectors() {
    const vectors = [];
    
    // Empty string
    {
        const input = new Uint8Array(0);
        const output = tavHash(input);
        vectors.push({
            name: "empty_string",
            input_utf8: "",
            input_hex: "",
            output_hex: bytesToHex(output)
        });
    }
    
    // "TAV"
    {
        const input = stringToBytes("TAV");
        const output = tavHash(input);
        vectors.push({
            name: "tav_string",
            input_utf8: "TAV",
            input_hex: "544156",
            output_hex: bytesToHex(output)
        });
    }
    
    // "Hello, World!"
    {
        const input = stringToBytes("Hello, World!");
        const output = tavHash(input);
        vectors.push({
            name: "hello_world",
            input_utf8: "Hello, World!",
            input_hex: "48656c6c6f2c20576f726c6421",
            output_hex: bytesToHex(output)
        });
    }
    
    // Sequential 0-31
    {
        const input = new Uint8Array(32);
        for (let i = 0; i < 32; i++) input[i] = i;
        const output = tavHash(input);
        vectors.push({
            name: "sequential_32",
            input_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            output_hex: bytesToHex(output)
        });
    }
    
    // All 0xFF
    {
        const input = new Uint8Array(32).fill(0xFF);
        const output = tavHash(input);
        vectors.push({
            name: "all_ff",
            input_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            output_hex: bytesToHex(output)
        });
    }
    
    // Long string
    {
        const input = stringToBytes("The quick brown fox jumps over the lazy dog. TAV Clock Cryptography V9.1");
        const output = tavHash(input);
        vectors.push({
            name: "long_string",
            input_utf8: "The quick brown fox jumps over the lazy dog. TAV Clock Cryptography V9.1",
            output_hex: bytesToHex(output)
        });
    }
    
    return vectors;
}

function generateKeyDerivationVectors() {
    const vectors = [];
    const seeds = ["test", "password123", "TAV_SEED_2025"];
    const levels = [SecurityLevel.IoT, SecurityLevel.Consumer, SecurityLevel.Enterprise];
    const levelNames = ["iot", "consumer", "enterprise"];
    
    for (let s = 0; s < seeds.length; s++) {
        for (let l = 0; l < levels.length; l++) {
            const tav = new Tav(seeds[s], levels[l]);
            tav.nonceCounter = 1;
            
            const pt = new Uint8Array([0x42]);
            const ct = tav.encrypt(pt, false);
            
            vectors.push({
                name: `seed_${seeds[s]}_level_${levelNames[l]}`,
                seed_utf8: seeds[s],
                level: levels[l],
                tx_count: 0,
                master_entropy_first16: bytesToHex(new Uint8Array(tav.masterEntropy.slice(0, 16))),
                ciphertext_len: ct.length,
                ciphertext_hex: bytesToHex(ct)
            });
        }
    }
    
    return vectors;
}

function generateEncryptDecryptVectors() {
    const vectors = [];
    
    const tests = [
        {name: "simple_iot", seed: "seed1", level: SecurityLevel.IoT, plaintext: "A"},
        {name: "simple_consumer", seed: "seed1", level: SecurityLevel.Consumer, plaintext: "A"},
        {name: "hello_consumer", seed: "test_key", level: SecurityLevel.Consumer, plaintext: "Hello, TAV!"},
        {name: "empty_enterprise", seed: "enterprise_key", level: SecurityLevel.Enterprise, plaintext: ""},
        {name: "long_military", seed: "military_key_2025", level: SecurityLevel.Military, 
         plaintext: "This is a longer message to test block processing in TAV encryption."},
    ];
    
    for (const t of tests) {
        const tav = new Tav(t.seed, t.level);
        tav.nonceCounter = 1;
        
        const pt = stringToBytes(t.plaintext);
        const ct = tav.encrypt(pt, false);
        
        // Roundtrip
        const tav2 = new Tav(t.seed, t.level);
        tav2.nonceCounter = 1;
        
        let decryptOk = false;
        let roundtripOk = false;
        
        try {
            const dec = tav2.decrypt(ct);
            decryptOk = true;
            roundtripOk = (dec.length === pt.length);
            if (roundtripOk) {
                for (let i = 0; i < pt.length; i++) {
                    if (pt[i] !== dec[i]) {
                        roundtripOk = false;
                        break;
                    }
                }
            }
        } catch (e) {
            // Decrypt failed
        }
        
        vectors.push({
            name: t.name,
            seed_utf8: t.seed,
            level: t.level,
            plaintext_utf8: t.plaintext,
            plaintext_len: pt.length,
            ciphertext_len: ct.length,
            ciphertext_hex: bytesToHex(ct),
            decrypt_ok: decryptOk,
            roundtrip_ok: roundtripOk
        });
    }
    
    return vectors;
}

function generateSignChainVectors() {
    const vectors = [];
    
    const tests = [
        {name: "basic_100", seed: "sign_seed", chain_len: 100, message: "test message"},
        {name: "short_chain", seed: "abc", chain_len: 10, message: "hello"},
        {name: "long_message", seed: "key123", chain_len: 50, 
         message: "This is a much longer message that needs to be signed securely."},
    ];
    
    for (const t of tests) {
        const seedBytes = stringToBytes(t.seed);
        const keys = new SignChainKeys(seedBytes, t.chain_len);
        
        const msg = stringToBytes(t.message);
        const sig = keys.sign(msg);
        
        const verifyOk = SignChainKeys.verify(keys.getPublicKey(), msg, sig);
        
        vectors.push({
            name: t.name,
            seed_utf8: t.seed,
            chain_length: t.chain_len,
            message_utf8: t.message,
            public_key_hex: bytesToHex(keys.getPublicKey()),
            private_seed_hex: bytesToHex(keys.privateSeed),
            signature_len: sig.length,
            signature_hex: bytesToHex(sig),
            verify_ok: verifyOk
        });
    }
    
    return vectors;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

function main() {
    const output = {
        generator: "JavaScript",
        version: "9.1.0",
        description: "TAV interoperability test vectors generated by JavaScript implementation",
        
        hash_tests: generateHashVectors(),
        key_derivation_tests: generateKeyDerivationVectors(),
        encrypt_decrypt_tests: generateEncryptDecryptVectors(),
        sign_chain_tests: generateSignChainVectors()
    };
    
    console.log(JSON.stringify(output, null, 2));
}

main();
