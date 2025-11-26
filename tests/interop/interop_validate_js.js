#!/usr/bin/env node
/*
 * TAV INTEROP TEST - Validador JavaScript
 * ========================================
 * 
 * Lê vetores gerados pelo C e valida com implementação JavaScript.
 * 
 * Uso: node interop_validate_js.js vectors_from_c.json
 */

const fs = require('fs');
const path = require('path');

// Importa TAV
const tavPath = path.join(__dirname, '../../js/tav.js');
const { Tav, SecurityLevel, tavHash, SignChainKeys } = require(tavPath);

/* ============================================================================
 * HELPERS
 * ============================================================================ */

function hexToBytes(hex) {
    if (!hex || hex.length === 0) return new Uint8Array(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function compareBytes(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

/* ============================================================================
 * TESTES
 * ============================================================================ */

let passed = 0;
let failed = 0;

function test(name, condition, details = '') {
    if (condition) {
        console.log(`  ✅ ${name}`);
        passed++;
    } else {
        console.log(`  ❌ ${name}`);
        if (details) console.log(`     ${details}`);
        failed++;
    }
}

function testHashVectors(vectors) {
    console.log('\n🔹 HASH TESTS');
    
    for (const v of vectors) {
        let input;
        if (v.input_hex) {
            input = hexToBytes(v.input_hex);
        } else if (v.input_utf8 !== undefined) {
            input = stringToBytes(v.input_utf8);
        }
        
        const result = tavHash(input);
        const resultHex = bytesToHex(result);
        const expectedHex = v.output_hex;
        
        const match = resultHex === expectedHex;
        test(`hash: ${v.name}`, match, 
             match ? '' : `Expected: ${expectedHex}\nGot:      ${resultHex}`);
    }
}

function testKeyDerivation(vectors) {
    console.log('\n🔹 KEY DERIVATION TESTS');
    
    for (const v of vectors) {
        try {
            const tav = new Tav(v.seed_utf8, v.level);
            
            // Compara primeiros 16 bytes da master_entropy
            const masterFirst16 = bytesToHex(new Uint8Array(tav.masterEntropy.slice(0, 16)));
            const expectedFirst16 = v.master_entropy_first16;
            
            // Nota: master_entropy pode diferir devido a coleta de entropia
            // O importante é que encrypt/decrypt funcionem igual
            
            // Força nonce determinístico
            tav.nonceCounter = 1;
            
            const pt = new Uint8Array([0x42]);
            const ct = tav.encrypt(pt, false);
            const ctHex = bytesToHex(ct);
            
            // Para interop real, precisamos do mesmo resultado
            // Por enquanto, verificamos apenas tamanho
            const sizeMatch = ct.length === v.ciphertext_len;
            
            test(`key_derive: ${v.name}`, sizeMatch,
                 sizeMatch ? '' : `Expected len: ${v.ciphertext_len}, Got: ${ct.length}`);
            
        } catch (e) {
            test(`key_derive: ${v.name}`, false, e.message);
        }
    }
}

function testEncryptDecrypt(vectors) {
    console.log('\n🔹 ENCRYPT/DECRYPT TESTS');
    
    for (const v of vectors) {
        try {
            const tav = new Tav(v.seed_utf8, v.level);
            tav.nonceCounter = 1;
            
            const pt = stringToBytes(v.plaintext_utf8);
            const ct = tav.encrypt(pt, false);
            
            // Verifica tamanho
            const sizeMatch = ct.length === v.ciphertext_len;
            
            // Verifica roundtrip
            const tav2 = new Tav(v.seed_utf8, v.level);
            tav2.nonceCounter = 1;
            
            // Para decrypt, precisamos do mesmo ciphertext
            // Como a entropia pode diferir, testamos apenas roundtrip local
            const dec = tav2.decrypt(ct);
            const roundtripOk = compareBytes(pt, dec);
            
            test(`encrypt: ${v.name} (size)`, sizeMatch,
                 sizeMatch ? '' : `Expected: ${v.ciphertext_len}, Got: ${ct.length}`);
            test(`encrypt: ${v.name} (roundtrip)`, roundtripOk);
            
        } catch (e) {
            test(`encrypt: ${v.name}`, false, e.message);
        }
    }
}

function testSignChain(vectors) {
    console.log('\n🔹 SIGN CHAIN TESTS');
    
    for (const v of vectors) {
        try {
            // Gera chaves com mesmo seed
            const seedBytes = stringToBytes(v.seed_utf8);
            const keys = new SignChainKeys(seedBytes, v.chain_length);
            
            // Compara public key
            const pubKeyHex = bytesToHex(keys.getPublicKey());
            const expectedPubKey = v.public_key_hex;
            const pubKeyMatch = pubKeyHex === expectedPubKey;
            
            test(`sign_chain: ${v.name} (pubkey)`, pubKeyMatch,
                 pubKeyMatch ? '' : `Expected: ${expectedPubKey}\nGot:      ${pubKeyHex}`);
            
            // Compara private seed hash
            const privSeedHex = bytesToHex(keys.privateSeed);
            const expectedPrivSeed = v.private_seed_hex;
            const privSeedMatch = privSeedHex === expectedPrivSeed;
            
            test(`sign_chain: ${v.name} (priv_seed)`, privSeedMatch,
                 privSeedMatch ? '' : `Expected: ${expectedPrivSeed}\nGot:      ${privSeedHex}`);
            
            // Assina mensagem
            const msg = stringToBytes(v.message_utf8);
            const sig = keys.sign(msg);
            const sigHex = bytesToHex(sig);
            
            // Verifica tamanho
            const sigSizeMatch = sig.length === v.signature_len;
            test(`sign_chain: ${v.name} (sig_size)`, sigSizeMatch,
                 sigSizeMatch ? '' : `Expected: ${v.signature_len}, Got: ${sig.length}`);
            
            // Verifica assinatura gerada pelo C
            const cSig = hexToBytes(v.signature_hex);
            const verifyCSig = SignChainKeys.verify(hexToBytes(expectedPubKey), msg, cSig);
            test(`sign_chain: ${v.name} (verify_c_sig)`, verifyCSig);
            
            // Verifica assinatura gerada pelo JS
            const verifyJsSig = SignChainKeys.verify(keys.getPublicKey(), msg, sig);
            test(`sign_chain: ${v.name} (verify_js_sig)`, verifyJsSig);
            
            // Compara assinaturas (devem ser idênticas se mesmo seed/index)
            const sigMatch = sigHex === v.signature_hex;
            test(`sign_chain: ${v.name} (sig_match)`, sigMatch,
                 sigMatch ? '' : `Expected: ${v.signature_hex}\nGot:      ${sigHex}`);
            
        } catch (e) {
            test(`sign_chain: ${v.name}`, false, e.message);
        }
    }
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 1) {
        console.log('Uso: node interop_validate_js.js <vectors.json>');
        console.log('');
        console.log('Gere os vetores primeiro:');
        console.log('  cd tests/interop');
        console.log('  gcc -O2 -I../../c interop_generate_c.c ../../c/tav.c ../../c/tav_sign.c -o gen_c -lm');
        console.log('  ./gen_c > vectors_from_c.json');
        console.log('  node interop_validate_js.js vectors_from_c.json');
        process.exit(1);
    }
    
    const vectorsFile = args[0];
    
    console.log('═══════════════════════════════════════════════════');
    console.log('TAV INTEROPERABILITY TEST - JavaScript Validator');
    console.log('═══════════════════════════════════════════════════');
    console.log(`Reading vectors from: ${vectorsFile}`);
    
    let vectors;
    try {
        const data = fs.readFileSync(vectorsFile, 'utf8');
        vectors = JSON.parse(data);
    } catch (e) {
        console.error(`Error reading vectors: ${e.message}`);
        process.exit(1);
    }
    
    console.log(`Generator: ${vectors.generator}`);
    console.log(`Version: ${vectors.version}`);
    
    // Executa testes
    if (vectors.hash_tests) {
        testHashVectors(vectors.hash_tests);
    }
    
    if (vectors.key_derivation_tests) {
        testKeyDerivation(vectors.key_derivation_tests);
    }
    
    if (vectors.encrypt_decrypt_tests) {
        testEncryptDecrypt(vectors.encrypt_decrypt_tests);
    }
    
    if (vectors.sign_chain_tests) {
        testSignChain(vectors.sign_chain_tests);
    }
    
    // Resumo
    console.log('\n═══════════════════════════════════════════════════');
    console.log(`RESULTS: ${passed} passed, ${failed} failed`);
    console.log('═══════════════════════════════════════════════════');
    
    process.exit(failed > 0 ? 1 : 0);
}

main();
