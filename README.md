# TAV Clock Cryptography

<p align="center">
  <img src="https://img.shields.io/badge/version-0.9-blue.svg" alt="Version 0.9">
  <img src="https://img.shields.io/badge/status-active%20development-orange.svg" alt="Active Development">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-green.svg" alt="License AGPL-3.0">
  <img src="https://img.shields.io/badge/commercial-free%20until%20May%202027-brightgreen.svg" alt="Commercial Free">
</p>

<p align="center">
  <b>A stateful cryptographic system based on ephemeral structure and continuous physical entropy.</b>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-documentation">Documentation</a> •
  <a href="#-support-the-project">Donate</a> •
  <a href="#-license">License</a>
</p>

---

## ⚠️ Important Disclaimer

> **TAV is experimental research software.** It has NOT been:
> - Formally verified or proven secure
> - Audited by independent cryptographers
> - Analyzed for side-channel vulnerabilities
> - Deployed in production environments
>
> **Do not use TAV for protecting sensitive data in production.** Use established algorithms (AES, ChaCha20, ML-KEM) for critical systems.

---

## 📋 Table of Contents

- [About TAV](#-about-tav)
- [Project Status](#-project-status)
- [Support the Project](#-support-the-project)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Security Levels](#-security-levels)
- [Performance](#-performance)
- [Digital Signatures](#-digital-signatures)
- [Architecture](#-architecture)
- [Use Cases](#-use-cases)
- [Repository Structure](#-repository-structure)
- [Installation](#-installation)
- [API Reference](#-api-reference)
- [Documentation](#-documentation)
- [License](#-license)
- [Contact](#-contact)
- [Citation](#-citation)

---

## 🔐 About TAV

**TAV** (Transactional Asynchronous Verification) is an innovative cryptographic system that takes a fundamentally different approach to security:

### The Core Innovation: Ephemeral Structure

Traditional cryptography relies on **static mathematical structures** (prime factorization, elliptic curves, lattices). TAV introduces **ephemeral structure** — algebraic elements that exist but change too rapidly to be exploited.

```
Traditional Crypto:  Static structure → Same attack surface forever
TAV:                 Ephemeral structure → Attack surface changes every operation
```

### How It Works

1. **Physical Entropy**: Collects CPU timing jitter continuously (not just at initialization)
2. **Transactional Clocks**: Four clocks with coprime prime periods (17, 23, 31, 47) govern state evolution
3. **Prime Boxes**: 1,464 prime numbers organized in 6 boxes, rotated by clock ticks
4. **Logic-Only Operations**: XOR, AND, OR, bit rotation — no modular addition
5. **State Evolution**: Every operation changes the internal state unpredictably

### Why No Modular Addition?

Modular addition (the "A" in ARX ciphers like ChaCha20) preserves correlations between rotated pairs, enabling [rotational cryptanalysis](https://en.wikipedia.org/wiki/Rotational_cryptanalysis). TAV deliberately avoids this by using AND/OR for non-linearity instead.

---

## 🚀 Project Status

TAV is under **active development**. Current focus areas:

| Area | Status | Description |
|------|--------|-------------|
| 🔬 Statistical Validation | In Progress | Extended NIST SP 800-22 test suite |
| 🔐 Signature Schemes | Implemented | Hash-Chain and Commitment-Reveal |
| ⚡ Performance | Ongoing | SIMD optimizations for C implementation |
| 📱 Mobile Support | Planned | iOS and Android libraries |
| 🧪 Test Coverage | Expanding | Cross-platform interoperability tests |
| 📖 Documentation | Ongoing | API docs and tutorials |
| 🔍 Security Audit | Seeking | Looking for independent cryptographic review |

### Roadmap

- **v0.9** (Current): Initial public release
- **v1.0** (Q2 2026): Production-ready after security review
- **v1.1** (Q3 2026): Mobile platforms support
- **v2.0** (2027): Next-generation features

---

## 💝 Support the Project

TAV is an **independent research project** developed without institutional funding or corporate backing.

### Why Donate?

Your support helps with:
- 🔬 Independent security audits
- 📚 Documentation and tutorials
- 🛠️ Development tools and infrastructure
- ☕ Coffee to fuel late-night coding sessions

### Donor Benefits

**Donors receive early access** to new features, updates, and releases!

| Benefit | Public | Donors |
|---------|--------|--------|
| Access to releases | After public release | **🚀 Early access** |
| New features preview | ❌ | ✅ |
| Development updates | GitHub only | **📧 Direct email** |
| Priority support | ❌ | ✅ |
| Name in contributors | ❌ | ✅ (optional) |
| Input on roadmap | ❌ | ✅ |

### How to Donate

<p align="center">
  <a href="https://www.paypal.com/donate/?hosted_button_id=S6KMBHT8PWSC2">
    <img src="https://img.shields.io/badge/PayPal-Donate-blue.svg?logo=paypal" alt="Donate with PayPal" height="40">
  </a>
</p>

**PayPal:** [Donate via PayPal](https://www.paypal.com/donate/?hosted_button_id=S6KMBHT8PWSC2)

📧 **Important:** Include your email in the donation note to receive early access updates!

---

## ✨ Features

### Core Cryptographic Features

| Feature | Description |
|---------|-------------|
| **Stream Cipher** | XOR-based encryption with derived keystream |
| **MAC Authentication** | Feistel-based MAC (no HMAC dependency) |
| **Digital Signatures** | Hash-Chain (66 bytes) and Commitment-Reveal (72 bytes) |
| **Key Derivation** | State-based derivation from master entropy |
| **Nonce Generation** | Timing-based, guaranteed unique |

### Advanced Features

| Feature | Description |
|---------|-------------|
| **Ephemeral Structure** | Algebraic elements that change every operation |
| **Physics-Based Entropy** | CPU timing jitter embedded throughout |
| **Automatic Checkpoint** | Encrypted state saved every 10,000 transactions |
| **Threat Management** | Automatic security escalation on attack detection |
| **Dead-Man Switch** | Key destruction after configurable inactivity |
| **Device Identity** | Unique state fingerprint for fraud prevention |
| **Hardware Detection** | Warns if running on different hardware |

### Security Properties

| Property | Implementation |
|----------|----------------|
| **Confidentiality** | Stream cipher with evolving keys |
| **Integrity** | MAC-Feistel authentication |
| **Authenticity** | Digital signatures |
| **Forward Secrecy** | State evolution prevents past key recovery |
| **Replay Prevention** | Unique nonces per transaction |
| **Tamper Detection** | MAC verification on all decryption |

---

## 🚀 Quick Start

### Python

```python
from tav_crypto import TAV

# Initialize with seed phrase and security level
tav = TAV("my secret seed phrase", nivel="consumer")

# Encrypt data
plaintext = b"Hello, TAV!"
ciphertext = tav.encrypt(plaintext)
print(f"Encrypted: {len(ciphertext)} bytes")

# Decrypt data
decrypted, success = tav.decrypt(ciphertext)
if success:
    print(f"Decrypted: {decrypted}")

# Check system status
status = tav.status()
print(f"Transactions: {status['tx_global']}")
print(f"Boot count: {status['boot_count']}")

# Manual state advancement
tav.tick(10)  # Advance 10 transactions

# Force checkpoint save
tav.forcar_checkpoint()
```

### JavaScript

```javascript
const { TAVCrypto, SecurityLevel } = require('./tav.js');

// Initialize
const tav = new TAVCrypto("my secret seed phrase", SecurityLevel.Consumer);

// Encrypt
const plaintext = new TextEncoder().encode("Hello, TAV!");
const ciphertext = tav.encrypt(plaintext);
console.log(`Encrypted: ${ciphertext.length} bytes`);

// Decrypt
const { success, data } = tav.decrypt(ciphertext);
if (success) {
    console.log(`Decrypted: ${new TextDecoder().decode(data)}`);
}

// Status
console.log(tav.status());

// With checkpoint callbacks (Node.js)
const fs = require('fs');
tav.setCheckpointCallbacks(
    (data) => { fs.writeFileSync('.tav_checkpoint', Buffer.from(data)); return true; },
    () => { try { return fs.readFileSync('.tav_checkpoint'); } catch { return null; } }
);
```

### C

```c
#include "tav.h"
#include <stdio.h>
#include <string.h>

int main() {
    tav_ctx_t ctx;
    const uint8_t seed[] = "my secret seed phrase";
    
    // Initialize
    tav_result_t res = tav_init(&ctx, seed, strlen((char*)seed), TAV_LEVEL_CONSUMER);
    if (res != TAV_OK) {
        printf("Init failed: %d\n", res);
        return 1;
    }
    
    // Encrypt
    const uint8_t plaintext[] = "Hello, TAV!";
    uint8_t ciphertext[256];
    size_t ct_len;
    
    res = tav_encrypt(&ctx, plaintext, strlen((char*)plaintext), 
                      ciphertext, &ct_len, true);
    if (res != TAV_OK) {
        printf("Encrypt failed: %d\n", res);
        return 1;
    }
    printf("Encrypted: %zu bytes\n", ct_len);
    
    // Decrypt
    uint8_t decrypted[256];
    size_t pt_len;
    
    res = tav_decrypt(&ctx, ciphertext, ct_len, decrypted, &pt_len);
    if (res != TAV_OK) {
        printf("Decrypt failed: %d\n", res);
        return 1;
    }
    decrypted[pt_len] = '\0';
    printf("Decrypted: %s\n", decrypted);
    
    // Get stats
    uint64_t tx_count;
    uint32_t boot_count;
    tav_get_stats(&ctx, &tx_count, &boot_count, NULL, NULL);
    printf("Transactions: %lu, Boots: %u\n", tx_count, boot_count);
    
    // Cleanup
    tav_cleanup(&ctx);
    return 0;
}
```

**Compile:**
```bash
gcc -o tav_example example.c tav.c -lm
```

### Rust

```rust
use tav_crypto::{Tav, SecurityLevel, TavError};

fn main() -> Result<(), TavError> {
    // Initialize
    let mut tav = Tav::new("my secret seed phrase", SecurityLevel::Consumer)?;
    
    // Encrypt
    let plaintext = b"Hello, TAV!";
    let ciphertext = tav.encrypt(plaintext, true)?;
    println!("Encrypted: {} bytes", ciphertext.len());
    
    // Decrypt
    let decrypted = tav.decrypt(&ciphertext)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    
    // Status
    let status = tav.status();
    println!("Transactions: {}", status.tx_count_global);
    println!("Boot count: {}", status.boot_count);
    
    Ok(())
}
```

**Cargo.toml:**
```toml
[dependencies]
tav-crypto = "0.9"
```

### Arduino/ESP32

```cpp
#include "tav_arduino.h"

tav_ctx_t ctx;

void setup() {
    Serial.begin(115200);
    
    // Initialize
    uint8_t seed[] = "my secret seed";
    tav_result_t res = tav_init(&ctx, seed, sizeof(seed)-1);
    
    if (res == TAV_OK) {
        Serial.println("TAV initialized!");
    }
}

void loop() {
    // Encrypt sensor data
    uint8_t data[] = "sensor:25.5C";
    uint8_t encrypted[64];
    uint16_t enc_len;
    
    if (tav_encrypt(&ctx, data, sizeof(data)-1, encrypted, &enc_len, 1) == TAV_OK) {
        // Send encrypted data
        Serial.write(encrypted, enc_len);
    }
    
    delay(1000);
}
```

---

## 🔒 Security Levels

TAV supports four security levels, each with different parameters:

| Level | Key Size | MAC Size | Nonce Size | Clocks | Boxes | Use Case |
|-------|----------|----------|------------|--------|-------|----------|
| **IoT** | 128 bits | 8 bytes | 12 bytes | 1 | 1-2 | Constrained devices, sensors |
| **Consumer** | 192 bits | 12 bytes | 16 bytes | 2 | 1-3 | Apps, personal projects |
| **Enterprise** | 256 bits | 16 bytes | 16 bytes | 3 | 1-4 | Business applications |
| **Military** | 256 bits | 24 bytes | 24 bytes | 4 | 1-6 | Maximum security |

### Choosing a Level

```python
# IoT - Minimum overhead for constrained devices
tav = TAV(seed, nivel="iot")  # ~200 bytes RAM

# Consumer - Balanced security/performance (recommended)
tav = TAV(seed, nivel="consumer")  # ~300 bytes RAM

# Enterprise - Higher security margin
tav = TAV(seed, nivel="enterprise")  # ~400 bytes RAM

# Military - Maximum security
tav = TAV(seed, nivel="military")  # ~500 bytes RAM
```

---

## 📊 Performance

### Throughput

| Implementation | Complete System | Keystream Only |
|----------------|-----------------|----------------|
| Python | ~500-850 KB/s | ~5 MB/s |
| C (no SIMD) | ~50-100 MB/s (est.) | ~300 MB/s (est.) |
| JavaScript | ~200-400 KB/s | ~2 MB/s |

### Entropy Quality

| Metric | Value | Threshold |
|--------|-------|-----------|
| Shannon Entropy | 7.996 bits/byte | > 7.9 ✅ |
| Bit Bias | 0.15% | < 3% ✅ |
| Autocorrelation | 0.001 | < 0.05 ✅ |
| Compression Ratio | 1.0004 | > 0.95 ✅ |

### NIST SP 800-22 Results

| Test | Result |
|------|--------|
| Frequency (Monobit) | ✅ PASS (p=0.536) |
| Runs | ✅ PASS (p=0.630) |
| Serial | ✅ PASS (χ²/df=1.70) |

### Memory Usage

| Platform | RAM Usage |
|----------|-----------|
| Arduino (IoT) | ~200 bytes |
| Arduino (Consumer) | ~300 bytes |
| ESP32 | ~400 bytes |
| Desktop | ~1-2 KB |

---

## ✍️ Digital Signatures

TAV provides two signature schemes, both dramatically smaller than post-quantum alternatives:

### Comparison with PQC

| Algorithm | Signature Size | Public Key | Type |
|-----------|---------------|------------|------|
| **TAV Hash-Chain** | **66 bytes** | 32 bytes | Stateful |
| **TAV Commitment** | **72 bytes** | 32 bytes | Stateful |
| ECDSA P-256 | 64 bytes | 64 bytes | Stateless |
| Ed25519 | 64 bytes | 32 bytes | Stateless |
| ML-DSA-44 | 2,420 bytes | 1,312 bytes | Stateless |
| ML-DSA-65 | 3,293 bytes | 1,952 bytes | Stateless |
| ML-DSA-87 | 4,627 bytes | 2,592 bytes | Stateless |

**TAV signatures are 36-70x smaller than ML-DSA!**

### Hash-Chain (Lamport-style)

```python
from tav_crypto import TAV

# Generate keys
tav = TAV("signature seed", nivel="consumer")
# public_key = tav.get_public_key()

# Sign (limited signatures per key - use for high-value transactions)
signature = tav.sign_chain(message)  # 66 bytes

# Verify
valid = tav.verify_chain(message, signature, public_key)
```

**Properties:**
- 66-byte signatures
- Quantum-resistant by design
- Limited signatures per key (chain length)
- Ideal for: certificates, firmware signing, high-value transactions

### Commitment-Reveal

```python
# Sign (unlimited signatures)
signature = tav.sign_commit(message)  # 72 bytes

# Verify
valid = tav.verify_commit(message, signature, public_commitment)
```

**Properties:**
- 72-byte signatures
- Unlimited signatures
- Based on TAV state evolution
- Ideal for: routine authentication, API requests, session tokens


### 🔑 Capability-Based Authorization (CBA)

TAV CBA is a **third communication system** that extends TAV's cryptographic primitives into a complete authorization framework. While Hash-Chain and Commitment-Reveal provide signatures, CBA provides **fine-grained access control** with minimal overhead.

#### The Problem CBA Solves

Traditional authorization systems (OAuth2, JWT, X.509) were designed for web servers with abundant resources. IoT devices need:
- Minimal memory footprint
- Offline verification (no network round-trips)
- Hierarchical delegation
- Instant revocation

#### How CBA Works
```
┌─────────────┐     Capability      ┌─────────────┐
│   Issuer    │ ─────────────────► │   Holder    │
│  (Gateway)  │   (150 bytes)      │  (Sensor)   │
└─────────────┘                     └──────┬──────┘
                                           │
                                           │ Proof (83-151 bytes)
                                           ▼
                                    ┌─────────────┐
                                    │  Verifier   │
                                    │  (Gateway)  │
                                    └─────────────┘
```

1. **Issuer** creates a capability granting specific permissions on specific resources
2. **Holder** generates compact proofs when accessing resources
3. **Verifier** validates proofs offline without network calls

#### CBA Features

| Feature | Description |
|---------|-------------|
| **10 Permissions** | READ, WRITE, DELETE, ENCRYPT, DECRYPT, SIGN, VERIFY, DELEGATE, REVOKE, ADMIN |
| **Resource Scoping** | Capabilities bound to specific resources (e.g., `zone:living`, `sensor:temp`) |
| **Hierarchical Delegation** | Gateway can delegate subset of permissions to sensors |
| **Automatic Restriction** | Delegated capabilities cannot exceed parent permissions |
| **Time-Bounded** | Capabilities expire automatically |
| **Use-Limited** | Optional maximum use count |
| **Instant Revocation** | Revoke without network propagation |

#### Size Comparison

| Protocol | Auth Token | Capability | Proof |
|----------|------------|------------|-------|
| **TAV CBA** | — | **~150 bytes** | **83-151 bytes** |
| JWT | 300-800 bytes | — | — |
| OAuth2 | 40-100 bytes | — | — |
| X.509 | 1,000+ bytes | — | — |
| ML-DSA-44 | — | — | 2,420 bytes |

CBA proofs are **16-29x smaller** than ML-DSA signatures.

#### Memory Footprint (IoT)

| Component | Size |
|-----------|------|
| Full context | ~280 bytes |
| Per capability | ~252 bytes |
| Per proof | ~152 bytes |
| **Total RAM** | **~400-600 bytes** |

Compare to ML-DSA requiring ~10-15 KB RAM.

#### Use Cases

| Scenario | How CBA Helps |
|----------|---------------|
| **Smart Home** | Gateway delegates READ to sensors, WRITE to actuators |
| **Industrial IoT** | Hierarchical access: Cloud → Hub → Sensor |
| **Content Authenticity** | Prove who created content, when, with what permissions |
| **Offline Devices** | Verify access without internet connectivity |
| **Battery-Constrained** | Minimal computation for proof generation |

#### Quick Example
```python
from tav_cba import CBAContext, CBA_PERM_READ, CBA_PERM_ENCRYPT

# Gateway issues capability to sensor
gateway = CBAContext("gateway-seed", chain_length=100)
sensor = CBAContext("sensor-seed", chain_length=50)

capability = gateway.issue_capability(
    holder_public_key=sensor.public_key,
    permissions=CBA_PERM_READ | CBA_PERM_ENCRYPT,
    resources=["temp", "humidity"],
    duration_seconds=3600,
    max_uses=100
)

# Sensor generates proof when reading
proof = sensor.generate_proof(capability, "READ", "temp")

# Gateway verifies (offline, no network)
is_valid = gateway.verify_proof(proof, capability)
```

#### Implementations Available

| Language | File | Status |
|----------|------|--------|
| Python | `tav_cba_protocol.py` | ✅ Complete |
| C | `tav_cba.h` + `tav_cba.c` | ✅ Complete |
| C (IoT) | `tav_cba_iot.h` | ✅ Header-only, zero malloc |
| Java | `TavCBA.java` | ✅ Complete |


---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        TAV SYSTEM v0.9                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐          │
│  │  PHYSICAL   │   │TRANSACTIONAL│   │   PRIME     │          │
│  │  ENTROPY    │──▶│   CLOCKS    │──▶│   BOXES     │          │
│  │ (CPU Jitter)│   │ P={17,23,   │   │ (6 boxes,   │          │
│  │             │   │    31,47}   │   │ 1464 primes)│          │
│  └─────────────┘   └─────────────┘   └─────────────┘          │
│         │                 │                 │                  │
│         ▼                 ▼                 ▼                  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              MASTER ENTROPY POOL (32-64 bytes)          │  │
│  │         Feistel mixing: XOR, AND, OR, ROT only          │  │
│  └─────────────────────────────────────────────────────────┘  │
│                              │                                 │
│         ┌────────────────────┼────────────────────┐           │
│         ▼                    ▼                    ▼           │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐   │
│  │    KEY      │      │   NONCE     │      │    MAC      │   │
│  │ DERIVATION  │      │ GENERATION  │      │  FEISTEL    │   │
│  └─────────────┘      └─────────────┘      └─────────────┘   │
│         │                    │                    │           │
│         └────────────────────┼────────────────────┘           │
│                              ▼                                 │
│                    ┌─────────────────┐                        │
│                    │  STREAM CIPHER  │                        │
│                    │   (XOR-based)   │                        │
│                    └─────────────────┘                        │
│                              │                                 │
│                              ▼                                 │
│                    ┌─────────────────┐                        │
│                    │     OUTPUT      │                        │
│                    │ [Nonce|CT|MAC]  │                        │
│                    └─────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

### Clock System

The four transactional clocks create a state cycle of:

```
LCM(17, 23, 31, 47) = 563,327 transactions
```

Combined with entropy injection, the effective state space exceeds **6×10²²** configurations.

### Checkpoint System

```
Every 10,000 transactions:
  1. Serialize state (tx_count, clocks, boxes, entropy)
  2. Encrypt with checkpoint key (derived from seed)
  3. Save to platform-specific location
  4. On restart: decrypt, verify, restore state
```

---

## 💡 Use Cases

### ✅ Appropriate Use Cases

| Use Case | Why TAV Works |
|----------|---------------|
| **IoT Sensors** | Low memory, no network for key exchange |
| **Embedded Systems** | Self-contained, no crypto library dependencies |
| **Research/Education** | Auditable code, novel concepts |
| **Prototyping** | Quick integration, multiple languages |
| **Device Pairing** | Stateful authentication without PKI |
| **Content Authenticity** | Device fingerprinting for fraud prevention |
| **Offline Systems** | No network required for key establishment |

### ❌ Inappropriate Use Cases

| Use Case | Why Not |
|----------|---------|
| **Production Financial Systems** | Needs formal audit first |
| **Healthcare Data** | Regulatory compliance requires proven algorithms |
| **Government/Military** | Needs FIPS certification |
| **High-Throughput Encryption** | Use AES-NI or ChaCha20-SIMD |
| **Long-Term Archival** | Unproven longevity |


## Project Structure

```
tav-crypto/
├── README.md
├── TAV_CBA_PROTOCOL.md
├── TAV_PAPER_V3_EN.pdf        # ZENODO DOI https://doi.org/10.5281/zenodo.17753449
├── LICENSE                    # AGPL-3.0
├── COMMERCIAL_LICENSE.md      # Commercial terms
├── CITATION.cff               # How to cite
├── SECURITY.md                # Vulnerability reporting
├── CONTRIBUTING.md            # Contribution guidelines
├── src/
│   ├── c/
│   │   ├── tav.c
│   │   ├── tav_sign.c
│   │   └── tav_openssl_engine.c
│   ├── rust/
│   │   └── lib.rs
│   ├── python/
│   │   ├── tav_cba_protocol.py
│   │   └── tav_crypto.py
│   ├── js/
│   │   └── tav.js
│   └── arduino/
│       └── tav_arduino.h
└── tests/
    ├── test_vectors.json
    ├── test_vectors.h
    └── test_runner.c
```


## 📥 Installation

### Python

```bash
# Clone repository
git clone https://github.com/carlostbastos/tav-crypto.git
cd tav-crypto

# Use directly
python -c "from tav_crypto import TAV; print(TAV('test', nivel='consumer').status())"
```

### C

```bash
# Compile as library
gcc -c tav.c -o tav.o
ar rcs libtav.a tav.o

# Or compile with your project
gcc -o myapp myapp.c tav.c -lm
```

### JavaScript (Node.js)

```bash
# Copy tav.js to your project
cp tav.js /your/project/

# Use in code
const { TAVCrypto } = require('./tav.js');
```

### Rust

```toml
# Add to Cargo.toml (when published)
[dependencies]
tav-crypto = "0.9"

# Or use local path
[dependencies]
tav-crypto = { path = "../tav-crypto" }
```

### Arduino

```cpp
// Copy tav_arduino.h to your sketch folder
// Include in your sketch
#include "tav_arduino.h"
```

### OpenSSL Engine

```bash
# Compile engine
gcc -shared -fPIC -o libtav_engine.so tav_openssl_engine.c tav.c -lcrypto

# Test
openssl engine -t ./libtav_engine.so

# Use
openssl enc -engine ./libtav_engine.so -tav-consumer -in plain.txt -out encrypted.bin
```

---

## 📚 API Reference

### Python API

```python
class TAV:
    def __init__(self, seed: str, nivel: str = "consumer", instance_id: str = "default")
    def encrypt(self, plaintext: bytes, auto_tick: bool = True) -> bytes
    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, bool]
    def tick(self, n: int = 1) -> dict
    def status(self) -> dict
    def verificar_hardware(self) -> Tuple[bool, float]
    def verificar_dead_man(self, limite: int = 10000) -> bool
    def forcar_checkpoint(self) -> None
```

### C API

```c
tav_result_t tav_init(tav_ctx_t* ctx, const uint8_t* seed, size_t seed_len, tav_level_t level);
void tav_cleanup(tav_ctx_t* ctx);
tav_result_t tav_encrypt(tav_ctx_t* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct, size_t* ct_len, bool auto_tick);
tav_result_t tav_decrypt(tav_ctx_t* ctx, const uint8_t* ct, size_t ct_len, uint8_t* pt, size_t* pt_len);
void tav_tick(tav_ctx_t* ctx, uint32_t n);
bool tav_verify_hardware(tav_ctx_t* ctx, float* similarity);
tav_result_t tav_force_checkpoint(tav_ctx_t* ctx);
void tav_get_stats(tav_ctx_t* ctx, uint64_t* tx_count, uint32_t* boot_count, uint64_t* last_checkpoint, bool* hw_changed);
```

### JavaScript API

```javascript
class TAVCrypto {
    constructor(seed: string, level: string | number, instanceId?: string)
    encrypt(plaintext: Uint8Array | string, autoTick?: boolean): Uint8Array
    decrypt(ciphertext: Uint8Array): { success: boolean, data: Uint8Array | null }
    tick(n?: number): void
    status(): object
    setCheckpointCallbacks(save: Function, load: Function): void
    forceCheckpoint(): void
}
```

### Rust API

```rust
impl Tav {
    pub fn new(seed: &str, level: SecurityLevel) -> Result<Self>;
    pub fn encrypt(&mut self, plaintext: &[u8], auto_tick: bool) -> Result<Vec<u8>>;
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    pub fn tick(&mut self, n: u32);
    pub fn status(&self) -> TavStatus;
    pub fn force_checkpoint(&mut self);
}
```

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [TAV_PAPER_v09.md](TAV_PAPER_v09.md) | Complete technical paper with theory, implementation, and analysis |
| [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) | Commercial licensing terms and pricing |
| [LICENSE](LICENSE) | AGPL-3.0 full text |

### Technical Paper Contents

1. Introduction and Motivation
2. The Concept of Ephemeral Structure
3. Related Work (Jitterentropy, ARX ciphers, NIST PQC)
4. TAV Architecture (all components detailed)
5. Security Analysis
6. Implementation (5 languages)
7. Performance Evaluation
8. Validation Results (40 tests)
9. Discussion and Future Work

---

## 📜 License

TAV is dual-licensed:

### Open Source (AGPL-3.0)

**Free forever** for:
- ✅ Personal use
- ✅ Academic and research use
- ✅ Open source projects

The only obligation: if you distribute TAV or provide it as a network service, you must make your source code available under AGPL-3.0.

### Commercial License

**Free until May 31, 2027** for any commercial use.

After May 2027, annual licensing based on company size (revenue):

| Company Size | Annual License |
|--------------|----------------|
| Micro (< $100K) | $99 - $299 |
| Small (< $1M) | $499 - $1,499 |
| Medium (< $10M) | $2,499 - $4,999 |
| Large (< $100M) | $9,999 - $24,999 |
| Enterprise ($100M+) | Custom |

See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for full terms.

---

## 📬 Contact

**Carlos Alberto Terencio de Bastos**

| Channel | Link |
|---------|------|
| 📧 Email | caterencio@yahoo.com.br |
| 💼 LinkedIn | [carlos-alberto-t-b7a055ba](https://linkedin.com/in/carlos-alberto-t-b7a055ba) |
| 🐙 GitHub | [carlostbastos/tav-crypto](https://github.com/carlostbastos/tav-crypto) |
| 💝 Donate | [PayPal](https://www.paypal.com/donate/?hosted_button_id=S6KMBHT8PWSC2) |

---

## 📖 Citation

If you use TAV in academic work, please cite:

```bibtex
@software{bastos2025tav,
  author       = {Bastos, Carlos Alberto Terencio de},
  title        = {{TAV Clock Cryptography: A Stateful Cryptographic System 
                   Based on Ephemeral Structure and Continuous Physical Entropy}},
  version      = {0.9},
  year         = {2025},
  month        = {November},
  url          = {https://github.com/carlostbastos/tav-crypto},
  note         = {Experimental research software}
}
```

---

## 🙏 Acknowledgments

Thanks to:
- All donors who support this independent research
- The cryptographic community for feedback and suggestions
- Open source contributors and testers

**Special thanks to early adopters who help improve TAV!**

---

<p align="center">
  <b>TAV Clock Cryptography v0.9</b><br>
  <i>Transactional Asynchronous Verification</i><br>
  November 2025 - Initial Public Release
</p>

<p align="center">
  <sub>Made with ☕ and 🔐 in Brazil</sub>
</p>

```
  _____  ___ _   __
 |_   _|/ _ \ | / /
   | | / /_\ \ |/ / 
   | | |  _  |   \  
   | | | | | | |\ \ 
   \_/ \_| |_/_| \_\
```

---

<p align="center">
  <a href="#tav-clock-cryptography">⬆ Back to Top</a>
</p>
