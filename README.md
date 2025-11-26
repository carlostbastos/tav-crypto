# TAV Clock Cryptography

**Transactional Asynchronous Verification** - A novel stateful cryptographic system with continuous physical entropy and prime-period transactional clocks.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Status: Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg)]()
[![Version: 9.1](https://img.shields.io/badge/Version-9.1-green.svg)]()

## ⚠️ Important Notice

**TAV is experimental research software.** It has NOT been audited, formally verified, or reviewed by professional cryptographers. **Do not use in production systems or for protecting sensitive data.**

This project is published for:
- Academic research and peer review
- Educational purposes
- Cryptographic experimentation
- Community analysis and feedback

## Overview

TAV (Transactional Asynchronous Verification) is a complete cryptographic system that integrates:

- **Physical Entropy Generator** - Continuous collection from CPU timing jitter
- **Multi-Clock State Machine** - Four transactional clocks with coprime prime periods (17, 23, 31, 47)
- **Prime Number Boxes** - Six boxes containing 21-500 primes each for key derivation
- **Stream Cipher** - XOR-based encryption with Feistel mixing
- **MAC Authentication** - Integrated message authentication without external hash functions

### Key Characteristics

| Feature | TAV Approach |
|---------|--------------|
| External Hash | None required |
| Modular Addition | Not used (avoids rotational cryptanalysis) |
| Operations | XOR, AND, OR, ROT only |
| State Period | LCM(17,23,31,47) = 563,327 transactions minimum |
| Entropy Source | Continuous CPU timing jitter |

## Performance

| Metric | Value |
|--------|-------|
| Encryption Throughput | ~3,892 KB/s |
| Entropy Generation | ~622 KB/s |
| Shannon Entropy | 7.996 bits/byte |
| NIST SP 800-22 | 6/6 tests PASS |

*Note: TAV prioritizes simplicity and auditability over raw speed.*

## Implementations

| Language | Lines | File | Status |
|----------|-------|------|--------|
| C | 1,608 | `src/c/tav.c` | ✅ Complete |
| Rust | 1,101 | `src/rust/lib.rs` | ✅ Complete |
| JavaScript | 928 | `src/js/tav.js` | ✅ Complete |
| Arduino/ESP32 | 790 | `src/arduino/tav_arduino.h` | ✅ Complete |

### Interoperability

- 100% hash compatibility between C and JavaScript
- 100% signature compatibility between C and JavaScript
- Test vectors provided in JSON format

## Quick Start

### C
```c
#include "tav.h"

TAVContext ctx;
tav_init(&ctx, TAV_SECURITY_CONSUMER);

uint8_t key[32], plaintext[64], ciphertext[64];
tav_generate_key(&ctx, key, 32);
tav_encrypt(&ctx, plaintext, ciphertext, 64, key);
```

### JavaScript
```javascript
import { TAV } from './tav.js';

const tav = new TAV(TAV.SECURITY_CONSUMER);
const key = tav.generateKey(32);
const ciphertext = tav.encrypt(plaintext, key);
```

### Rust
```rust
use tav::{TAVContext, SecurityLevel};

let mut ctx = TAVContext::new(SecurityLevel::Consumer);
let key = ctx.generate_key(32);
let ciphertext = ctx.encrypt(&plaintext, &key);
```

## Security Levels

| Level | Rounds | Prime Box | Use Case |
|-------|--------|-----------|----------|
| IoT | 8 | 21 primes | Constrained devices |
| Consumer | 12 | 101 primes | General applications |
| Enterprise | 16 | 251 primes | Business systems |
| Military | 24 | 500 primes | Maximum security |

## Digital Signatures

TAV provides two signature schemes:

### Hash-Chain (Lamport-style)
- Signature size: 66 bytes
- One-time use per key
- Quantum-resistant by design

### Commitment-Reveal
- Signature size: 72 bytes
- Interactive protocol
- Suitable for challenge-response

## Project Structure

```
tav-crypto/
├── README.md
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
│   ├── js/
│   │   └── tav.js
│   └── arduino/
│       └── tav_arduino.h
└── tests/
    ├── test_vectors.json
    ├── test_vectors.h
    └── test_runner.c
```

## Known Limitations

1. **No formal security proofs** - Security claims are theoretical
2. **No professional audit** - Code has not been reviewed by cryptographers
3. **No side-channel analysis** - Timing attacks not evaluated
4. **Limited real-world testing** - No production deployment
5. **Performance trade-off** - Slower than optimized alternatives

## Comparison with Established Systems

| Aspect | ChaCha20 | AES-GCM | ML-KEM | TAV |
|--------|----------|---------|--------|-----|
| Type | Stream cipher | Block cipher | KEM | Integrated system |
| Speed | ~1000 MB/s | ~3000 MB/s | <1ms keygen | ~3.8 MB/s |
| External deps | Poly1305 | GHASH | SHA3/SHAKE | None |
| Standardization | RFC 8439 | NIST | NIST 2024 | Experimental |
| Audit status | Extensive | Extensive | Extensive | None |

## License

### Open Source
This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

### Commercial Use
**Free commercial use until November 2026.** See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for details.

After November 2026, commercial users who cannot comply with AGPL terms should contact the author for a commercial license.

## Citation

If you use TAV in academic work, please cite:

```bibtex
@software{bastos2025tav,
  author = {Bastos, Carlos Alberto Terencio de},
  title = {TAV Clock Cryptography: Stateful Encryption with Prime-Period Transactional Clocks},
  version = {9.1},
  year = {2025},
  url = {https://github.com/caterencio/tav-crypto}
}
```

## Author

**Carlos Alberto Terencio de Bastos**
- Email: caterencio@yahoo.com.br
- GitHub: https://github.com/carlostbastos/

## Support the Project

TAV is developed independently. If you find it useful for research or education:

- ⭐ Star this repository
- 🐛 Report issues and vulnerabilities
- 🔬 Conduct independent analysis
- 📝 Cite in academic work
- 💬 Share feedback

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The author makes no claims about the cryptographic security of this system. Use at your own risk. This software should NOT be used to protect sensitive data until it has been thoroughly analyzed by the cryptographic community.

---

*TAV: Exploring the intersection of physical entropy and stateful cryptography.*
