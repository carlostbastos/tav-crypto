# Security Policy

## ⚠️ Important Disclaimer

**TAV is experimental software.** It has NOT been:
- Professionally audited
- Formally verified
- Reviewed by cryptographers
- Tested against side-channel attacks
- Deployed in production environments

**Do NOT use TAV to protect sensitive data.**

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 9.1.x   | :white_check_mark: |
| < 9.1   | :x:                |

Only the latest version receives security updates.

---

## Reporting a Vulnerability

We take security seriously, even for experimental software. If you discover a vulnerability:

### For Non-Critical Issues

1. **Open a GitHub Issue** with the label `security`
2. Describe the vulnerability
3. Include steps to reproduce
4. Suggest a fix if possible

### For Critical Issues

If you believe the vulnerability could cause significant harm:

1. **Email directly**: caterencio@yahoo.com.br
2. **Subject line**: `[TAV SECURITY] Brief description`
3. **Include**:
   - Detailed description of the vulnerability
   - Proof of concept (if available)
   - Potential impact assessment
   - Your suggested fix (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| 24-48 hours | Acknowledgment of report |
| 7 days | Initial assessment |
| 30 days | Fix development (if applicable) |
| 90 days | Public disclosure (coordinated) |

---

## Scope

### In Scope

- Cryptographic weaknesses in TAV algorithms
- Implementation bugs that compromise security
- Key derivation vulnerabilities
- Entropy source weaknesses
- Authentication bypasses
- Information leakage

### Out of Scope

- Denial of service attacks
- Social engineering
- Physical attacks requiring device access
- Attacks requiring malicious dependencies
- Issues in example code or documentation

---

## Known Limitations

These are **not** vulnerabilities but acknowledged limitations:

1. **No formal proofs** - Security is theoretical, not proven
2. **Timing side-channels** - Not analyzed or mitigated
3. **Power analysis** - Not considered in design
4. **Cache attacks** - Not addressed
5. **Fault injection** - No countermeasures

---

## Security Best Practices

If you choose to experiment with TAV:

1. **Never use for sensitive data** - Use established algorithms instead
2. **Assume it's broken** - Treat TAV as educational, not secure
3. **Layer security** - Don't rely solely on TAV
4. **Monitor for updates** - Check this repository regularly
5. **Contribute analysis** - Help the community understand TAV better

---

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Coordinate** - Work with reporters on timing
2. **Credit** - Acknowledge researchers (unless anonymity requested)
3. **No legal action** - We won't pursue legal action against good-faith researchers
4. **Transparency** - Publish details after fixes are available

---

## Hall of Fame

Security researchers who have contributed to TAV's security:

*No entries yet - be the first!*

---

## Contact

**Carlos Alberto Terencio de Bastos**
- Security reports: caterencio@yahoo.com.br
- General inquiries: GitHub Issues

---

*Thank you for helping make TAV better, even if it's just for research purposes.*
