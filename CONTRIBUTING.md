# Contributing to TAV

Thank you for your interest in contributing to TAV! This document provides guidelines for contributing to the project.

## 🎯 Project Goals

TAV is an **experimental cryptographic system** for:
- Academic research
- Educational purposes
- Cryptographic experimentation
- Community analysis

**TAV is NOT intended for production use yet.**

---

## 🤝 Ways to Contribute

### 1. Cryptographic Analysis

The most valuable contribution is independent security analysis:

- **Cryptanalysis** - Attempt to break TAV's security claims
- **Formal verification** - Prove or disprove security properties
- **Side-channel analysis** - Evaluate timing, power, cache attacks
- **Statistical testing** - Additional randomness tests

### 2. Code Contributions

- **Bug fixes** - Fix implementation errors
- **Optimizations** - Improve performance without compromising security
- **New implementations** - Port to other languages
- **Test coverage** - Add unit and integration tests

### 3. Documentation

- **Clarifications** - Improve existing documentation
- **Examples** - Add usage examples
- **Translations** - Translate docs to other languages
- **Tutorials** - Write guides for specific use cases

### 4. Community

- **Issue triage** - Help categorize and respond to issues
- **Code review** - Review pull requests
- **Discussion** - Participate in design discussions

---

## 📋 Contribution Process

### For Small Changes

1. Fork the repository
2. Create a branch: `git checkout -b fix/description`
3. Make your changes
4. Test thoroughly
5. Submit a Pull Request

### For Large Changes

1. **Open an Issue first** - Discuss the change before implementing
2. Wait for feedback
3. Fork and implement
4. Submit a Pull Request referencing the issue

---

## 🔧 Development Setup

### C Implementation

```bash
# Compile
gcc -O2 -o tav_test src/c/tav.c tests/test_runner.c -lm

# Run tests
./tav_test
```

### Rust Implementation

```bash
cd src/rust
cargo build
cargo test
```

### JavaScript Implementation

```bash
cd src/js
node --test tav.test.js
```

---

## 📐 Code Standards

### C Code

- Follow K&R style with 4-space indentation
- Use `snake_case` for functions and variables
- Add comments for non-obvious logic
- No external dependencies (except standard library)

### Rust Code

- Follow standard Rust conventions
- Use `cargo fmt` before committing
- Use `cargo clippy` to check for issues
- Add documentation comments for public APIs

### JavaScript Code

- ES6+ syntax
- Use `camelCase` for functions and variables
- Add JSDoc comments for public functions
- No external dependencies

### All Languages

- Maintain interoperability (same test vectors must pass)
- Keep security-critical code simple and auditable
- Avoid unnecessary complexity

---

## ✅ Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code compiles without warnings
- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] Documentation updated if needed
- [ ] Commit messages are clear and descriptive
- [ ] PR description explains the change
- [ ] No unrelated changes included

---

## 🧪 Testing Requirements

### For Bug Fixes

- Add a test that fails before the fix
- Verify the test passes after the fix

### For New Features

- Add comprehensive unit tests
- Add integration tests if applicable
- Update test vectors if cryptographic output changes

### For Cryptographic Changes

- **Justify the change** - Explain why it improves security
- **Maintain compatibility** - Or document breaking changes
- **Update all implementations** - Changes must be reflected in C, Rust, and JS

---

## 📜 Contributor License Agreement

By contributing to TAV, you agree that:

1. Your contributions are your own original work
2. You have the right to submit the contribution
3. You grant the project a perpetual, worldwide, non-exclusive, royalty-free license to use your contribution
4. Your contribution may be distributed under AGPL-3.0 and/or commercial license
5. You understand TAV is experimental and makes no security guarantees

---

## 🏷️ Issue Labels

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `enhancement` | New feature or request |
| `security` | Security-related issue |
| `documentation` | Documentation improvements |
| `cryptanalysis` | Security analysis findings |
| `help wanted` | Extra attention needed |
| `good first issue` | Good for newcomers |

---

## 💬 Communication

- **GitHub Issues** - Bug reports, feature requests
- **GitHub Discussions** - General questions, ideas
- **Email** - caterencio@yahoo.com.br (for private matters)

---

## 🙏 Recognition

Contributors will be recognized in:

- `CONTRIBUTORS.md` file
- Release notes
- Academic papers (for significant contributions)

---

## ❓ Questions?

If you're unsure about anything, open an issue with the `question` label. We're happy to help!

---

*Thank you for helping improve TAV!*
