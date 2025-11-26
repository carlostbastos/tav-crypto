#!/bin/bash
#
# TAV INTEROPERABILITY TEST SUITE
# ================================
#
# Testa interoperabilidade entre implementações C, JavaScript e Rust.
#
# Uso: ./run_interop_tests.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "═══════════════════════════════════════════════════════════════════"
echo "TAV INTEROPERABILITY TEST SUITE"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Root directory: $ROOT_DIR"
echo ""

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Contadores
TOTAL_PASSED=0
TOTAL_FAILED=0

# Função para reportar resultado
report() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
        ((TOTAL_PASSED++))
    else
        echo -e "${RED}❌ $2${NC}"
        ((TOTAL_FAILED++))
    fi
}

# =============================================================================
# PASSO 1: Compilar ferramentas C
# =============================================================================

echo "📦 STEP 1: Building C tools..."
echo ""

cd "$SCRIPT_DIR"

# Gerador C
echo "   Compiling C vector generator..."
gcc -O2 -I../../c interop_generate_c.c ../../c/tav.c ../../c/tav_sign.c \
    -o interop_generate_c -lm 2>&1 && \
    report 0 "C generator compiled" || \
    report 1 "C generator compilation failed"

# Validador C
echo "   Compiling C validator..."
gcc -O2 -I../../c interop_validate_c.c ../../c/tav.c ../../c/tav_sign.c \
    -o interop_validate_c -lm 2>&1 && \
    report 0 "C validator compiled" || \
    report 1 "C validator compilation failed"

echo ""

# =============================================================================
# PASSO 2: Verificar Node.js
# =============================================================================

echo "📦 STEP 2: Checking Node.js..."
echo ""

if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo "   Node.js version: $NODE_VERSION"
    report 0 "Node.js available"
    HAS_NODE=1
else
    echo "   Node.js not found"
    report 1 "Node.js not available (skipping JS tests)"
    HAS_NODE=0
fi

echo ""

# =============================================================================
# PASSO 3: Gerar vetores
# =============================================================================

echo "📦 STEP 3: Generating test vectors..."
echo ""

# Gerar vetores do C
echo "   Generating vectors from C implementation..."
./interop_generate_c > vectors_from_c.json 2>&1 && \
    report 0 "C vectors generated (vectors_from_c.json)" || \
    report 1 "C vector generation failed"

# Gerar vetores do JS
if [ $HAS_NODE -eq 1 ]; then
    echo "   Generating vectors from JavaScript implementation..."
    node interop_generate_js.js > vectors_from_js.json 2>&1 && \
        report 0 "JS vectors generated (vectors_from_js.json)" || \
        report 1 "JS vector generation failed"
fi

echo ""

# =============================================================================
# PASSO 4: Validação cruzada
# =============================================================================

echo "📦 STEP 4: Cross-validation..."
echo ""

# C valida vetores do JS
if [ $HAS_NODE -eq 1 ] && [ -f vectors_from_js.json ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "C validating JavaScript vectors:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if ./interop_validate_c vectors_from_js.json; then
        report 0 "C validated JS vectors"
    else
        report 1 "C failed to validate JS vectors"
    fi
    echo ""
fi

# JS valida vetores do C
if [ $HAS_NODE -eq 1 ] && [ -f vectors_from_c.json ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "JavaScript validating C vectors:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if node interop_validate_js.js vectors_from_c.json; then
        report 0 "JS validated C vectors"
    else
        report 1 "JS failed to validate C vectors"
    fi
    echo ""
fi

# =============================================================================
# PASSO 5: Comparação direta de hashes
# =============================================================================

echo "📦 STEP 5: Direct hash comparison..."
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Comparing hash outputs:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f vectors_from_c.json ] && [ -f vectors_from_js.json ]; then
    # Extrai hashes de "TAV" de ambos os arquivos
    C_HASH=$(grep -A5 '"tav_string"' vectors_from_c.json | grep 'output_hex' | cut -d'"' -f4)
    JS_HASH=$(grep -A5 '"tav_string"' vectors_from_js.json | grep 'output_hex' | cut -d'"' -f4)
    
    echo "   Input: 'TAV'"
    echo "   C  hash: $C_HASH"
    echo "   JS hash: $JS_HASH"
    
    if [ "$C_HASH" = "$JS_HASH" ]; then
        report 0 "Hash('TAV') matches between C and JS"
    else
        report 1 "Hash('TAV') MISMATCH between C and JS"
    fi
    
    # Extrai hashes de "Hello, World!"
    C_HASH=$(grep -A5 '"hello_world"' vectors_from_c.json | grep 'output_hex' | cut -d'"' -f4)
    JS_HASH=$(grep -A5 '"hello_world"' vectors_from_js.json | grep 'output_hex' | cut -d'"' -f4)
    
    echo ""
    echo "   Input: 'Hello, World!'"
    echo "   C  hash: $C_HASH"
    echo "   JS hash: $JS_HASH"
    
    if [ "$C_HASH" = "$JS_HASH" ]; then
        report 0 "Hash('Hello, World!') matches between C and JS"
    else
        report 1 "Hash('Hello, World!') MISMATCH between C and JS"
    fi
fi

echo ""

# =============================================================================
# PASSO 6: Comparação de assinaturas
# =============================================================================

echo "📦 STEP 6: Signature comparison..."
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Comparing signature outputs:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f vectors_from_c.json ] && [ -f vectors_from_js.json ]; then
    # Extrai public keys
    C_PUBKEY=$(grep -A10 '"basic_100"' vectors_from_c.json | grep 'public_key_hex' | cut -d'"' -f4)
    JS_PUBKEY=$(grep -A10 '"basic_100"' vectors_from_js.json | grep 'public_key_hex' | cut -d'"' -f4)
    
    echo "   Test: basic_100"
    echo "   C  pubkey: ${C_PUBKEY:0:32}..."
    echo "   JS pubkey: ${JS_PUBKEY:0:32}..."
    
    if [ "$C_PUBKEY" = "$JS_PUBKEY" ]; then
        report 0 "Public keys match between C and JS"
    else
        report 1 "Public keys MISMATCH between C and JS"
    fi
    
    # Extrai signatures
    C_SIG=$(grep -A10 '"basic_100"' vectors_from_c.json | grep 'signature_hex' | cut -d'"' -f4)
    JS_SIG=$(grep -A10 '"basic_100"' vectors_from_js.json | grep 'signature_hex' | cut -d'"' -f4)
    
    echo ""
    echo "   C  signature: ${C_SIG:0:32}..."
    echo "   JS signature: ${JS_SIG:0:32}..."
    
    if [ "$C_SIG" = "$JS_SIG" ]; then
        report 0 "Signatures match between C and JS"
    else
        report 1 "Signatures MISMATCH between C and JS"
    fi
fi

echo ""

# =============================================================================
# SUMÁRIO
# =============================================================================

echo "═══════════════════════════════════════════════════════════════════"
echo "                         FINAL RESULTS"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo -e "   Passed: ${GREEN}$TOTAL_PASSED${NC}"
echo -e "   Failed: ${RED}$TOTAL_FAILED${NC}"
echo ""

if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL INTEROPERABILITY TESTS PASSED!${NC}"
    echo ""
    echo "C and JavaScript implementations produce identical results for:"
    echo "  - Hash function"
    echo "  - Key derivation"
    echo "  - Digital signatures"
    exit 0
else
    echo -e "${RED}⚠️  SOME TESTS FAILED - INTEROPERABILITY ISSUES DETECTED${NC}"
    echo ""
    echo "Check the output above for details on which tests failed."
    exit 1
fi
