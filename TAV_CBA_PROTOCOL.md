# TAV Capability-Based Authentication (CBA) Protocol

## Visão Geral

O protocolo CBA combina **três camadas** de autenticação para resolver as limitações dos protocolos originais:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PROTOCOLO CBA                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐   │
│   │   IDENTIDADE    │   │     SESSÃO      │   │    CAPABILITIES     │   │
│   │  (Hash-Chain)   │ + │  (Commitment-   │ + │  (Controle Acesso)  │   │
│   │                 │   │    Reveal)      │   │                     │   │
│   └────────┬────────┘   └────────┬────────┘   └──────────┬──────────┘   │
│            │                     │                       │               │
│            v                     v                       v               │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │                     PROVA CBA (CBAProof)                       │    │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │    │
│   │  │ Identity │ │ Session  │ │Capability│ │ Operation+       │   │    │
│   │  │  Proof   │ │  Proof   │ │    ID    │ │ Resource+Nonce   │   │    │
│   │  │(opcional)│ │          │ │          │ │                  │   │    │
│   │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Comparação dos 3 Protocolos

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    HASH-CHAIN (Original)                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   S₀ ──hash──> S₁ ──hash──> S₂ ──hash──> ... ──hash──> Sₙ (public key)      │
│   ▲                                                      │                   │
│   │                                                      │                   │
│   private                                              public                │
│                                                                              │
│   ASSINATURA #i: Revela S_{n-i}                                             │
│                                                                              │
│   ✓ Quantum-safe        ✓ Verificação independente                          │
│   ✗ LIMITADO (n usos)   ✗ Sem controle granular                             │
│                                                                              │
│   Tamanho: 66 bytes                                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                  COMMITMENT-REVEAL (Original)                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   master_entropy ──hash──> commitment (public key)                          │
│         │                                                                    │
│         ├── + tx_count ──hash──> state_proof                                │
│         │                                                                    │
│         └── + message ──MAC──> signature                                    │
│                                                                              │
│   ✓ ILIMITADO            ✓ Único por transação                              │
│   ✗ Requer sincronização ✗ Sem controle granular                            │
│                                                                              │
│   Tamanho: 72 bytes                                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         CBA (NOVO - HÍBRIDO)                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   CAMADA 1: IDENTIDADE (Hash-Chain)                                         │
│   ─────────────────────────────────                                         │
│   • Usado APENAS para:                                                       │
│     - Criar capabilities raiz                                                │
│     - Assinar capabilities delegadas                                         │
│     - Emergências/recovery                                                   │
│   • Preserva assinaturas valiosas                                           │
│                                                                              │
│   CAMADA 2: SESSÃO (Commitment-Reveal)                                       │
│   ──────────────────────────────────                                         │
│   • Usado para operações do dia-a-dia                                        │
│   • ILIMITADO dentro da sessão                                               │
│   • Vinculado a capability como âncora                                       │
│                                                                              │
│   CAMADA 3: CAPABILITIES (NOVO)                                              │
│   ─────────────────────────────                                              │
│   • Define QUEM pode fazer O QUÊ em QUAIS recursos                          │
│   • Delegável com RESTRIÇÕES automáticas                                     │
│   • Revogável instantaneamente                                               │
│   • Limites de uso e tempo                                                   │
│                                                                              │
│   ✓ Ilimitado para operações comuns                                         │
│   ✓ Forte para operações críticas                                           │
│   ✓ Controle de acesso granular                                             │
│   ✓ Delegação segura                                                        │
│   ✓ Revogação instantânea                                                   │
│                                                                              │
│   Tamanhos: Capability ~200 bytes, Proof ~120-200 bytes                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Fluxo de Delegação

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CADEIA DE DELEGAÇÃO                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                         ALICE (Root)                              │     │
│   │  IdentityKey: 0x1234...                                           │     │
│   │  Permissões: FULL_ACCESS                                          │     │
│   │  Recursos: {"*"}                                                  │     │
│   └───────────────────────────┬───────────────────────────────────────┘     │
│                               │                                              │
│                               │ EMITE (usa 1 assinatura de identidade)       │
│                               v                                              │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                       CAPABILITY #1 (para Bob)                    │     │
│   │  depth: 0                                                         │     │
│   │  Permissões: READ | ENCRYPT | DELEGATE                           │     │
│   │  Recursos: {"file:a.txt", "file:b.pdf", "channel:123"}           │     │
│   │  max_uses: 50                                                     │     │
│   │  max_delegation: 2                                                │     │
│   │  assinatura: Alice.sign()                                         │     │
│   └───────────────────────────┬───────────────────────────────────────┘     │
│                               │                                              │
│                               │ BOB DELEGA (usa 1 assinatura)                │
│                               v                                              │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                     CAPABILITY #2 (para Carol)                    │     │
│   │  depth: 1                                                         │     │
│   │  Permissões: READ         ← RESTRITO (≤ parent)                  │     │
│   │  Recursos: {"file:a.txt"} ← RESTRITO (⊆ parent)                  │     │
│   │  max_uses: 50             ← HERDADO                               │     │
│   │  max_delegation: 2 (Carol só pode delegar mais 1 nível)          │     │
│   │  parent: Capability #1                                            │     │
│   │  assinatura: Bob.sign()                                           │     │
│   └───────────────────────────┬───────────────────────────────────────┘     │
│                               │                                              │
│                               │ CAROL DELEGA                                 │
│                               v                                              │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │                     CAPABILITY #3 (para Dave)                     │     │
│   │  depth: 2  ← MÁXIMO ATINGIDO                                      │     │
│   │  Permissões: READ                                                 │     │
│   │  Recursos: {"file:a.txt"}                                         │     │
│   │  max_delegation: 2 (Dave NÃO pode delegar - depth = max)         │     │
│   │  parent: Capability #2                                            │     │
│   │  assinatura: Carol.sign()                                         │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│   DAVE tenta delegar → ERRO: "Profundidade máxima atingida"                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Estrutura da Prova CBA

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CBAProof                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Offset  │ Campo              │ Tamanho │ Descrição                        │
│   ────────┼────────────────────┼─────────┼─────────────────────────────────│
│   0       │ Magic ("TPRF")     │ 4       │ Identificador                    │
│   4       │ Version            │ 1       │ Versão do protocolo              │
│   5       │ capability_id      │ 16      │ ID da capability usada           │
│   21      │ session_proof      │ 32      │ Prova do estado da sessão        │
│   53      │ operation_len      │ 1       │ Tamanho da operação              │
│   54      │ operation          │ var     │ "READ", "WRITE", etc.            │
│   ...     │ resource_len       │ 2       │ Tamanho do recurso               │
│   ...     │ resource_id        │ var     │ "file:doc.txt", etc.             │
│   ...     │ timestamp          │ 8       │ Unix timestamp                   │
│   ...     │ nonce              │ 16      │ Anti-replay                      │
│   ...     │ proof_signature    │ 32      │ MAC final                        │
│   ...     │ has_identity       │ 1       │ Flag                             │
│   ...     │ identity_proof     │ 66      │ (opcional) Prova de identidade   │
│   ...     │ chain_index        │ 2       │ (opcional) Índice usado          │
│                                                                              │
│   Tamanho típico: 120-200 bytes                                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Permissões Granulares

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            SISTEMA DE PERMISSÕES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Bit │ Permissão  │ Descrição                                              │
│   ────┼────────────┼───────────────────────────────────────────────────────│
│   0   │ READ       │ Ler dados do recurso                                   │
│   1   │ WRITE      │ Escrever dados no recurso                              │
│   2   │ DELETE     │ Deletar o recurso                                      │
│   3   │ ENCRYPT    │ Usar TAV.encrypt() no recurso                          │
│   4   │ DECRYPT    │ Usar TAV.decrypt() no recurso                          │
│   5   │ SIGN       │ Assinar dados relacionados ao recurso                  │
│   6   │ VERIFY     │ Verificar assinaturas                                  │
│   7   │ DELEGATE   │ Criar sub-capabilities                                 │
│   8   │ REVOKE     │ Revogar capabilities derivadas                         │
│   9   │ ADMIN      │ Acesso administrativo total                            │
│                                                                              │
│   COMBINAÇÕES PRÉ-DEFINIDAS:                                                 │
│   ──────────────────────────                                                 │
│   READ_ONLY    = READ | VERIFY                              = 0x41 (65)     │
│   READ_WRITE   = READ | WRITE | ENCRYPT | DECRYPT           = 0x1B (27)     │
│   FULL_CRYPTO  = ENCRYPT | DECRYPT | SIGN | VERIFY          = 0x78 (120)    │
│   DELEGATOR    = READ | WRITE | DELEGATE                    = 0x83 (131)    │
│   FULL_ACCESS  = todos                                      = 0x3FF (1023)  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Revogação

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SISTEMA DE REVOGAÇÃO                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   REVOGAÇÃO DIRETA:                                                          │
│   ─────────────────                                                          │
│   Alice revoga Capability #1                                                 │
│      │                                                                       │
│      └──> Capability #1.revoked = true                                       │
│           Capability #1.revoked_at = timestamp                               │
│           revocation_list.add(Capability #1.id)                              │
│                                                                              │
│   REVOGAÇÃO EM CASCATA (opcional):                                           │
│   ─────────────────────────────────                                          │
│   Quando Capability #1 é revogada:                                           │
│      │                                                                       │
│      ├──> Capability #2 (parent = #1) → TAMBÉM revogada                     │
│      │      │                                                                │
│      │      └──> Capability #3 (parent = #2) → TAMBÉM revogada              │
│      │                                                                       │
│      └──> Toda a cadeia de delegação é invalidada                           │
│                                                                              │
│   VERIFICAÇÃO:                                                               │
│   ────────────                                                               │
│   Ao verificar uma prova:                                                    │
│   1. Checa se capability_id está em revocation_list → FALHA                 │
│   2. Checa se capability.revoked == true → FALHA                            │
│   3. (Opcional) Checa toda a cadeia de parents                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Casos de Uso

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CASOS DE USO                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. IoT SENSOR NETWORK                                                      │
│   ─────────────────────                                                      │
│   • Gateway tem capability FULL_ACCESS                                       │
│   • Sensores recebem capabilities READ | ENCRYPT (dados próprios)           │
│   • Atuadores recebem DECRYPT | WRITE (comandos recebidos)                  │
│   • Revogação instantânea se sensor comprometido                            │
│                                                                              │
│   2. CONTEÚDO AUTENTICADO (anti-deepfake)                                   │
│   ────────────────────────────────────────                                   │
│   • Criador de conteúdo: capability SIGN para seus vídeos                   │
│   • Plataforma: capability VERIFY para todos os conteúdos                   │
│   • Viewer: recebe prova junto com conteúdo                                 │
│   • Sem capability válida = conteúdo potencialmente falso                   │
│                                                                              │
│   3. API ACCESS CONTROL                                                      │
│   ─────────────────────                                                      │
│   • Admin: FULL_ACCESS + DELEGATE                                            │
│   • Desenvolvedor: READ | WRITE em endpoints específicos                    │
│   • Teste: READ_ONLY, max_uses: 100, expires: 1 hora                        │
│   • Produção: READ | WRITE | ENCRYPT, sem limite de uso                     │
│                                                                              │
│   4. SUPPLY CHAIN                                                            │
│   ───────────────                                                            │
│   • Fabricante: capability para assinar lote                                │
│   • Transportadora: capability para registrar movimentação                  │
│   • Varejista: capability para verificar autenticidade                      │
│   • Cada etapa recebe capability delegada da anterior                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Comparação de Tamanhos

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPARAÇÃO DE TAMANHOS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Protocolo          │ Assinatura/Prova │ Chave Pública │ Observação        │
│   ───────────────────┼──────────────────┼───────────────┼──────────────────│
│   TAV Hash-Chain     │ 66 bytes         │ 32 bytes      │ Limitado          │
│   TAV Commitment     │ 72 bytes         │ 32 bytes      │ Requer sync       │
│   TAV CBA (básico)   │ ~120 bytes       │ 32 bytes      │ Ilimitado+granular│
│   TAV CBA (c/ ident) │ ~186 bytes       │ 32 bytes      │ Máxima segurança  │
│   ───────────────────┼──────────────────┼───────────────┼──────────────────│
│   ECDSA P-256        │ 64 bytes         │ 64 bytes      │ Não quantum-safe  │
│   Ed25519            │ 64 bytes         │ 32 bytes      │ Não quantum-safe  │
│   ML-DSA-44 (PQC)    │ 2,420 bytes      │ 1,312 bytes   │ Quantum-safe      │
│   ML-DSA-65 (PQC)    │ 3,293 bytes      │ 1,952 bytes   │ Quantum-safe      │
│   ML-DSA-87 (PQC)    │ 4,627 bytes      │ 2,592 bytes   │ Quantum-safe      │
│                                                                              │
│   CBA é 12-38x menor que ML-DSA com funcionalidade similar                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Segurança

### O que CBA resolve:

1. **Limitação do Hash-Chain**: Identidade usada apenas para operações críticas
2. **Sincronização do Commitment-Reveal**: Capability serve como âncora verificável
3. **Acesso total ou nada**: Permissões granulares por operação e recurso
4. **Delegação sem controle**: Restrições automáticas (≤ parent)
5. **Revogação lenta**: Instantânea via revocation_list

### Limitações que permanecem:

1. **Não há prova formal de segurança** (como todo o TAV)
2. **Revogação requer comunicação** da lista atualizada
3. **Complexidade maior** que protocolos simples
4. **Tamanho maior** que assinaturas mínimas (mas menor que PQC)
