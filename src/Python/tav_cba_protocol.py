"""
 TAV Clock Cryptography v0.9
 Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto

===============================================

Hybrid protocol that combines:
1. Hash-Chain: Establishes IDENTITY (who you are)
2. Commitment-Reveal: Establishes SESSION (current state)
3. Capabilities: Define PERMISSIONS (what you can do)

Solves the limitations of both original protocols:

- Hash-Chain: limited in signatures → CBA uses it for root identity only
- Commitment-Reveal: requires synchronization → CBA includes proof-of-chain for bootstrapping

Unique properties:
- Secure delegation of permissions
- Instant revocation
- Granular access by resource/operation
- Offline verification possible

Author: Carlos Alberto Terêncio de Bastos
Data: November 2025
"""

import os
import time
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from enum import IntFlag, auto


# =============================================================================
# IMPORTS DO TAV (simulados para standalone)
# =============================================================================

def _rot_left(b: int, n: int) -> int:
    """Rotação à esquerda de byte."""
    n &= 7
    return ((b << n) | (b >> (8 - n))) & 0xFF

def _tav_hash(data: bytes, size: int = 32) -> bytes:
    """Hash TAV usando Feistel (simplificado para demonstração)."""
    state = bytearray(32)
    
    # Constantes
    CONST_AND = bytes([0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF] * 4)
    CONST_OR = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80] * 4)
    
    # Inicializa com prefixo
    prefix = b'TAV-CBA-HASH-V1'
    for i, b in enumerate(prefix):
        state[i % 32] ^= b
    
    # Absorve dados
    for i, b in enumerate(data):
        state[i % 32] ^= b
        if (i + 1) % 32 == 0:
            # Mix round
            for r in range(4):
                for j in range(32):
                    x = state[j]
                    x = _rot_left(x, (r + j) & 7)
                    x = x & CONST_AND[(j + r * 7) & 31]
                    x = x | CONST_OR[(j + r * 11) & 31]
                    x = x ^ state[(j + r + 1) % 32]
                    state[j] = x
    
    # Finalização
    state[0] ^= (len(data) >> 8) & 0xFF
    state[1] ^= len(data) & 0xFF
    
    for r in range(8):
        for j in range(32):
            x = state[j]
            x = _rot_left(x, (r + j) & 7)
            x = x & CONST_AND[(j + r * 7) & 31]
            x = x | CONST_OR[(j + r * 11) & 31]
            x = x ^ state[(j + r + 1) % 32]
            state[j] = x
    
    return bytes(state[:size])


def _tav_mac(key: bytes, data: bytes, size: int = 16) -> bytes:
    """MAC TAV."""
    return _tav_hash(key + data + key, size)


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Comparação em tempo constante."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# =============================================================================
# PERMISSÕES (FLAGS DE CAPABILITY)
# =============================================================================

class Permission(IntFlag):
    """Permissões granulares para capabilities."""
    NONE = 0
    
    # Operações de dados
    READ = auto()           # Ler dados
    WRITE = auto()          # Escrever dados
    DELETE = auto()         # Deletar dados
    
    # Operações de sistema
    ENCRYPT = auto()        # Usar encrypt
    DECRYPT = auto()        # Usar decrypt
    SIGN = auto()           # Assinar mensagens
    VERIFY = auto()         # Verificar assinaturas
    
    # Operações administrativas
    DELEGATE = auto()       # Criar sub-capabilities
    REVOKE = auto()         # Revogar capabilities
    ADMIN = auto()          # Acesso total
    
    # Combinações comuns
    READ_ONLY = READ | VERIFY
    READ_WRITE = READ | WRITE | ENCRYPT | DECRYPT
    FULL_CRYPTO = ENCRYPT | DECRYPT | SIGN | VERIFY
    DELEGATOR = READ | WRITE | DELEGATE
    FULL_ACCESS = READ | WRITE | DELETE | ENCRYPT | DECRYPT | SIGN | VERIFY | DELEGATE | REVOKE | ADMIN


@dataclass
class Resource:
    """Representa um recurso protegido."""
    id: str                          # Identificador único
    type: str                        # Tipo: "file", "channel", "device", etc.
    permissions_required: Permission  # Permissões mínimas para acessar


# =============================================================================
# ESTRUTURAS DO PROTOCOLO CBA
# =============================================================================

@dataclass
class IdentityKey:
    """
    Chave de identidade baseada em Hash-Chain.
    Usada RARAMENTE - apenas para:
    1. Bootstrap inicial
    2. Criar root capabilities
    3. Recuperação de emergência
    """
    public_key: bytes              # Hash final da cadeia (32 bytes)
    private_seed: bytes            # Seed secreta (32 bytes)
    chain_length: int              # Tamanho da cadeia
    current_index: int = 0         # Posição atual (quantas já usadas)
    
    # Cache da cadeia (opcional, para performance)
    _chain_cache: List[bytes] = field(default_factory=list, repr=False)


@dataclass
class SessionKey:
    """
    Chave de sessão baseada em Commitment-Reveal.
    Usada FREQUENTEMENTE - para operações do dia-a-dia.
    """
    commitment: bytes              # hash(master_entropy) - público
    session_id: bytes              # Identificador único da sessão (16 bytes)
    created_at: int                # Timestamp de criação
    expires_at: int                # Timestamp de expiração
    tx_count: int = 0              # Contador de transações
    
    # Estado interno (privado)
    _master_entropy: bytes = field(default=b'', repr=False)


@dataclass
class Capability:
    """
    Token de capacidade que combina identidade + sessão + permissões.
    
    Estrutura:
    - Derivado de uma IdentityKey (prova de quem criou)
    - Vinculado a uma SessionKey (contexto temporal)
    - Especifica permissões granulares
    - Pode ser delegado (com restrições)
    """
    id: bytes                      # ID único (16 bytes)
    issuer_id: bytes               # Hash da IdentityKey do emissor
    holder_id: bytes               # Hash da IdentityKey do detentor (ou sessão)
    
    permissions: Permission        # O que pode fazer
    resources: Set[str]            # Em quais recursos (IDs)
    
    created_at: int                # Quando foi criado
    expires_at: int                # Quando expira
    max_uses: int                  # Máximo de usos (-1 = ilimitado)
    uses_count: int = 0            # Usos atuais
    
    # Cadeia de delegação
    delegation_depth: int = 0      # 0 = root, 1 = delegado, etc.
    max_delegation_depth: int = 3  # Máximo de níveis de delegação
    parent_capability_id: Optional[bytes] = None  # De quem foi delegado
    
    # Assinatura que prova validade
    signature: bytes = b''         # Assinatura do emissor
    
    # Revogação
    revoked: bool = False
    revoked_at: Optional[int] = None


@dataclass 
class CBAProof:
    """
    Prova de autenticação CBA.
    
    Combina:
    1. Prova de identidade (chain-based, apenas se necessário)
    2. Prova de sessão (commitment-reveal)
    3. Capability token
    4. Prova de operação específica
    """
    # Identificação
    capability_id: bytes
    session_proof: bytes           # Prova do estado da sessão
    
    # Contexto da operação
    operation: str                 # Ex: "READ", "WRITE", "ENCRYPT"
    resource_id: str               # Recurso sendo acessado
    timestamp: int                 # Quando a prova foi gerada
    nonce: bytes                   # Contra replay (16 bytes)
    
    # Assinatura da prova
    proof_signature: bytes         # MAC que amarra tudo
    
    # Opcional: prova de identidade (para bootstrap ou verificação extra)
    identity_proof: Optional[bytes] = None
    chain_index: Optional[int] = None


# =============================================================================
# PROTOCOLO CBA - IMPLEMENTAÇÃO
# =============================================================================

class TAVCapabilityAuth:
    """
    Sistema de Autenticação Baseado em Capabilities.
    
    Fluxo típico:
    1. Gerar IdentityKey (uma vez, guardar com cuidado)
    2. Criar SessionKey (por sessão/dispositivo)
    3. Emitir Capabilities (conforme necessário)
    4. Gerar CBAProof para cada operação
    5. Verificar CBAProof no receptor
    """
    
    VERSION = "1.0"
    
    def __init__(self, seed: str, chain_length: int = 1000):
        """
        Inicializa o sistema CBA.
        
        Args:
            seed: Seed secreta do usuário
            chain_length: Tamanho da cadeia de identidade
        """
        self.seed = seed.encode() if isinstance(seed, str) else seed
        self.chain_length = chain_length
        
        # Gera identidade
        self.identity = self._generate_identity()
        
        # Sessão ativa (None até criar)
        self.session: Optional[SessionKey] = None
        
        # Capabilities emitidas/recebidas
        self.capabilities: Dict[bytes, Capability] = {}
        
        # Lista de revogação
        self.revocation_list: Set[bytes] = set()
        
        # Contador para IDs únicos
        self._id_counter = 0
    
    # =========================================================================
    # IDENTIDADE (Hash-Chain)
    # =========================================================================
    
    def _generate_identity(self) -> IdentityKey:
        """Gera chave de identidade baseada em hash-chain."""
        # Deriva seed privada
        private_seed = _tav_hash(self.seed + b'_IDENTITY_SEED', 32)
        
        # Gera cadeia
        chain = [private_seed]
        current = private_seed
        
        for i in range(self.chain_length):
            current = _tav_hash(current + struct.pack('>I', i), 32)
            chain.append(current)
        
        public_key = chain[-1]  # Último hash é a chave pública
        
        identity = IdentityKey(
            public_key=public_key,
            private_seed=private_seed,
            chain_length=self.chain_length,
            current_index=0,
            _chain_cache=chain
        )
        
        return identity
    
    def _get_chain_element(self, index: int) -> bytes:
        """Obtém elemento da cadeia de identidade."""
        if index < 0 or index > self.chain_length:
            raise ValueError(f"Índice inválido: {index}")
        
        if self.identity._chain_cache:
            return self.identity._chain_cache[index]
        
        # Recalcula se não tiver cache
        current = self.identity.private_seed
        for i in range(index):
            current = _tav_hash(current + struct.pack('>I', i), 32)
        return current
    
    def sign_with_identity(self, data: bytes) -> Tuple[bytes, int]:
        """
        Assina dados usando a cadeia de identidade.
        
        ATENÇÃO: Use com moderação! Cada uso consome uma posição.
        
        Returns:
            (assinatura, índice_usado)
        """
        if self.identity.current_index >= self.chain_length:
            raise RuntimeError("Cadeia de identidade esgotada!")
        
        index = self.identity.current_index
        reveal = self._get_chain_element(self.chain_length - index - 1)
        
        # MAC da mensagem com o reveal
        mac = _tav_mac(reveal, data, 32)
        
        # Assinatura = índice + reveal + mac
        signature = struct.pack('>H', index) + reveal + mac
        
        self.identity.current_index += 1
        
        return signature, index
    
    def verify_identity_signature(self, public_key: bytes, data: bytes, 
                                   signature: bytes) -> bool:
        """Verifica assinatura de identidade."""
        if len(signature) < 66:  # 2 + 32 + 32
            return False
        
        index = struct.unpack('>H', signature[:2])[0]
        reveal = signature[2:34]
        mac = signature[34:66]
        
        # Verifica MAC
        expected_mac = _tav_mac(reveal, data, 32)
        if not _constant_time_compare(mac, expected_mac):
            return False
        
        # Verifica cadeia: hash^(index+1)(reveal) == public_key
        current = reveal
        for i in range(index + 1):
            current = _tav_hash(current + struct.pack('>I', self.chain_length - index - 1 + i), 32)
        
        return _constant_time_compare(current, public_key)
    
    # =========================================================================
    # SESSÃO (Commitment-Reveal)
    # =========================================================================
    
    def create_session(self, duration_seconds: int = 3600) -> SessionKey:
        """
        Cria uma nova sessão.
        
        Args:
            duration_seconds: Duração da sessão em segundos
        """
        now = int(time.time())
        
        # Gera entropia para sessão
        session_entropy = _tav_hash(
            self.seed + 
            struct.pack('>Q', now) + 
            struct.pack('>I', self._id_counter) +
            os.urandom(16),
            64
        )
        self._id_counter += 1
        
        # Commitment = hash público
        commitment = _tav_hash(session_entropy, 32)
        
        # ID da sessão
        session_id = _tav_hash(commitment + struct.pack('>Q', now), 16)
        
        self.session = SessionKey(
            commitment=commitment,
            session_id=session_id,
            created_at=now,
            expires_at=now + duration_seconds,
            tx_count=0,
            _master_entropy=session_entropy
        )
        
        return self.session
    
    def get_session_proof(self) -> bytes:
        """Gera prova do estado atual da sessão."""
        if not self.session:
            raise RuntimeError("Nenhuma sessão ativa")
        
        if time.time() > self.session.expires_at:
            raise RuntimeError("Sessão expirada")
        
        # Prova = hash(entropy || tx_count)
        proof = _tav_hash(
            self.session._master_entropy + 
            struct.pack('>Q', self.session.tx_count),
            32
        )
        
        self.session.tx_count += 1
        
        return proof
    
    def verify_session_proof(self, commitment: bytes, proof: bytes, 
                              tx_count: int, master_entropy: bytes) -> bool:
        """
        Verifica prova de sessão.
        
        Nota: Requer conhecimento do master_entropy (compartilhado previamente
        ou derivado de segredo comum).
        """
        expected_commitment = _tav_hash(master_entropy, 32)
        if not _constant_time_compare(commitment, expected_commitment):
            return False
        
        expected_proof = _tav_hash(
            master_entropy + struct.pack('>Q', tx_count),
            32
        )
        
        return _constant_time_compare(proof, expected_proof)
    
    # =========================================================================
    # CAPABILITIES
    # =========================================================================
    
    def issue_capability(self, 
                         holder_public_key: bytes,
                         permissions: Permission,
                         resources: Set[str],
                         duration_seconds: int = 86400,
                         max_uses: int = -1,
                         max_delegation_depth: int = 1) -> Capability:
        """
        Emite uma nova capability.
        
        Args:
            holder_public_key: Chave pública de quem vai usar
            permissions: Permissões concedidas
            resources: IDs dos recursos acessíveis
            duration_seconds: Validade em segundos
            max_uses: Máximo de usos (-1 = ilimitado)
            max_delegation_depth: Níveis de delegação permitidos
        """
        now = int(time.time())
        
        # Gera ID único
        cap_id = _tav_hash(
            self.identity.public_key +
            holder_public_key +
            struct.pack('>Q', now) +
            struct.pack('>I', self._id_counter),
            16
        )
        self._id_counter += 1
        
        # Cria capability
        cap = Capability(
            id=cap_id,
            issuer_id=_tav_hash(self.identity.public_key, 16),
            holder_id=_tav_hash(holder_public_key, 16),
            permissions=permissions,
            resources=resources,
            created_at=now,
            expires_at=now + duration_seconds,
            max_uses=max_uses,
            uses_count=0,
            delegation_depth=0,
            max_delegation_depth=max_delegation_depth,
            parent_capability_id=None
        )
        
        # Assina a capability
        cap_data = self._serialize_capability_for_signing(cap)
        cap.signature, _ = self.sign_with_identity(cap_data)
        
        # Armazena
        self.capabilities[cap_id] = cap
        
        return cap
    
    def delegate_capability(self,
                            parent_cap: Capability,
                            new_holder_public_key: bytes,
                            permissions: Permission,
                            resources: Set[str],
                            duration_seconds: int = 3600) -> Capability:
        """
        Delega uma capability existente (com restrições).
        
        A nova capability:
        - Não pode ter mais permissões que a parent
        - Não pode acessar recursos fora da parent
        - Não pode durar mais que a parent
        - Aumenta delegation_depth
        """
        # Validações
        if parent_cap.revoked:
            raise ValueError("Capability parent foi revogada")
        
        if parent_cap.delegation_depth >= parent_cap.max_delegation_depth:
            raise ValueError("Profundidade máxima de delegação atingida")
        
        if Permission.DELEGATE not in parent_cap.permissions:
            raise ValueError("Capability parent não permite delegação")
        
        # Restringe permissões
        allowed_permissions = permissions & parent_cap.permissions
        if allowed_permissions != permissions:
            print(f"Aviso: Permissões reduzidas para {allowed_permissions}")
        
        # Restringe recursos
        allowed_resources = resources & parent_cap.resources
        if allowed_resources != resources:
            print(f"Aviso: Recursos reduzidos para {allowed_resources}")
        
        # Restringe duração
        now = int(time.time())
        max_expires = parent_cap.expires_at
        actual_expires = min(now + duration_seconds, max_expires)
        
        # Cria nova capability
        cap_id = _tav_hash(
            parent_cap.id +
            new_holder_public_key +
            struct.pack('>Q', now) +
            struct.pack('>I', self._id_counter),
            16
        )
        self._id_counter += 1
        
        cap = Capability(
            id=cap_id,
            issuer_id=_tav_hash(self.identity.public_key, 16),
            holder_id=_tav_hash(new_holder_public_key, 16),
            permissions=allowed_permissions,
            resources=allowed_resources,
            created_at=now,
            expires_at=actual_expires,
            max_uses=parent_cap.max_uses,  # Herda limite
            uses_count=0,
            delegation_depth=parent_cap.delegation_depth + 1,
            max_delegation_depth=parent_cap.max_delegation_depth,
            parent_capability_id=parent_cap.id
        )
        
        # Assina
        cap_data = self._serialize_capability_for_signing(cap)
        cap.signature, _ = self.sign_with_identity(cap_data)
        
        self.capabilities[cap_id] = cap
        
        return cap
    
    def revoke_capability(self, cap_id: bytes):
        """Revoga uma capability."""
        if cap_id in self.capabilities:
            cap = self.capabilities[cap_id]
            cap.revoked = True
            cap.revoked_at = int(time.time())
        
        self.revocation_list.add(cap_id)
    
    def _serialize_capability_for_signing(self, cap: Capability) -> bytes:
        """Serializa capability para assinatura."""
        data = bytearray()
        data.extend(cap.id)
        data.extend(cap.issuer_id)
        data.extend(cap.holder_id)
        data.extend(struct.pack('>I', cap.permissions))
        data.extend(struct.pack('>Q', cap.created_at))
        data.extend(struct.pack('>Q', cap.expires_at))
        data.extend(struct.pack('>i', cap.max_uses))
        data.extend(struct.pack('>B', cap.delegation_depth))
        data.extend(struct.pack('>B', cap.max_delegation_depth))
        if cap.parent_capability_id:
            data.extend(cap.parent_capability_id)
        
        # Ordena recursos para consistência
        for res in sorted(cap.resources):
            data.extend(res.encode())
        
        return bytes(data)
    
    # =========================================================================
    # PROVA CBA (Autenticação Completa)
    # =========================================================================
    
    def generate_proof(self,
                       capability: Capability,
                       operation: str,
                       resource_id: str,
                       include_identity: bool = False) -> CBAProof:
        """
        Gera prova de autenticação CBA.
        
        Args:
            capability: Capability sendo usada
            operation: Operação sendo realizada
            resource_id: Recurso sendo acessado
            include_identity: Se deve incluir prova de identidade (mais forte)
        """
        # Validações
        if capability.revoked or capability.id in self.revocation_list:
            raise ValueError("Capability revogada")
        
        now = int(time.time())
        if now > capability.expires_at:
            raise ValueError("Capability expirada")
        
        if capability.max_uses >= 0 and capability.uses_count >= capability.max_uses:
            raise ValueError("Limite de usos atingido")
        
        if resource_id not in capability.resources:
            raise ValueError(f"Recurso {resource_id} não permitido")
        
        # Verifica permissão
        op_permission = self._operation_to_permission(operation)
        if op_permission not in capability.permissions:
            raise ValueError(f"Operação {operation} não permitida")
        
        # Gera nonce
        nonce = _tav_hash(os.urandom(16) + struct.pack('>Q', now), 16)
        
        # Prova de sessão
        session_proof = self.get_session_proof()
        
        # Prova de identidade (opcional)
        identity_proof = None
        chain_index = None
        if include_identity:
            identity_data = capability.id + session_proof + nonce
            identity_proof, chain_index = self.sign_with_identity(identity_data)
        
        # Cria prova
        proof = CBAProof(
            capability_id=capability.id,
            session_proof=session_proof,
            operation=operation,
            resource_id=resource_id,
            timestamp=now,
            nonce=nonce,
            proof_signature=b'',  # Preenchido abaixo
            identity_proof=identity_proof,
            chain_index=chain_index
        )
        
        # Assinatura final que amarra tudo
        proof_data = self._serialize_proof_for_signing(proof)
        proof.proof_signature = _tav_mac(
            self.session._master_entropy if self.session else self.seed,
            proof_data,
            32
        )
        
        # Incrementa uso
        capability.uses_count += 1
        
        return proof
    
    def verify_proof(self,
                     proof: CBAProof,
                     capability: Capability,
                     issuer_public_key: bytes,
                     session_master_entropy: Optional[bytes] = None,
                     max_age_seconds: int = 300) -> Tuple[bool, str]:
        """
        Verifica prova CBA.
        
        Args:
            proof: Prova a verificar
            capability: Capability referenciada
            issuer_public_key: Chave pública do emissor da capability
            session_master_entropy: Entropia da sessão (se disponível)
            max_age_seconds: Idade máxima aceita da prova
        
        Returns:
            (sucesso, mensagem)
        """
        now = int(time.time())
        
        # 1. Verifica timestamp
        if now - proof.timestamp > max_age_seconds:
            return False, "Prova expirada"
        
        if proof.timestamp > now + 60:  # Tolerância de 1 minuto
            return False, "Prova do futuro"
        
        # 2. Verifica capability
        if proof.capability_id != capability.id:
            return False, "Capability ID não corresponde"
        
        if capability.revoked:
            return False, "Capability revogada"
        
        if now > capability.expires_at:
            return False, "Capability expirada"
        
        # 3. Verifica assinatura da capability
        cap_data = self._serialize_capability_for_signing(capability)
        if not self.verify_identity_signature(issuer_public_key, cap_data, 
                                               capability.signature):
            return False, "Assinatura da capability inválida"
        
        # 4. Verifica operação/recurso
        if proof.resource_id not in capability.resources:
            return False, f"Recurso {proof.resource_id} não permitido"
        
        op_permission = self._operation_to_permission(proof.operation)
        if op_permission not in capability.permissions:
            return False, f"Operação {proof.operation} não permitida"
        
        # 5. Verifica prova de identidade (se presente)
        if proof.identity_proof:
            identity_data = capability.id + proof.session_proof + proof.nonce
            if not self.verify_identity_signature(issuer_public_key, 
                                                   identity_data,
                                                   proof.identity_proof):
                return False, "Prova de identidade inválida"
        
        # 6. Verifica assinatura da prova (se tiver entropia da sessão)
        if session_master_entropy:
            proof_data = self._serialize_proof_for_signing(proof)
            expected_sig = _tav_mac(session_master_entropy, proof_data, 32)
            if not _constant_time_compare(proof.proof_signature, expected_sig):
                return False, "Assinatura da prova inválida"
        
        return True, "OK"
    
    def _serialize_proof_for_signing(self, proof: CBAProof) -> bytes:
        """Serializa prova para assinatura."""
        data = bytearray()
        data.extend(proof.capability_id)
        data.extend(proof.session_proof)
        data.extend(proof.operation.encode())
        data.extend(proof.resource_id.encode())
        data.extend(struct.pack('>Q', proof.timestamp))
        data.extend(proof.nonce)
        if proof.identity_proof:
            data.extend(proof.identity_proof)
        return bytes(data)
    
    def _operation_to_permission(self, operation: str) -> Permission:
        """Converte string de operação para Permission."""
        mapping = {
            'READ': Permission.READ,
            'WRITE': Permission.WRITE,
            'DELETE': Permission.DELETE,
            'ENCRYPT': Permission.ENCRYPT,
            'DECRYPT': Permission.DECRYPT,
            'SIGN': Permission.SIGN,
            'VERIFY': Permission.VERIFY,
            'DELEGATE': Permission.DELEGATE,
            'REVOKE': Permission.REVOKE,
            'ADMIN': Permission.ADMIN,
        }
        return mapping.get(operation.upper(), Permission.NONE)
    
    # =========================================================================
    # SERIALIZAÇÃO (para transmissão)
    # =========================================================================
    
    def serialize_capability(self, cap: Capability) -> bytes:
        """Serializa capability para transmissão."""
        data = bytearray()
        
        # Header
        data.extend(b'TCAP')  # Magic
        data.extend(struct.pack('>B', 1))  # Versão
        
        # Campos fixos
        data.extend(cap.id)  # 16 bytes
        data.extend(cap.issuer_id)  # 16 bytes
        data.extend(cap.holder_id)  # 16 bytes
        data.extend(struct.pack('>I', cap.permissions))
        data.extend(struct.pack('>Q', cap.created_at))
        data.extend(struct.pack('>Q', cap.expires_at))
        data.extend(struct.pack('>i', cap.max_uses))
        data.extend(struct.pack('>I', cap.uses_count))
        data.extend(struct.pack('>B', cap.delegation_depth))
        data.extend(struct.pack('>B', cap.max_delegation_depth))
        
        # Parent (opcional)
        if cap.parent_capability_id:
            data.extend(struct.pack('>B', 1))
            data.extend(cap.parent_capability_id)
        else:
            data.extend(struct.pack('>B', 0))
        
        # Recursos
        data.extend(struct.pack('>H', len(cap.resources)))
        for res in sorted(cap.resources):
            res_bytes = res.encode()
            data.extend(struct.pack('>H', len(res_bytes)))
            data.extend(res_bytes)
        
        # Assinatura
        data.extend(struct.pack('>H', len(cap.signature)))
        data.extend(cap.signature)
        
        return bytes(data)
    
    def deserialize_capability(self, data: bytes) -> Capability:
        """Deserializa capability."""
        if data[:4] != b'TCAP':
            raise ValueError("Magic inválido")
        
        pos = 5  # Pula magic + versão
        
        cap_id = data[pos:pos+16]; pos += 16
        issuer_id = data[pos:pos+16]; pos += 16
        holder_id = data[pos:pos+16]; pos += 16
        permissions = Permission(struct.unpack('>I', data[pos:pos+4])[0]); pos += 4
        created_at = struct.unpack('>Q', data[pos:pos+8])[0]; pos += 8
        expires_at = struct.unpack('>Q', data[pos:pos+8])[0]; pos += 8
        max_uses = struct.unpack('>i', data[pos:pos+4])[0]; pos += 4
        uses_count = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
        delegation_depth = data[pos]; pos += 1
        max_delegation_depth = data[pos]; pos += 1
        
        has_parent = data[pos]; pos += 1
        parent_id = None
        if has_parent:
            parent_id = data[pos:pos+16]; pos += 16
        
        n_resources = struct.unpack('>H', data[pos:pos+2])[0]; pos += 2
        resources = set()
        for _ in range(n_resources):
            res_len = struct.unpack('>H', data[pos:pos+2])[0]; pos += 2
            resources.add(data[pos:pos+res_len].decode()); pos += res_len
        
        sig_len = struct.unpack('>H', data[pos:pos+2])[0]; pos += 2
        signature = data[pos:pos+sig_len]
        
        return Capability(
            id=cap_id,
            issuer_id=issuer_id,
            holder_id=holder_id,
            permissions=permissions,
            resources=resources,
            created_at=created_at,
            expires_at=expires_at,
            max_uses=max_uses,
            uses_count=uses_count,
            delegation_depth=delegation_depth,
            max_delegation_depth=max_delegation_depth,
            parent_capability_id=parent_id,
            signature=signature
        )
    
    def serialize_proof(self, proof: CBAProof) -> bytes:
        """Serializa prova para transmissão."""
        data = bytearray()
        
        # Header
        data.extend(b'TPRF')  # Magic
        data.extend(struct.pack('>B', 1))  # Versão
        
        # Campos
        data.extend(proof.capability_id)  # 16 bytes
        data.extend(proof.session_proof)  # 32 bytes
        
        op_bytes = proof.operation.encode()
        data.extend(struct.pack('>B', len(op_bytes)))
        data.extend(op_bytes)
        
        res_bytes = proof.resource_id.encode()
        data.extend(struct.pack('>H', len(res_bytes)))
        data.extend(res_bytes)
        
        data.extend(struct.pack('>Q', proof.timestamp))
        data.extend(proof.nonce)  # 16 bytes
        data.extend(proof.proof_signature)  # 32 bytes
        
        # Identidade (opcional)
        if proof.identity_proof:
            data.extend(struct.pack('>B', 1))
            data.extend(struct.pack('>H', len(proof.identity_proof)))
            data.extend(proof.identity_proof)
            data.extend(struct.pack('>H', proof.chain_index or 0))
        else:
            data.extend(struct.pack('>B', 0))
        
        return bytes(data)
    
    # =========================================================================
    # STATUS
    # =========================================================================
    
    def status(self) -> Dict:
        """Retorna status do sistema CBA."""
        return {
            'version': self.VERSION,
            'identity': {
                'public_key': self.identity.public_key.hex()[:32] + '...',
                'chain_length': self.identity.chain_length,
                'signatures_used': self.identity.current_index,
                'signatures_remaining': self.identity.chain_length - self.identity.current_index,
            },
            'session': {
                'active': self.session is not None,
                'id': self.session.session_id.hex() if self.session else None,
                'expires_at': self.session.expires_at if self.session else None,
                'tx_count': self.session.tx_count if self.session else 0,
            },
            'capabilities': {
                'issued': len(self.capabilities),
                'revoked': len(self.revocation_list),
            }
        }


# =============================================================================
# DEMONSTRAÇÃO
# =============================================================================

def demo():
    """Demonstração do protocolo CBA."""
    print("=" * 70)
    print("TAV CAPABILITY-BASED AUTHENTICATION (CBA) V1.0")
    print("=" * 70)
    print()
    print("Protocolo híbrido combinando:")
    print("  - Hash-Chain: Identidade forte (uso limitado)")
    print("  - Commitment-Reveal: Sessões ilimitadas")
    print("  - Capabilities: Controle de acesso granular")
    print()
    
    # =========================================================================
    # CENÁRIO: Alice quer dar acesso limitado a Bob
    # =========================================================================
    
    print("=" * 70)
    print("CENÁRIO: Alice concede acesso limitado a Bob")
    print("=" * 70)
    
    # 1. Alice inicializa seu sistema
    print("\n1. ALICE INICIALIZA SISTEMA")
    print("-" * 50)
    alice = TAVCapabilityAuth("alice super secret seed", chain_length=100)
    print(f"   Chave pública: {alice.identity.public_key.hex()[:32]}...")
    print(f"   Assinaturas disponíveis: {alice.identity.chain_length}")
    
    # 2. Bob inicializa seu sistema
    print("\n2. BOB INICIALIZA SISTEMA")
    print("-" * 50)
    bob = TAVCapabilityAuth("bob super secret seed", chain_length=100)
    print(f"   Chave pública: {bob.identity.public_key.hex()[:32]}...")
    
    # 3. Alice cria sessão
    print("\n3. ALICE CRIA SESSÃO")
    print("-" * 50)
    alice_session = alice.create_session(duration_seconds=3600)
    print(f"   Session ID: {alice_session.session_id.hex()}")
    print(f"   Expira em: {alice_session.expires_at - alice_session.created_at}s")
    
    # 4. Alice emite capability para Bob
    print("\n4. ALICE EMITE CAPABILITY PARA BOB")
    print("-" * 50)
    
    cap = alice.issue_capability(
        holder_public_key=bob.identity.public_key,
        permissions=Permission.READ | Permission.ENCRYPT | Permission.DELEGATE,
        resources={"file:documento.txt", "file:relatorio.pdf", "channel:chat-123"},
        duration_seconds=7200,  # 2 horas
        max_uses=50,
        max_delegation_depth=2
    )
    
    print(f"   Capability ID: {cap.id.hex()}")
    print(f"   Permissões: {cap.permissions}")
    print(f"   Recursos: {cap.resources}")
    print(f"   Máx usos: {cap.max_uses}")
    print(f"   Delegação: até {cap.max_delegation_depth} níveis")
    print(f"   Assinatura: {len(cap.signature)} bytes")
    
    # Serializa para transmitir a Bob
    cap_serialized = alice.serialize_capability(cap)
    print(f"   Tamanho serializado: {len(cap_serialized)} bytes")
    
    # 5. Bob recebe e usa a capability
    print("\n5. BOB RECEBE E USA CAPABILITY")
    print("-" * 50)
    
    # Bob cria sua sessão
    bob_session = bob.create_session(duration_seconds=3600)
    
    # Bob armazena a capability recebida
    bob.capabilities[cap.id] = cap
    
    # Bob gera prova para acessar arquivo
    proof = bob.generate_proof(
        capability=cap,
        operation="READ",
        resource_id="file:documento.txt",
        include_identity=True  # Prova extra forte
    )
    
    print(f"   Operação: {proof.operation}")
    print(f"   Recurso: {proof.resource_id}")
    print(f"   Session proof: {proof.session_proof.hex()[:32]}...")
    print(f"   Identity proof: {len(proof.identity_proof)} bytes")
    print(f"   Proof signature: {proof.proof_signature.hex()[:32]}...")
    
    # Serializa prova
    proof_serialized = bob.serialize_proof(proof)
    print(f"   Tamanho da prova: {len(proof_serialized)} bytes")
    
    # 6. Alice (ou servidor) verifica a prova
    print("\n6. VERIFICAÇÃO DA PROVA")
    print("-" * 50)
    
    success, message = alice.verify_proof(
        proof=proof,
        capability=cap,
        issuer_public_key=alice.identity.public_key,
        session_master_entropy=None,  # Não temos entropia de Bob
        max_age_seconds=300
    )
    
    print(f"   Resultado: {'✓ VÁLIDO' if success else '✗ INVÁLIDO'}")
    print(f"   Mensagem: {message}")
    
    # 7. Bob delega para Carol (com restrições)
    print("\n7. BOB DELEGA PARA CAROL (SUB-CAPABILITY)")
    print("-" * 50)
    
    carol = TAVCapabilityAuth("carol secret seed", chain_length=50)
    print(f"   Carol chave pública: {carol.identity.public_key.hex()[:32]}...")
    
    # Bob delega apenas READ (não ENCRYPT ou DELEGATE)
    sub_cap = bob.delegate_capability(
        parent_cap=cap,
        new_holder_public_key=carol.identity.public_key,
        permissions=Permission.READ,  # Apenas leitura
        resources={"file:documento.txt"},  # Apenas 1 arquivo
        duration_seconds=1800  # 30 minutos
    )
    
    print(f"   Sub-capability ID: {sub_cap.id.hex()}")
    print(f"   Permissões: {sub_cap.permissions} (restrito)")
    print(f"   Recursos: {sub_cap.resources} (restrito)")
    print(f"   Profundidade: {sub_cap.delegation_depth}")
    print(f"   Parent: {sub_cap.parent_capability_id.hex()}")
    
    # 8. Teste de acesso negado
    print("\n8. TESTE: CAROL TENTA OPERAÇÃO NÃO PERMITIDA")
    print("-" * 50)
    
    carol_session = carol.create_session()
    carol.capabilities[sub_cap.id] = sub_cap
    
    try:
        # Carol tenta ENCRYPT, mas só tem READ
        proof_fail = carol.generate_proof(
            capability=sub_cap,
            operation="ENCRYPT",
            resource_id="file:documento.txt"
        )
        print("   ERRO: Deveria ter falhado!")
    except ValueError as e:
        print(f"   ✓ Corretamente negado: {e}")
    
    # 9. Revogação
    print("\n9. ALICE REVOGA CAPABILITY DE BOB")
    print("-" * 50)
    
    alice.revoke_capability(cap.id)
    print(f"   Capability {cap.id.hex()[:16]}... REVOGADA")
    print(f"   Lista de revogação: {len(alice.revocation_list)} itens")
    
    # Bob tenta usar capability revogada
    try:
        proof_revoked = bob.generate_proof(
            capability=cap,
            operation="READ",
            resource_id="file:documento.txt"
        )
        print("   ERRO: Deveria ter falhado!")
    except ValueError as e:
        print(f"   ✓ Corretamente negado: {e}")
    
    # 10. Status final
    print("\n10. STATUS FINAL")
    print("-" * 50)
    
    for name, system in [("Alice", alice), ("Bob", bob), ("Carol", carol)]:
        status = system.status()
        print(f"\n   {name}:")
        print(f"     Assinaturas de identidade usadas: {status['identity']['signatures_used']}")
        print(f"     Assinaturas restantes: {status['identity']['signatures_remaining']}")
        print(f"     Transações na sessão: {status['session']['tx_count']}")
        print(f"     Capabilities: {status['capabilities']['issued']}")
    
    # Resumo
    print("\n" + "=" * 70)
    print("RESUMO DO PROTOCOLO CBA")
    print("=" * 70)
    print("""
    COMBINA O MELHOR DOS DOIS PROTOCOLOS ORIGINAIS:
    
    Hash-Chain:
      ✓ Identidade raiz forte
      ✓ Verificação independente
      ✗ Limitado → Usado apenas para bootstrap e emergência
    
    Commitment-Reveal:
      ✓ Operações ilimitadas
      ✓ Provas únicas por transação
      ✗ Requer sync → Mitigado com capability como âncora
    
    CBA Adiciona:
      ✓ Controle de acesso granular (permissões por operação)
      ✓ Delegação segura (com restrições automáticas)
      ✓ Revogação instantânea
      ✓ Recursos específicos (não acesso total)
      ✓ Limites de uso e tempo
      ✓ Rastreabilidade (cadeia de delegação)
    
    TAMANHOS:
      - Capability serializada: ~150-200 bytes
      - Prova básica: ~120 bytes
      - Prova com identidade: ~186 bytes
    """)
    
    print("=" * 70)
    print("DEMONSTRAÇÃO CONCLUÍDA")
    print("=" * 70)


if __name__ == "__main__":
    demo()
