/*
 * TAV CAPABILITY-BASED AUTHENTICATION (CBA) V1.0 - Java Implementation
 * =====================================================================
 * 
 * Protocolo híbrido combinando:
 * 1. Hash-Chain: Identidade forte (uso limitado)
 * 2. Commitment-Reveal: Sessões ilimitadas
 * 3. Capabilities: Controle de acesso granular
 * 
 * Licença: AGPL-3.0 | Uso comercial gratuito até maio de 2027
 * Data: Novembro 2025
 */

package com.tav.cba;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/**
 * TAV Capability-Based Authentication System
 */
public class TavCBA {
    
    public static final String VERSION = "1.0";
    public static final int HASH_SIZE = 32;
    public static final int ID_SIZE = 16;
    public static final int NONCE_SIZE = 16;
    public static final int SIGNATURE_SIZE = 66;
    public static final int SESSION_ENTROPY_SIZE = 64;
    public static final int MAX_CHAIN_LENGTH = 1000;
    
    // Constantes criptográficas
    private static final byte[] CONST_AND = {
        (byte)0xF7, (byte)0xFB, (byte)0xFD, (byte)0xFE, 
        (byte)0x7F, (byte)0xBF, (byte)0xDF, (byte)0xEF,
        (byte)0xF7, (byte)0xFB, (byte)0xFD, (byte)0xFE, 
        (byte)0x7F, (byte)0xBF, (byte)0xDF, (byte)0xEF,
        (byte)0xF7, (byte)0xFB, (byte)0xFD, (byte)0xFE, 
        (byte)0x7F, (byte)0xBF, (byte)0xDF, (byte)0xEF,
        (byte)0xF7, (byte)0xFB, (byte)0xFD, (byte)0xFE, 
        (byte)0x7F, (byte)0xBF, (byte)0xDF, (byte)0xEF
    };
    
    private static final byte[] CONST_OR = {
        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, 
        (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80,
        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, 
        (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80,
        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, 
        (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80,
        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, 
        (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80
    };
    
    // =========================================================================
    // ENUMS E EXCEÇÕES
    // =========================================================================
    
    /**
     * Permissões disponíveis
     */
    public enum Permission {
        NONE(0),
        READ(1 << 0),
        WRITE(1 << 1),
        DELETE(1 << 2),
        ENCRYPT(1 << 3),
        DECRYPT(1 << 4),
        SIGN(1 << 5),
        VERIFY(1 << 6),
        DELEGATE(1 << 7),
        REVOKE(1 << 8),
        ADMIN(1 << 9);
        
        public final int value;
        
        Permission(int value) {
            this.value = value;
        }
        
        // Combinações comuns
        public static final int READ_ONLY = READ.value | VERIFY.value;
        public static final int READ_WRITE = READ.value | WRITE.value | ENCRYPT.value | DECRYPT.value;
        public static final int FULL_CRYPTO = ENCRYPT.value | DECRYPT.value | SIGN.value | VERIFY.value;
        public static final int DELEGATOR = READ.value | WRITE.value | DELEGATE.value;
        public static final int FULL_ACCESS = 0x3FF;
        
        public static Permission fromString(String op) {
            try {
                return Permission.valueOf(op.toUpperCase());
            } catch (IllegalArgumentException e) {
                return NONE;
            }
        }
    }
    
    /**
     * Exceções do CBA
     */
    public static class CBAException extends Exception {
        public enum ErrorCode {
            CHAIN_EXHAUSTED,
            SESSION_EXPIRED,
            CAPABILITY_EXPIRED,
            CAPABILITY_REVOKED,
            PERMISSION_DENIED,
            RESOURCE_DENIED,
            MAX_USES_EXCEEDED,
            MAX_DELEGATION,
            SIGNATURE_INVALID,
            PROOF_EXPIRED,
            PROOF_INVALID,
            INVALID_DATA
        }
        
        public final ErrorCode code;
        
        public CBAException(ErrorCode code, String message) {
            super(message);
            this.code = code;
        }
    }
    
    // =========================================================================
    // CLASSES DE DADOS
    // =========================================================================
    
    /**
     * Chave de identidade (Hash-Chain)
     */
    public static class IdentityKey {
        public final byte[] publicKey;
        private final byte[] privateSeed;
        public final int chainLength;
        private int currentIndex;
        
        public IdentityKey(byte[] seed, int chainLength) {
            this.chainLength = Math.min(chainLength, MAX_CHAIN_LENGTH);
            this.currentIndex = 0;
            
            // Deriva seed privada
            byte[] seedWithSuffix = concatenate(seed, "_IDENTITY_SEED".getBytes(StandardCharsets.UTF_8));
            this.privateSeed = hash(seedWithSuffix, HASH_SIZE);
            
            // Gera cadeia para obter chave pública
            byte[] current = Arrays.copyOf(privateSeed, HASH_SIZE);
            for (int i = 0; i < this.chainLength; i++) {
                byte[] input = concatenate(current, intToBytes(i));
                current = hash(input, HASH_SIZE);
            }
            this.publicKey = current;
        }
        
        public int getRemaining() {
            return chainLength - currentIndex;
        }
        
        public boolean isExhausted() {
            return currentIndex >= chainLength;
        }
        
        private byte[] getChainElement(int steps) {
            byte[] current = Arrays.copyOf(privateSeed, HASH_SIZE);
            for (int i = 0; i < steps; i++) {
                byte[] input = concatenate(current, intToBytes(i));
                current = hash(input, HASH_SIZE);
            }
            return current;
        }
        
        public SignatureResult sign(byte[] data) throws CBAException {
            if (isExhausted()) {
                throw new CBAException(CBAException.ErrorCode.CHAIN_EXHAUSTED, 
                    "Identity chain exhausted");
            }
            
            int index = currentIndex;
            int steps = chainLength - index - 1;
            
            byte[] reveal = getChainElement(steps);
            byte[] macInput = concatenate(data, reveal);
            byte[] mac = hash(macInput, HASH_SIZE);
            
            // Assinatura: índice (2) + reveal (32) + mac (32) = 66 bytes
            ByteBuffer sig = ByteBuffer.allocate(SIGNATURE_SIZE);
            sig.putShort((short) index);
            sig.put(reveal);
            sig.put(mac);
            
            currentIndex++;
            
            return new SignatureResult(sig.array(), index);
        }
    }
    
    public static class SignatureResult {
        public final byte[] signature;
        public final int chainIndex;
        
        public SignatureResult(byte[] signature, int chainIndex) {
            this.signature = signature;
            this.chainIndex = chainIndex;
        }
    }
    
    /**
     * Chave de sessão (Commitment-Reveal)
     */
    public static class SessionKey {
        public final byte[] commitment;
        public final byte[] sessionId;
        private final byte[] masterEntropy;
        public final long createdAt;
        public final long expiresAt;
        private int txCount;
        private boolean active;
        
        public SessionKey(byte[] identitySeed, long durationSeconds) {
            long now = System.currentTimeMillis() / 1000;
            this.createdAt = now;
            this.expiresAt = now + durationSeconds;
            this.txCount = 0;
            this.active = true;
            
            // Gera entropia
            SecureRandom random = new SecureRandom();
            byte[] randomBytes = new byte[16];
            random.nextBytes(randomBytes);
            
            byte[] entropyInput = concatenate(
                concatenate(identitySeed, longToBytes(now)),
                randomBytes
            );
            this.masterEntropy = hash(entropyInput, SESSION_ENTROPY_SIZE);
            
            // Commitment
            this.commitment = hash(masterEntropy, HASH_SIZE);
            
            // Session ID
            byte[] sidInput = concatenate(commitment, longToBytes(now));
            this.sessionId = hash(sidInput, ID_SIZE);
        }
        
        public boolean isActive() {
            if (!active) return false;
            return System.currentTimeMillis() / 1000 <= expiresAt;
        }
        
        public byte[] generateProof() throws CBAException {
            if (!isActive()) {
                active = false;
                throw new CBAException(CBAException.ErrorCode.SESSION_EXPIRED, 
                    "Session expired");
            }
            
            byte[] input = concatenate(masterEntropy, intToBytes(txCount));
            txCount++;
            
            return hash(input, HASH_SIZE);
        }
        
        public byte[] getMasterEntropy() {
            return masterEntropy;
        }
        
        public int getTxCount() {
            return txCount;
        }
    }
    
    /**
     * Capability
     */
    public static class Capability {
        public final byte[] id;
        public final byte[] issuerId;
        public final byte[] holderId;
        public int permissions;
        public final Set<String> resources;
        public final long createdAt;
        public long expiresAt;
        public int maxUses;
        public int usesCount;
        public int delegationDepth;
        public int maxDelegationDepth;
        public byte[] parentId;
        public byte[] signature;
        public boolean revoked;
        public Long revokedAt;
        
        public Capability(byte[] id, byte[] issuerId, byte[] holderId, 
                         int permissions, Set<String> resources,
                         long createdAt, long expiresAt,
                         int maxUses, int maxDelegationDepth) {
            this.id = id;
            this.issuerId = issuerId;
            this.holderId = holderId;
            this.permissions = permissions;
            this.resources = new HashSet<>(resources);
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.maxUses = maxUses;
            this.usesCount = 0;
            this.delegationDepth = 0;
            this.maxDelegationDepth = maxDelegationDepth;
            this.parentId = null;
            this.revoked = false;
            this.revokedAt = null;
        }
        
        public boolean hasPermission(Permission perm) {
            return (permissions & perm.value) == perm.value;
        }
        
        public boolean hasPermission(int permValue) {
            return (permissions & permValue) == permValue;
        }
        
        public boolean hasResource(String resourceId) {
            return resources.contains(resourceId) || resources.contains("*");
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() / 1000 > expiresAt;
        }
        
        public boolean isUsable() {
            if (revoked) return false;
            if (isExpired()) return false;
            if (maxUses >= 0 && usesCount >= maxUses) return false;
            return true;
        }
        
        public byte[] getDataForSigning() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                baos.write(id);
                baos.write(issuerId);
                baos.write(holderId);
                baos.write(intToBytes(permissions));
                baos.write(longToBytes(createdAt));
                baos.write(longToBytes(expiresAt));
                baos.write(intToBytes(maxUses));
                baos.write(new byte[]{(byte)delegationDepth, (byte)maxDelegationDepth});
                if (parentId != null) {
                    baos.write(parentId);
                }
                for (String r : resources) {
                    baos.write(r.getBytes(StandardCharsets.UTF_8));
                }
            } catch (IOException e) {
                // Shouldn't happen with ByteArrayOutputStream
            }
            return baos.toByteArray();
        }
        
        public byte[] serialize() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            
            try {
                // Magic + Version
                dos.write(new byte[]{'T', 'C', 'A', 'P', 1});
                
                // IDs
                dos.write(id);
                dos.write(issuerId);
                dos.write(holderId);
                
                // Permissions & timestamps
                dos.writeInt(permissions);
                dos.writeLong(createdAt);
                dos.writeLong(expiresAt);
                
                // Limits
                dos.writeInt(maxUses);
                dos.writeInt(usesCount);
                dos.writeByte(delegationDepth);
                dos.writeByte(maxDelegationDepth);
                
                // Parent
                dos.writeBoolean(parentId != null);
                if (parentId != null) {
                    dos.write(parentId);
                }
                
                // Resources
                dos.writeByte(resources.size());
                for (String r : resources) {
                    byte[] rBytes = r.getBytes(StandardCharsets.UTF_8);
                    dos.writeByte(rBytes.length);
                    dos.write(rBytes);
                }
                
                // Signature
                dos.writeShort(signature != null ? signature.length : 0);
                if (signature != null) {
                    dos.write(signature);
                }
                
            } catch (IOException e) {
                // Shouldn't happen
            }
            
            return baos.toByteArray();
        }
        
        public static Capability deserialize(byte[] data) throws CBAException {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
            
            try {
                // Magic + Version
                byte[] magic = new byte[5];
                dis.readFully(magic);
                if (magic[0] != 'T' || magic[1] != 'C' || magic[2] != 'A' || magic[3] != 'P') {
                    throw new CBAException(CBAException.ErrorCode.INVALID_DATA, "Invalid magic");
                }
                
                // IDs
                byte[] id = new byte[ID_SIZE];
                byte[] issuerId = new byte[ID_SIZE];
                byte[] holderId = new byte[ID_SIZE];
                dis.readFully(id);
                dis.readFully(issuerId);
                dis.readFully(holderId);
                
                // Permissions & timestamps
                int permissions = dis.readInt();
                long createdAt = dis.readLong();
                long expiresAt = dis.readLong();
                
                // Limits
                int maxUses = dis.readInt();
                int usesCount = dis.readInt();
                int delegationDepth = dis.readByte() & 0xFF;
                int maxDelegationDepth = dis.readByte() & 0xFF;
                
                // Parent
                boolean hasParent = dis.readBoolean();
                byte[] parentId = null;
                if (hasParent) {
                    parentId = new byte[ID_SIZE];
                    dis.readFully(parentId);
                }
                
                // Resources
                int nResources = dis.readByte() & 0xFF;
                Set<String> resources = new HashSet<>();
                for (int i = 0; i < nResources; i++) {
                    int len = dis.readByte() & 0xFF;
                    byte[] rBytes = new byte[len];
                    dis.readFully(rBytes);
                    resources.add(new String(rBytes, StandardCharsets.UTF_8));
                }
                
                // Signature
                int sigLen = dis.readShort() & 0xFFFF;
                byte[] signature = null;
                if (sigLen > 0) {
                    signature = new byte[sigLen];
                    dis.readFully(signature);
                }
                
                Capability cap = new Capability(id, issuerId, holderId, permissions, 
                    resources, createdAt, expiresAt, maxUses, maxDelegationDepth);
                cap.usesCount = usesCount;
                cap.delegationDepth = delegationDepth;
                cap.parentId = parentId;
                cap.signature = signature;
                
                return cap;
                
            } catch (IOException e) {
                throw new CBAException(CBAException.ErrorCode.INVALID_DATA, 
                    "Failed to deserialize: " + e.getMessage());
            }
        }
    }
    
    /**
     * Prova CBA
     */
    public static class CBAProof {
        public final byte[] capabilityId;
        public final byte[] sessionProof;
        public final String operation;
        public final String resourceId;
        public final long timestamp;
        public final byte[] nonce;
        public byte[] proofSignature;
        public byte[] identityProof;
        public Integer chainIndex;
        
        public CBAProof(byte[] capabilityId, byte[] sessionProof, 
                       String operation, String resourceId) {
            this.capabilityId = capabilityId;
            this.sessionProof = sessionProof;
            this.operation = operation;
            this.resourceId = resourceId;
            this.timestamp = System.currentTimeMillis() / 1000;
            
            SecureRandom random = new SecureRandom();
            this.nonce = new byte[NONCE_SIZE];
            random.nextBytes(this.nonce);
        }
        
        public byte[] serialize() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            
            try {
                // Magic
                dos.write(new byte[]{'T', 'C', 'P', 'R', 1});
                
                dos.write(capabilityId);
                dos.write(sessionProof);
                
                byte[] opBytes = operation.getBytes(StandardCharsets.UTF_8);
                dos.writeByte(opBytes.length);
                dos.write(opBytes);
                
                byte[] resBytes = resourceId.getBytes(StandardCharsets.UTF_8);
                dos.writeByte(resBytes.length);
                dos.write(resBytes);
                
                dos.writeLong(timestamp);
                dos.write(nonce);
                dos.write(proofSignature);
                
                dos.writeBoolean(identityProof != null);
                if (identityProof != null) {
                    dos.writeShort(identityProof.length);
                    dos.write(identityProof);
                    dos.writeShort(chainIndex != null ? chainIndex : 0);
                }
                
            } catch (IOException e) {
                // Shouldn't happen
            }
            
            return baos.toByteArray();
        }
    }
    
    // =========================================================================
    // CONTEXTO PRINCIPAL
    // =========================================================================
    
    private final IdentityKey identity;
    private SessionKey session;
    private final Set<ByteArrayWrapper> revocationList;
    private int idCounter;
    
    public TavCBA(String seed, int chainLength) {
        this(seed.getBytes(StandardCharsets.UTF_8), chainLength);
    }
    
    public TavCBA(byte[] seed, int chainLength) {
        this.identity = new IdentityKey(seed, chainLength);
        this.session = null;
        this.revocationList = new HashSet<>();
        this.idCounter = 0;
    }
    
    // =========================================================================
    // API DE IDENTIDADE
    // =========================================================================
    
    public byte[] getPublicKey() {
        return identity.publicKey;
    }
    
    public int getIdentityRemaining() {
        return identity.getRemaining();
    }
    
    public SignatureResult signWithIdentity(byte[] data) throws CBAException {
        return identity.sign(data);
    }
    
    public static boolean verifyIdentitySignature(byte[] publicKey, byte[] data, 
                                                   byte[] signature, int chainLength) {
        if (signature.length < SIGNATURE_SIZE) return false;
        
        ByteBuffer buf = ByteBuffer.wrap(signature);
        int index = buf.getShort() & 0xFFFF;
        byte[] reveal = new byte[HASH_SIZE];
        byte[] mac = new byte[HASH_SIZE];
        buf.get(reveal);
        buf.get(mac);
        
        // Verifica MAC
        byte[] macInput = concatenate(data, reveal);
        byte[] expectedMac = hash(macInput, HASH_SIZE);
        if (!constantTimeEquals(mac, expectedMac)) {
            return false;
        }
        
        // Verifica cadeia
        byte[] current = Arrays.copyOf(reveal, HASH_SIZE);
        for (int i = chainLength - index - 1; i < chainLength; i++) {
            byte[] input = concatenate(current, intToBytes(i));
            current = hash(input, HASH_SIZE);
        }
        
        return constantTimeEquals(current, publicKey);
    }
    
    // =========================================================================
    // API DE SESSÃO
    // =========================================================================
    
    public void createSession(long durationSeconds) {
        this.session = new SessionKey(identity.publicKey, durationSeconds);
    }
    
    public boolean hasActiveSession() {
        return session != null && session.isActive();
    }
    
    public byte[] getSessionProof() throws CBAException {
        if (session == null) {
            throw new CBAException(CBAException.ErrorCode.SESSION_EXPIRED, "No active session");
        }
        return session.generateProof();
    }
    
    public byte[] getSessionCommitment() {
        return session != null ? session.commitment : null;
    }
    
    // =========================================================================
    // API DE CAPABILITIES
    // =========================================================================
    
    public Capability issueCapability(byte[] holderPublicKey, int permissions,
                                       Set<String> resources, long durationSeconds,
                                       int maxUses, int maxDelegationDepth) throws CBAException {
        long now = System.currentTimeMillis() / 1000;
        
        // Gera ID
        byte[] capId = generateCapabilityId(holderPublicKey);
        
        // IDs do emissor e detentor
        byte[] issuerId = hash(identity.publicKey, ID_SIZE);
        byte[] holderId = hash(holderPublicKey, ID_SIZE);
        
        Capability cap = new Capability(capId, issuerId, holderId, permissions,
            resources, now, now + durationSeconds, maxUses, maxDelegationDepth);
        
        // Assina
        SignatureResult sig = identity.sign(cap.getDataForSigning());
        cap.signature = sig.signature;
        
        return cap;
    }
    
    public Capability delegateCapability(Capability parent, byte[] newHolderPublicKey,
                                          int permissions, Set<String> resources,
                                          long durationSeconds) throws CBAException {
        if (parent.revoked || isRevoked(parent.id)) {
            throw new CBAException(CBAException.ErrorCode.CAPABILITY_REVOKED, 
                "Parent capability is revoked");
        }
        
        if (parent.delegationDepth >= parent.maxDelegationDepth) {
            throw new CBAException(CBAException.ErrorCode.MAX_DELEGATION, 
                "Maximum delegation depth reached");
        }
        
        if (!parent.hasPermission(Permission.DELEGATE)) {
            throw new CBAException(CBAException.ErrorCode.PERMISSION_DENIED, 
                "Parent capability cannot delegate");
        }
        
        long now = System.currentTimeMillis() / 1000;
        
        // Restringe permissões
        int allowedPerms = permissions & parent.permissions;
        
        // Restringe duração
        long maxExpires = parent.expiresAt;
        long actualExpires = Math.min(now + durationSeconds, maxExpires);
        
        // Filtra recursos
        Set<String> allowedResources = new HashSet<>();
        for (String r : resources) {
            if (parent.hasResource(r)) {
                allowedResources.add(r);
            }
        }
        
        // Gera ID
        byte[] capId = generateCapabilityId(newHolderPublicKey);
        byte[] issuerId = hash(identity.publicKey, ID_SIZE);
        byte[] holderId = hash(newHolderPublicKey, ID_SIZE);
        
        Capability delegated = new Capability(capId, issuerId, holderId, allowedPerms,
            allowedResources, now, actualExpires, parent.maxUses, parent.maxDelegationDepth);
        delegated.delegationDepth = parent.delegationDepth + 1;
        delegated.parentId = parent.id;
        
        // Assina
        SignatureResult sig = identity.sign(delegated.getDataForSigning());
        delegated.signature = sig.signature;
        
        return delegated;
    }
    
    public void revokeCapability(byte[] capabilityId) {
        revocationList.add(new ByteArrayWrapper(capabilityId));
    }
    
    public boolean isRevoked(byte[] capabilityId) {
        return revocationList.contains(new ByteArrayWrapper(capabilityId));
    }
    
    // =========================================================================
    // API DE PROVA
    // =========================================================================
    
    public CBAProof generateProof(Capability cap, String operation, 
                                   String resourceId, boolean includeIdentity) throws CBAException {
        // Validações
        if (cap.revoked || isRevoked(cap.id)) {
            throw new CBAException(CBAException.ErrorCode.CAPABILITY_REVOKED, 
                "Capability is revoked");
        }
        
        if (cap.isExpired()) {
            throw new CBAException(CBAException.ErrorCode.CAPABILITY_EXPIRED, 
                "Capability expired");
        }
        
        if (cap.maxUses >= 0 && cap.usesCount >= cap.maxUses) {
            throw new CBAException(CBAException.ErrorCode.MAX_USES_EXCEEDED, 
                "Maximum uses exceeded");
        }
        
        if (!cap.hasResource(resourceId)) {
            throw new CBAException(CBAException.ErrorCode.RESOURCE_DENIED, 
                "Resource not in capability: " + resourceId);
        }
        
        Permission perm = Permission.fromString(operation);
        if (!cap.hasPermission(perm)) {
            throw new CBAException(CBAException.ErrorCode.PERMISSION_DENIED, 
                "Operation " + operation + " not permitted");
        }
        
        // Gera prova de sessão
        byte[] sessionProof = getSessionProof();
        
        CBAProof proof = new CBAProof(cap.id, sessionProof, operation, resourceId);
        
        // Prova de identidade (opcional)
        if (includeIdentity) {
            byte[] idData = concatenate(
                concatenate(cap.id, sessionProof),
                proof.nonce
            );
            SignatureResult idSig = identity.sign(idData);
            proof.identityProof = idSig.signature;
            proof.chainIndex = idSig.chainIndex;
        }
        
        // Assinatura final
        ByteArrayOutputStream proofData = new ByteArrayOutputStream();
        try {
            proofData.write(proof.capabilityId);
            proofData.write(proof.sessionProof);
            proofData.write(proof.operation.getBytes(StandardCharsets.UTF_8));
            proofData.write(proof.resourceId.getBytes(StandardCharsets.UTF_8));
            proofData.write(longToBytes(proof.timestamp));
            proofData.write(proof.nonce);
            if (proof.identityProof != null) {
                proofData.write(proof.identityProof);
            }
        } catch (IOException e) {
            // Shouldn't happen
        }
        
        proof.proofSignature = mac(session.getMasterEntropy(), proofData.toByteArray(), HASH_SIZE);
        
        // Incrementa uso
        cap.usesCount++;
        
        return proof;
    }
    
    public boolean verifyProof(CBAProof proof, Capability cap, 
                               byte[] issuerPublicKey, int issuerChainLength,
                               long maxAgeSeconds) {
        long now = System.currentTimeMillis() / 1000;
        
        // Verifica timestamp
        if (now - proof.timestamp > maxAgeSeconds) {
            return false;
        }
        
        if (proof.timestamp > now + 60) {
            return false;
        }
        
        // Verifica capability ID
        if (!constantTimeEquals(proof.capabilityId, cap.id)) {
            return false;
        }
        
        // Verifica revogação
        if (cap.revoked || isRevoked(cap.id)) {
            return false;
        }
        
        // Verifica expiração
        if (cap.isExpired()) {
            return false;
        }
        
        // Verifica assinatura da capability
        if (!verifyIdentitySignature(issuerPublicKey, cap.getDataForSigning(), 
                                     cap.signature, issuerChainLength)) {
            return false;
        }
        
        // Verifica operação e recurso
        if (!cap.hasResource(proof.resourceId)) {
            return false;
        }
        
        Permission perm = Permission.fromString(proof.operation);
        if (!cap.hasPermission(perm)) {
            return false;
        }
        
        // Verifica prova de identidade se presente
        if (proof.identityProof != null) {
            byte[] idData = concatenate(
                concatenate(cap.id, proof.sessionProof),
                proof.nonce
            );
            if (!verifyIdentitySignature(issuerPublicKey, idData, 
                                         proof.identityProof, issuerChainLength)) {
                return false;
            }
        }
        
        return true;
    }
    
    // =========================================================================
    // FUNÇÕES AUXILIARES
    // =========================================================================
    
    private byte[] generateCapabilityId(byte[] holderKey) {
        long now = System.currentTimeMillis() / 1000;
        byte[] input = concatenate(
            concatenate(identity.publicKey, holderKey),
            concatenate(longToBytes(now), intToBytes(idCounter++))
        );
        return hash(input, ID_SIZE);
    }
    
    private static void feistelRound(byte[] state, int round) {
        int len = state.length;
        for (int i = 0; i < len; i++) {
            int x = state[i] & 0xFF;
            x = rotateLeft((byte)x, (round + i) & 7) & 0xFF;
            x = x & (CONST_AND[(i + round * 7) & 31] & 0xFF);
            x = x | (CONST_OR[(i + round * 11) & 31] & 0xFF);
            x = x ^ (state[(i + round + 1) % len] & 0xFF);
            state[i] = (byte) x;
        }
    }
    
    private static byte rotateLeft(byte b, int n) {
        int val = b & 0xFF;
        return (byte) ((val << n) | (val >>> (8 - n)));
    }
    
    public static byte[] hash(byte[] data, int outLen) {
        byte[] state = new byte[32];
        
        // Prefixo
        byte[] prefix = "TAV-CBA-HASH-V1".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < prefix.length; i++) {
            state[i % 32] ^= prefix[i];
        }
        
        // Absorve dados
        for (int i = 0; i < data.length; i++) {
            state[i % 32] ^= data[i];
            if ((i + 1) % 32 == 0) {
                for (int r = 0; r < 4; r++) {
                    feistelRound(state, r);
                }
            }
        }
        
        // Finalização
        state[0] ^= (data.length >> 8) & 0xFF;
        state[1] ^= data.length & 0xFF;
        
        for (int r = 0; r < 8; r++) {
            feistelRound(state, r);
        }
        
        return Arrays.copyOf(state, Math.min(outLen, 32));
    }
    
    public static byte[] mac(byte[] key, byte[] data, int outLen) {
        byte[] combined = concatenate(concatenate(key, data), key);
        return hash(combined, outLen);
    }
    
    private static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    private static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
    
    private static byte[] longToBytes(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }
    
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    // Wrapper para usar byte[] em HashSet
    private static class ByteArrayWrapper {
        private final byte[] data;
        
        ByteArrayWrapper(byte[] data) {
            this.data = data;
        }
        
        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof ByteArrayWrapper)) return false;
            return Arrays.equals(data, ((ByteArrayWrapper) obj).data);
        }
        
        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }
    }
    
    // =========================================================================
    // DEMONSTRAÇÃO
    // =========================================================================
    
    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("TAV CAPABILITY-BASED AUTHENTICATION (CBA) V1.0 - Java Demo");
        System.out.println("======================================================================\n");
        
        try {
            // Alice
            System.out.println("1. Inicializando Alice...");
            TavCBA alice = new TavCBA("alice super secret seed", 100);
            System.out.println("   Assinaturas disponíveis: " + alice.getIdentityRemaining());
            
            // Bob
            System.out.println("\n2. Inicializando Bob...");
            TavCBA bob = new TavCBA("bob super secret seed", 100);
            System.out.println("   Assinaturas disponíveis: " + bob.getIdentityRemaining());
            
            // Sessões
            System.out.println("\n3. Criando sessões...");
            alice.createSession(3600);
            bob.createSession(3600);
            System.out.println("   Alice session ativa: " + alice.hasActiveSession());
            System.out.println("   Bob session ativa: " + bob.hasActiveSession());
            
            // Capability
            System.out.println("\n4. Alice emite capability para Bob...");
            Set<String> resources = new HashSet<>(Arrays.asList(
                "file:documento.txt", "file:relatorio.pdf", "channel:chat-123"
            ));
            
            Capability cap = alice.issueCapability(
                bob.getPublicKey(),
                Permission.READ.value | Permission.ENCRYPT.value | Permission.DELEGATE.value,
                resources,
                7200,   // 2 horas
                50,     // max 50 usos
                2       // max 2 níveis de delegação
            );
            
            System.out.println("   Capability ID: " + bytesToHex(cap.id).substring(0, 16) + "...");
            System.out.println("   Permissões: " + cap.permissions);
            System.out.println("   Recursos: " + cap.resources);
            System.out.println("   Tamanho serializado: " + cap.serialize().length + " bytes");
            
            // Bob usa capability
            System.out.println("\n5. Bob usa capability (READ)...");
            CBAProof proof = bob.generateProof(cap, "READ", "file:documento.txt", true);
            System.out.println("   Prova gerada com sucesso");
            System.out.println("   Com identidade: " + (proof.identityProof != null));
            System.out.println("   Tamanho da prova: " + proof.serialize().length + " bytes");
            
            // Carol
            System.out.println("\n6. Bob delega para Carol...");
            TavCBA carol = new TavCBA("carol super secret seed", 50);
            carol.createSession(3600);
            
            Set<String> carolResources = new HashSet<>(Arrays.asList("file:documento.txt"));
            Capability carolCap = bob.delegateCapability(
                cap,
                carol.getPublicKey(),
                Permission.READ.value,  // Apenas READ
                carolResources,
                3600
            );
            
            System.out.println("   Capability delegada");
            System.out.println("   Permissões: " + carolCap.permissions + " (apenas READ)");
            System.out.println("   Recursos: " + carolCap.resources);
            System.out.println("   Profundidade: " + carolCap.delegationDepth);
            
            // Carol tenta ENCRYPT (deve falhar)
            System.out.println("\n7. Carol tenta ENCRYPT (deve falhar)...");
            try {
                carol.generateProof(carolCap, "ENCRYPT", "file:documento.txt", false);
                System.out.println("   ERRO: Deveria ter falhado!");
            } catch (CBAException e) {
                System.out.println("   Negado: " + e.getMessage());
            }
            
            // Carol usa READ (deve funcionar)
            System.out.println("\n8. Carol usa READ (deve funcionar)...");
            CBAProof carolProof = carol.generateProof(carolCap, "READ", "file:documento.txt", false);
            System.out.println("   Sucesso! Prova gerada.");
            
            // Revogação
            System.out.println("\n9. Alice revoga capability de Bob...");
            alice.revokeCapability(cap.id);
            System.out.println("   Revogada: " + alice.isRevoked(cap.id));
            
            // Bob tenta usar após revogação
            System.out.println("\n10. Bob tenta usar capability revogada...");
            try {
                bob.generateProof(cap, "READ", "file:documento.txt", false);
                System.out.println("    ERRO: Deveria ter falhado!");
            } catch (CBAException e) {
                System.out.println("    Negado: " + e.getMessage());
            }
            
            // Status final
            System.out.println("\n11. Status final:");
            System.out.println("    Alice assinaturas restantes: " + alice.getIdentityRemaining());
            System.out.println("    Bob assinaturas restantes: " + bob.getIdentityRemaining());
            System.out.println("    Carol assinaturas restantes: " + carol.getIdentityRemaining());
            
        } catch (CBAException e) {
            System.err.println("Erro: " + e.code + " - " + e.getMessage());
        }
        
        System.out.println("\n======================================================================");
        System.out.println("Demo concluída!");
        System.out.println("======================================================================");
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
