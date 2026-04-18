# Presentation Script for Teacher - CryptoChat E2E Encrypted Chat

## Duration: 10-15 minutes

---

## 1. INTRODUCTION (1-2 min)

> "Good morning/afternoon. For my cryptography exam, I implemented a zero-knowledge end-to-end encrypted chat application called CryptoChat. The key feature is that the server never sees the actual messages - it only routes opaque encrypted data."

**Key points to mention:**
- This is a practical implementation of what we've studied in class
- Combines several cryptographic primitives: ECDH, HKDF, Fernet
- Demonstrates zero-knowledge architecture

---

## 2. ARCHITECTURE OVERVIEW (2-3 min)

> "Let me show you the architecture. We have three components:"

```
┌─────────┐         ┌──────────┐         ┌─────────┐
│ Client1 │ ←─────→ │  Server  │ ←─────→ │ Client2 │
│  (EC)   │   WS   │ (Blind)  │   WS    │  (EC)   │
└─────────┘         └──────────┘         └─────────┘
     ↓                    ↓                    ↓
  Keys in             JSON only             Keys in
  memory only         routing               memory only
```

**Say:** "The server is a 'blind router' - it reads only the JSON headers (type, from, to) to know where to forward messages. It never touches the encrypted payload or public keys."

---

## 3. CRYPTOGRAPHY EXPLANATION (4-5 min)

### Step 1: Key Generation (SECP384R1)

> "Each client generates an ephemeral EC keypair using SECP384R1 curve at runtime. These keys exist only in memory - they're never written to disk."

```python
private_key = ec.generate_private_key(ec.SECP384R1())
```

**Why SECP384R1?** "It's a NIST P-384 curve, stronger than P-256 we studied, providing 192-bit security level."

---

### Step 2: Key Exchange (ECDH)

> "When Client1 wants to chat with Client2, they exchange public keys as PEM strings through the server."

```python
# Both clients compute the same shared secret
shared_secret = my_private.exchange(ECDH(), peer_public_key)
```

**Key point:** "The server only sees the public keys as opaque PEM strings - it cannot compute the shared secret because it doesn't have either private key."

---

### Step 3: Key Derivation (HKDF)

> "IMPORTANT: We never use the raw ECDH output directly as an encryption key. We always derive a proper key using HKDF."

```python
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,  # Fernet requires exactly 32 bytes
    info=b"CryptoChat-ECDH-SECP384R1",
).derive(shared_secret)
```

**Why HKDF?** "This prevents potential weak key attacks and properly distributes the entropy from the ECDH output."

---

### Step 4: Fernet Encryption

> "We convert the derived 32-byte key to base64url format (as Fernet requires) and use it for symmetric encryption."

```python
fernet_key = base64.urlsafe_b64encode(derived_key)
cipher = Fernet(fernet_key)

# Encrypt message
ciphertext = cipher.encrypt(message.encode())
payload_b64 = base64.b64encode(ciphertext).decode()
```

**Why Fernet?** "It's a high-level interface to AES-128-CBC with HMAC-SHA256 for authentication. It provides both confidentiality and integrity."

---

## 4. PROTOCOL FLOW (2-3 min)

> "Let me walk through what happens when Client1 sends a message to Client2:"

1. **Registration**: Both clients register with the server
2. **Key Exchange**: Client1 sends public key via `pubkey_offer`, Client2 responds with `pubkey_accept`
3. **Key Derivation**: Both derive the same Fernet key from ECDH
4. **Chat**: Client1 encrypts with Fernet → base64 → sends as `payload_b64`
5. **Decryption**: Client2 decrypts with the same derived key

**Demo live:** "I can show you the actual execution now."

---

## 5. ZERO-KNOWLEDGE PROOF (1-2 min)

> "The server is truly zero-knowledge because:"

- ✅ Server sees ONLY `type`, `from`, `to` fields for routing
- ✅ `public_key_pem` is forwarded as opaque PEM string (server can't read it)
- ✅ `payload_b64` is forwarded as opaque base64 (server can't decrypt it)
- ✅ Private keys never leave the client
- ✅ Server never has the symmetric key

**Ask the teacher:** "Can I prove this by showing the server code?"

---

## 6. QUESTIONS PREPARATION

### Common questions you might get:

**Q: Why not use RSA?**
A: "RSA would require the server to forward messages that the receiver must decrypt with their private key. With ECDH, both parties derive the same symmetric key - the server never sees any decryptable data."

**Q: Why HKDF and not use the raw ECDH output?**
A: "The raw ECDH output is not uniformly distributed - it's a point on the curve. HKDF properly extracts and expands the entropy into a cryptographically strong symmetric key."

**Q: What happens if a man-in-the-middle replaces the public keys?**
A: "This is a known limitation - we need a way to verify key authenticity. In production, we'd add key fingerprints or a PKI. For this exam project, we assume the server doesn't tamper with keys."

**Q: Is this truly end-to-end encrypted?**
A: "Yes. Only Client1 and Client2 can read the messages. The server only sees encrypted blobs."

---

## 7. LIVE DEMO

**Instructions:**

```bash
# Terminal 1 - Start server
python server.py

# Terminal 2 - Start Client1
python client1.py

# Terminal 3 - Start Client2
python client2.py
```

**What to show:**
1. Type message in Client1 → shows `[me] <message>`
2. Client2 receives → shows `[peer] <message>`
3. Type `salir` to exit

---

## 8. CONCLUSION

> "In summary, this project demonstrates:
- ECDH for key exchange (no server involvement)
- HKDF for proper key derivation
- Fernet for authenticated symmetric encryption
- Zero-knowledge server architecture

Thank you for your time. I'm happy to answer any questions."

---

## Quick Reference Card

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Gen | SECP384R1 | Ephemeral EC keypair per session |
| Exchange | ECDH | Compute shared secret |
| Derivation | HKDF-SHA256 | 32-byte symmetric key |
| Encryption | Fernet (AES-128-CBC + HMAC) | Authenticated encryption |
| Payload | base64 | JSON-safe binary encoding |