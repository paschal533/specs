| Lifecycle Stage | Maturity      | Status | Latest Revision |
|-----------------|---------------|--------|-----------------|
| 1A              | Working Draft | Active | 2026-04-28      |

Authors: [@paschal533](https://github.com/paschal533)

Interest Group: to be formed -- post on the [libp2p forum](https://discuss.libp2p.io) to join

See the [lifecycle document](https://github.com/libp2p/specs/blob/master/00-framework-01-spec-lifecycle.md) for context about the maturity level and expected evolution of this spec.

---

# Noise PQ: Post-Quantum Hybrid Noise Handshake for libp2p

**Protocol ID:** `/noise-pq/1.0.0`
**Pattern:** `Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256`
**Based on:** [Noise HFS extension spec](https://github.com/noiseprotocol/noise_hfs_spec), [PQNoise (ePrint 2022/539)](https://eprint.iacr.org/2022/539), [draft-connolly-cfrg-xwing-kem](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.txt)

## Table of Contents

- [1. Overview](#1-overview)
- [2. Algorithm Identifiers](#2-algorithm-identifiers)
- [3. Handshake Pattern](#3-handshake-pattern)
- [4. KEM Interface](#4-kem-interface)
- [5. Wire Format](#5-wire-format)
- [6. Token Ordering](#6-token-ordering)
- [7. State Machine](#7-state-machine)
- [8. Cipher State Split](#8-cipher-state-split)
- [9. ML-KEM Implicit Rejection](#9-ml-kem-implicit-rejection)
- [10. Security Properties](#10-security-properties)
- [11. Test Vectors](#11-test-vectors)
- [12. Usage](#12-usage)
- [13. Interoperability Requirements](#13-interoperability-requirements)
- [14. Performance Reference](#14-performance-reference)

---

## 1. Overview

This document specifies the `Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256` handshake as a post-quantum hybrid extension of the classical [Noise XX](https://github.com/libp2p/specs/tree/master/noise) protocol used in libp2p.

The handshake adds an ephemeral KEM step (the Noise HFS tokens `e1` and `ekem1`) alongside the existing X25519 ECDH operations. This provides **hybrid post-quantum forward secrecy**: the session is secure if **either** X25519 **or** ML-KEM-768 is unbroken, preserving full backward compatibility with classical security guarantees while adding protection against future quantum adversaries.

The protocol uses X-Wing as the KEM primitive. X-Wing is a hybrid KEM that combines ML-KEM-768 (NIST FIPS 203) and X25519 via a SHA3-256 combiner, producing a 32-byte shared secret compatible with standard Noise key schedules.

---

## 2. Algorithm Identifiers

| Role | Algorithm | Specification |
|------|-----------|---------------|
| KEM | X-Wing (ML-KEM-768 + X25519) | [draft-connolly-cfrg-xwing-kem-06](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.txt) |
| DH | X25519 | RFC 7748 |
| AEAD | ChaCha20-Poly1305 | RFC 8439 |
| Hash / HKDF | SHA-256 | FIPS 180-4 / RFC 5869 |
| KEM lattice | ML-KEM-768 | NIST FIPS 203 |

X-Wing outputs a 32-byte combined shared secret using the combiner defined in the IETF draft. This combiner binds to both the ML-KEM and X25519 ciphertexts and public keys, preventing mix-and-match attacks.

---

## 3. Handshake Pattern

The `XXhfs` pattern extends classical Noise XX by adding the `e1` and `ekem1` HFS tokens:

```
Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256:
  <- s
  ...
  -> e, e1
  <- e, ee, ekem1, s, es
  -> s, se
```

- **`e`**: X25519 ephemeral key (classical, 32 bytes)
- **`e1`**: X-Wing KEM ephemeral public key (1216 bytes: 1184-byte ML-KEM-768 encapsulation key + 32-byte X25519 pk)
- **`ekem1`**: X-Wing ciphertext encrypted under the `ee`-derived key (1136 bytes: 1120-byte ct + 16-byte AEAD tag), followed by `MixKey(KEM shared secret)`

The HFS tokens follow the Noise HFS extension specification: `encryptAndHash(cipherText)` is applied **before** `mixKey(sharedSecret)`. This ordering is mandatory.

---

## 4. KEM Interface

Any KEM used with this protocol must implement the following interface:

```
IKem:
  PUBKEY_LEN: integer   // X-Wing: 1216 bytes
  CT_LEN:     integer   // X-Wing: 1120 bytes
  SS_LEN:     integer   // X-Wing: 32 bytes

  generateKemKeyPair() -> (publicKey: bytes, secretKey: bytes)
  encapsulate(remotePublicKey: bytes) -> (cipherText: bytes, sharedSecret: bytes)
  decapsulate(cipherText: bytes, secretKey: bytes) -> sharedSecret: bytes
```

The default implementation uses X-Wing as defined in [draft-connolly-cfrg-xwing-kem](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.txt). Implementations MAY substitute a different KEM conforming to this interface for testing or experimentation, but interoperability across implementations requires the X-Wing default.

---

## 5. Wire Format

Message sizes assume an empty libp2p `NoiseHandshakePayload`. Real handshakes include identity keys and signatures (approximately 108 bytes per side for Ed25519), adding roughly 308 bytes total to the figures below.

### 5.1 Message A (initiator to responder)

```
+-------------------+-----------------------+---------+
| e.publicKey       | e1.publicKey          | payload |
| 32 bytes          | 1216 bytes            | 0 bytes |
+-------------------+-----------------------+---------+
Total: 1248 bytes
```

`e.publicKey` is sent in plaintext (no cipher key exists yet). `e1.publicKey` is processed via `encryptAndHash()`, which at this stage is a plain `MixHash()` because there is no active cipher.

### 5.2 Message B (responder to initiator)

```
+-------------------+-----------------------+--------------------+---------+
| e.publicKey       | enc(KEM ciphertext)   | enc(s.publicKey)   | payload |
| 32 bytes          | 1136 bytes            | 48 bytes           | 16 bytes|
+-------------------+-----------------------+--------------------+---------+
Total: 1232 bytes (with empty payload; 16-byte AEAD tag on payload)
```

After `ee`: `MixKey(DH(e_R, e_I))` establishes the first cipher key. The 1120-byte X-Wing ciphertext is encrypted under this key (adding a 16-byte AEAD tag = 1136 bytes total). `MixKey(kemSharedSecret)` follows the ciphertext, strengthening subsequent operations.

### 5.3 Message C (initiator to responder)

```
+--------------------+---------+
| enc(s.publicKey)   | payload |
| 48 bytes           | 16 bytes|
+--------------------+---------+
Total: 64 bytes (with empty payload)
```

Identical structure to the classical Noise XX Message C.

### 5.4 Size comparison with classical XX

| Message | Classical XX | XXhfs (PQ) | Delta |
|---------|------------:|----------:|------:|
| Msg A | 32 bytes | 1,248 bytes | +1,216 bytes |
| Msg B | 96 bytes | 1,232 bytes | +1,136 bytes |
| Msg C | 64 bytes | 64 bytes | 0 bytes |
| **Total** | **192 bytes** | **2,544 bytes** | **+2,352 bytes** |

---

## 6. Token Ordering

The `ekem1` token **must** follow this exact ordering on both initiator and responder sides:

**Responder (write ekem1):**

```
1. (ct, ss) = encapsulate(re1)       // encapsulate to initiator's e1 public key
2. encryptAndHash(ct)                // encrypt ciphertext under ee-derived key
3. mixKey(ss)                        // mix KEM shared secret AFTER encrypting ct
```

**Initiator (read ekem1):**

```
1. ct = decryptAndHash(enc_ct)       // decrypt the ciphertext (AEAD authenticated)
2. ss = decapsulate(ct, e1.secretKey)
3. mixKey(ss)                        // must match write ordering
```

Swapping steps 2 and 3 (encrypt/decrypt after mixKey) produces divergent chaining keys and is **incorrect**. The AEAD protection on the ciphertext means tampering is caught at step 1 before decapsulation is attempted.

---

## 7. State Machine

```
Initiator                               Responder
---------                               ---------
generate e (X25519)
generate e1 (X-Wing)
writeMessageA(payload=empty)
  MixHash(e.publicKey)
  MixHash(e1.publicKey)
  -> e, e1
                                        readMessageA()
                                          MixHash(e.publicKey)    // store as re
                                          MixHash(e1.publicKey)   // store as re1

                                        generate e (X25519)
                                        writeMessageB(payload)
                                          MixHash(e.publicKey)
                                          ee: MixKey(DH(e_R, e_I))
                                          (ct, ss) = encapsulate(re1)
                                          encryptAndHash(ct)      // ekem1 write
                                          mixKey(ss)
                                          encryptAndHash(s.publicKey)
                                          es: MixKey(DH(s_R, e_I))
                                          encryptAndHash(payload)
                                          -> e, enc(ct), enc(s), enc(payload)

readMessageB()
  MixHash(re.publicKey)
  ee: MixKey(DH(e_I, re))
  ct = decryptAndHash(enc_ct)         // ekem1 read
  ss = decapsulate(ct, e1.secretKey)
  mixKey(ss)
  resp_s = decryptAndHash(enc_s)
  es: MixKey(DH(e_I, resp_s))
  verify payload signature

writeMessageC(payload)
  encryptAndHash(s.publicKey)
  se: MixKey(DH(s_I, re))
  encryptAndHash(payload)
  -> enc(s), enc(payload)
                                        readMessageC()
                                          init_s = decryptAndHash(enc_s)
                                          se: MixKey(DH(e_R, init_s))
                                          verify payload signature

[cs1, cs2] = split()                    [cs1, cs2] = split()
encrypt = cs1, decrypt = cs2            encrypt = cs2, decrypt = cs1
```

---

## 8. Cipher State Split

After `split()`, two directional cipher states are derived from the final chaining key via HKDF-SHA256:

| Direction | Initiator | Responder |
|-----------|-----------|-----------|
| Initiator to responder | encrypt with `cs1` | decrypt with `cs1` |
| Responder to initiator | decrypt with `cs2` | encrypt with `cs2` |

Each cipher state maintains an independent nonce counter starting at zero. The nonce is never transmitted; both sides increment in lockstep.

---

## 9. ML-KEM Implicit Rejection

ML-KEM-768 (FIPS 203 Section 6.4) implements implicit rejection: `Decaps()` never throws on an invalid ciphertext. Instead it returns a pseudorandom value derived from a secret implicit rejection key. This means:

- A tampered or wrong-key ciphertext produces a divergent KEM shared secret rather than an explicit error.
- The divergence propagates through `mixKey()`, causing all subsequent AEAD operations to fail authentication.
- The handshake still aborts cleanly via AEAD failure.

Because `encryptAndHash(ct)` precedes `mixKey(ss)`, an attacker who tampers with the ciphertext in transit will be caught by the AEAD tag before decapsulation runs.

---

## 10. Security Properties

| Property | Mechanism |
|----------|-----------|
| Forward secrecy (classical) | Ephemeral X25519 on both sides (DH ee) |
| Forward secrecy (quantum-safe) | X-Wing KEM: ML-KEM-768 + X25519 hybrid |
| Mutual authentication | DH(es) + DH(se) via libp2p identity signatures |
| Identity hiding | Static keys transmitted after ephemeral exchange |
| Hybrid robustness | Secure if either X25519 or ML-KEM-768 is unbroken |
| Payload confidentiality | ChaCha20-Poly1305 under the post-split cipher states |

**Out of scope:** Quantum-safe *authentication*. Identity keys use Ed25519 (classical). Full post-quantum authentication requires ML-DSA (FIPS 204) identity keys and is tracked separately.

---

## 11. Test Vectors

Implementations should validate against the test vectors schema:

```json
{
  "protocol": "Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256",
  "vectors": [
    {
      "vector_index": 1,
      "static_i_public":        "<hex 32B>",
      "static_i_private":       "<hex 32B>",
      "static_r_public":        "<hex 32B>",
      "static_r_private":       "<hex 32B>",
      "ephemeral_dh_i_public":  "<hex 32B>",
      "ephemeral_dh_i_private": "<hex 32B>",
      "ephemeral_dh_r_public":  "<hex 32B>",
      "ephemeral_dh_r_private": "<hex 32B>",
      "ephemeral_kem_i_public": "<hex 1216B>",
      "ephemeral_kem_i_secret": "<hex 32B seed>",
      "encap_seed_hex":         "<hex 64B>",
      "msg_a":                  "<hex 1248B>",
      "msg_b":                  "<hex 1232B>",
      "msg_c":                  "<hex 64B>",
      "handshake_hash":         "<hex 32B>",
      "cs1_k":                  "<hex 32B>",
      "cs2_k":                  "<hex 32B>"
    }
  ]
}
```

Reference test vectors are published in the JavaScript implementation at [paschal533/js-libp2p-noise](https://github.com/paschal533/js-libp2p-noise) under `test/fixtures/pqc-test-vectors.json`.

---

## 12. Usage

### JavaScript (js-libp2p-noise)

```typescript
import { createLibp2p } from 'libp2p'
import { noiseHFS } from '@chainsafe/libp2p-noise'

const node = await createLibp2p({
  connectionEncrypters: [noiseHFS()],
})
```

### Python (py-libp2p)

```python
from libp2p.security.noise.pq import TransportPQ, PROTOCOL_ID

host = await new_node(
    security_opt={PROTOCOL_ID: TransportPQ(libp2p_keypair, noise_privkey)}
)
```

Both implementations auto-select the fastest available KEM backend (native WASM or liboqs C library if available, falling back to pure-software implementations).

---

## 13. Interoperability Requirements

A conforming implementation MUST:

1. Use the exact protocol name: `Noise_XXhfs_25519+XWing_ChaChaPoly_SHA256`
2. Use X-Wing (ML-KEM-768 + X25519 with SHA3-256 combiner) as the KEM primitive
3. Apply `encryptAndHash(cipherText)` BEFORE `mixKey(sharedSecret)` in the `ekem1` token
4. Transmit `e1.publicKey` as 1216 bytes in Message A (no AEAD tag at this stage)
5. Transmit `ekem1` as exactly 1136 bytes in Message B (1120-byte ciphertext + 16-byte AEAD tag)
6. Pass the test vectors published by the reference implementation

---

## 14. Performance Reference

Measured on Node.js v22, Windows 11 x64 (pure-JS, no WASM):

| Operation | ops/s | ms/op |
|-----------|------:|------:|
| X-Wing keygen | 293 | 3.42 |
| X-Wing encapsulate | 120 | 8.32 |
| X-Wing decapsulate | 136 | 7.33 |
| KEM round-trip | 47 | 21.43 |
| Classical XX handshake | 114 | 8.75 |
| XXhfs handshake | 23 | 44.18 |

The approximately 5x latency increase over classical XX is dominated by the X-Wing KEM (~21 ms per round-trip). WASM acceleration of the ML-KEM-768 lattice arithmetic yields a 3.2x speedup in isolated KEM throughput; full handshake improvement is approximately 4% because non-KEM operations (SHA-256, ChaCha20-Poly1305, HKDF, Ed25519, protobuf serialization, async scheduling) dominate in the JavaScript runtime.

Python measurements with the kyber-py pure-Python backend show significantly higher KEM latency (keygen 10.5 ms, encap 12.3 ms, decap 15.5 ms), with the KEM accounting for approximately 94% of total handshake time. The liboqs C backend reduces this to below 3.2 ms, below the classical Noise baseline.
