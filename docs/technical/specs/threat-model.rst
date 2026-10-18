============
Threat Model
============

Requirement Mapping
-------------------

Fulfills ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``, ``[FUNC-005]``, ``[FUNC-006]``, ``[FUNC-007]`` in :doc:`../../functional/specs/core-requirements`.

Technical Specification
-----------------------

* **[TECH-005] Cryptographic, Framing, and Bus Threat Mitigations**:
  Fulfills ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``, ``[FUNC-005]``, ``[FUNC-006]``, and ``[FUNC-007]``. The library enforces the following deterministic security controls:

  * **ECDSA Nonce-Reuse Mitigation**: Hardware RNG faults that repeat an ECDSA per-message secret ``k`` allow immediate algebraic recovery of the NIST P-256 private scalar. ``SignatureRTracker#check_and_add!`` atomically tracks the last 10,000 ``r`` components in ``O(1)`` time using ``Set(String)`` and ``Deque(String)`` under ``Sync::Mutex`` and raises ``SecurityError`` before any duplicate-nonce signature is returned.
  * **Constant-Time Authorization Verification**: ``Session#verify_response_hmac`` compares expected and received HMAC digests over ``cpHash`` and ``rpHash`` parameters using ``Crypto::Subtle.constant_time_compare`` to eliminate timing side channels.
  * **Physical Bus Sniffing Protection**: ``ParameterEncryption`` derives per-command session keys via TCG TPM 2.0 Part 1 ``KDFa`` bound to rolling ``nonceCaller`` and ``nonceTPM`` values, enforcing non-empty session keys and nonces before performing ``XOR`` obfuscation or ``AES-128-CFB`` encryption.
  * **NV Index Collision and Hierarchy Isolation**: ``NVMetadataStore`` partitions FIDO2 credential metadata into ``0x01800000..0x01BFFFFF`` disjoint from the KDF root key at ``0x01C00000``, derives distinct persistent handles ``0x81010000 | hash_u16``, and verifies embedded ``credential_id`` payloads during linear probing.
  * **Overflow-Safe Wire Unmarshaling**: ``TPMResponse.parse`` widens session ``auth_size`` bounds checks to ``UInt64`` prior to slicing response buffers, and Phase 2 ``Tpm2bCodec`` decoders reject truncated or oversized ``TPM2B_*`` structures before heap allocation.
  * **PCR State Binding**: Phase 2 ``PolicyPCR`` sessions bind credential authorization to measured platform configuration registers and salted session keys so compromised OS processes cannot replay captured authorization tokens across altered boot states.
