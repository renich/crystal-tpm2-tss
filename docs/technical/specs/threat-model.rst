============
Threat Model
============

Requirement Mapping
-------------------

Fulfills ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``, ``[FUNC-005]``.

Security Posture
----------------

* **ECDSA Nonce Reuse Mitigation**: Hardware RNG faults that repeat an ECDSA per-message secret ``k`` allow immediate algebraic recovery of the private scalar. ``SignatureRTracker#check_and_add!`` atomically tracks the last 10,000 ``r`` components in ``O(1)`` time and raises ``SecurityError`` before any duplicate-nonce signature is returned.
* **Constant-Time Authorization Verification**: ``Session#verify_response_hmac`` compares expected and received HMAC digests using ``Crypto::Subtle.constant_time_compare`` to eliminate timing side channels.
* **Bus Sniffing Protection**: ``ParameterEncryption`` derives per-command session keys via TCG TPM 2.0 Part 1 ``KDFa`` bound to rolling ``nonceCaller`` and ``nonceTPM`` values, supporting both ``XOR`` obfuscation and ``AES-128-CFB`` encryption.
* **NV Index Collision Isolation**: ``NVMetadataStore`` partitions FIDO2 credential metadata into ``0x01800000..0x01BFFFFF`` (disjoint from the KDF root key at ``0x01C00000``) and verifies embedded ``credential_id`` payloads during linear probing.
* **Overflow-Safe Response Framing**: ``TPMResponse.parse`` widens session ``auth_size`` bounds checks to ``UInt64`` prior to slicing response buffers, preventing integer wraparound attacks on malformed TPM packets.
