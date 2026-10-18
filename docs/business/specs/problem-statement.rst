=================
Problem Statement
=================

Context
-------

Interacting with Trusted Platform Module 2.0 hardware from Crystal traditionally requires C bindings to multi-layered C TSS libraries or shelling out to ``tpm2-tools`` subprocesses. Furthermore, naive FIDO2 authenticator implementations lose authorization state across reboots, fail to update rolling session nonces, omit parameter encryption on the LPC/SPI bus, or remain vulnerable to catastrophic private key recovery when a hardware RNG reuses an ECDSA nonce.

Solution
--------

``crystal-tpm2-tss`` provides a memory-safe Crystal TPM 2.0 Software Stack that communicates directly over ``/dev/tpmrm0`` or a deterministic in-memory OpenSSL 3.5 NIST P-256 virtual simulator. In Phase 1 ``v0.4.0``, the shard enforces persistent NV storage for KDF master keys, collision-resistant NV metadata linear probing, rolling ``cpHash``/``rpHash`` session authorization, KDFa ``XOR`` and ``AES-128-CFB`` parameter encryption, and atomic ``O(1)`` ECDSA nonce-reuse detection. In Phase 2 ``v0.4.1``, the shard extends physical ``/dev/tpmrm0`` interoperability with full TCG TPM 2.0 Part 2 binary structure marshaling and hardware salted/bound HMAC and ``PolicyPCR`` session lifecycles.
