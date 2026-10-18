=================
Problem Statement
=================

Context
-------

Interacting with Trusted Platform Module 2.0 hardware from Crystal typically requires complex C bindings to multi-layered C TSS libraries or shelling out to ``tpm2-tools`` subprocesses. Furthermore, naive FIDO2 authenticator implementations frequently lose authorization state across reboots, fail to update rolling session nonces, or remain vulnerable to catastrophic private key recovery if a hardware RNG reuses an ECDSA nonce.

Solution
--------

``crystal-tpm2-tss`` provides a pure, memory-safe Crystal TPM 2.0 Software Stack that communicates directly over ``/dev/tpmrm0`` or an in-memory OpenSSL 3.5 NIST P-256 virtual simulator. It enforces persistent NV storage for KDF master keys, collision-resistant NV metadata linear probing, rolling ``cpHash``/``rpHash`` session authorization, KDFa XOR and AES-128-CFB parameter encryption, and atomic ``O(1)`` ECDSA nonce reuse detection.
