=====================
Architecture Overview
=====================

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``, ``[FUNC-005]``.

Library Layout and Namespaces
-----------------------------

The library source is organized under the ``Crystal::Tpm2::Tss`` namespace with top-level backwards-compatibility aliases:

* **``src/crystal-tpm2-tss.cr``**: Shard entrypoint, ``VERSION`` constant, and top-level type aliases.
* **``src/crystal-tpm2-tss/types.cr``**: TCG TPM 2.0 command codes, handles, algorithms, curves, attributes, ``TPMError``, ``SecurityError``, and ``ECDSASignature`` value struct.
* **``src/crystal-tpm2-tss/p256_key.cr``**: OpenSSL 3.5 ``EVP_PKEY`` NIST P-256 keypair generator, ECDSA signer, and public-key verifier.
* **``src/crystal-tpm2-tss/command.cr``**: Big-endian ``TPMCommand`` packet serializer and ``TPMS_AUTH_COMMAND`` password/session framing builders.
* **``src/crystal-tpm2-tss/response.cr``**: Overflow-safe ``TPMResponse`` parser, session ``nonceTPM`` extractor, and ``TPM2_ReadPublic``/``TPM2_Sign`` payload decoders.
* **``src/crystal-tpm2-tss/device.cr``**: ``TPMDevice`` fail-closed ``/dev/tpmrm0`` character device transport and stateful OpenSSL P-256 virtual TPM simulator.
* **``src/crystal-tpm2-tss/session.cr``**: Thread-safe ``Session`` state machine with ``cpHash``, ``rpHash``, nonce rolling, and constant-time HMAC verification.
* **``src/crystal-tpm2-tss/parameter_encryption.cr``**: TCG TPM 2.0 Part 1 §11.4.9.2 ``KDFa`` counter-mode key derivation with ``XOR`` and ``AES-128-CFB`` parameter encryption.
* **``src/crystal-tpm2-tss/signature_r_tracker.cr``**: Thread-safe ``O(1)`` bounded ECDSA ``r``-component nonce reuse detector.
* **``src/crystal-tpm2-tss/kdf_key_manager.cr``**: Hardware NV-backed KDF master key manager at ``0x01C00000``.
* **``src/crystal-tpm2-tss/nv_metadata_store.cr``**: Disjoint NV index allocator (``0x01800000..0x01BFFFFF``) with bounded linear collision probing.
* **``src/crystal-tpm2-tss/fido2_credential.cr``**: ``FIDO2Credential`` entity encapsulating persistent handle, public ``(x, y)`` coordinates, signing, and signature verification.
* **``src/crystal-tpm2-tss/fido2_credential_manager.cr``**: ``FIDO2CredentialManager`` orchestrating primary key creation, child key loading, ``EvictControl`` persistence, and ``TPM2_ReadPublic`` inspection.

Memory and Concurrency Profile
------------------------------

All mutable session nonces, NV caches, virtual device stores, and ``SignatureRTracker`` windows are synchronized via ``Sync::Mutex`` for safe concurrent execution across Crystal 1.21 multithreaded Execution Contexts. Hardware command responses read into stack-allocated ``StaticArray(UInt8, 4096)`` buffers, while ``ECDSASignature`` uses value ``struct`` semantics.
