=================
Core Requirements
=================

Functional Requirements
-----------------------

* **[FUNC-001] Binary TPM 2.0 Command and Response Framing**:
  The library must serialize big-endian ``TPMCommand`` packets (headers, handle areas, ``TPMS_AUTH_COMMAND`` session areas, and parameter buffers) and parse ``TPMResponse`` packets with overflow-safe session boundary checks.

* **[FUNC-002] Hardware and Stateful Virtual Transport**:
  ``TPMDevice`` must support fail-closed character device I/O over ``/dev/tpmrm0`` as well as an in-memory virtual simulator backed by real OpenSSL 3.5 NIST P-256 key generation (``Create``, ``Load``, ``EvictControl``, ``ReadPublic``, ``Sign``, and ``StartAuthSession``).

* **[FUNC-003] Session Authorization and Parameter Encryption**:
  ``Session`` and ``ParameterEncryption`` must support thread-safe nonce rolling, TCG TPM 2.0 Part 1 §19.6.5 ``cpHash`` and ``rpHash`` calculation, constant-time HMAC verification, and KDFa counter-mode ``XOR`` and ``AES-128-CFB`` parameter encryption.

* **[FUNC-004] Persistent KDF and FIDO2 Credential Lifecycle**:
  ``KDFKeyManager``, ``NVMetadataStore``, and ``FIDO2CredentialManager`` must persist root derivation keys in TPM NV memory, resolve NV index collisions via bounded linear probing, derive distinct persistent handles per credential, extract public ``(x, y)`` coordinates via ``TPM2_ReadPublic``, and verify NIST P-256 ECDSA signatures.

* **[FUNC-005] Atomic ECDSA Nonce Reuse Detection**:
  ``SignatureRTracker`` must record ECDSA ``r`` components in an ``O(1)`` ``Set``/``Deque`` window and raise ``SecurityError`` immediately upon detecting duplicate ``r`` values.
