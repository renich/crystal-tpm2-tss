=======================================
Phase 1: TPM 2.0 Software Stack MVP
=======================================

Status: Completed
Target Version: 0.1.0

Overview
========
Implement native TPM 2.0 Software Stack (TSS) capabilities in Crystal, supporting NV storage key derivation, password sessions, primary key generation, and FIDO2 credential signing.

Milestones & Deliverables
=========================
* **[TPM-001] TPM2 Command Framing**: Build and serialize command packets and parse response headers and parameters.
* **[TPM-002] NV Memory KDF Persistence**: Store and retrieve root derivation keys in hardware NV indices with platform secret authorization.
* **[TPM-003] Session Nonce Management**: Track caller and TPM nonces across auth sessions.
* **[TPM-004] FIDO2 Credential Creation**: Create ECC primary keys and sign challenge digests.
