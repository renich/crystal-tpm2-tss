===================================
Phase 1: TPM 2.0 Software Stack MVP
===================================

Timeline and Objectives
-----------------------

Deliver native TPM 2.0 Software Stack capabilities in Crystal, supporting NV storage key derivation, password and HMAC sessions, primary key generation, and FIDO2 credential signing.

Milestones and Deliverables
---------------------------

* **Milestone 1.1: Core TPM 2.0 Wire Framing and NV Persistence**:

  - [x] ``[TPM-001]`` Serialize ``TPMCommand`` packets and parse ``TPMResponse`` headers and session areas.
  - [x] ``[TPM-002]`` Store and retrieve root derivation keys in hardware NV indices via ``KDFKeyManager``.
  - [x] ``[TPM-003]`` Track caller and TPM nonces across authorization sessions in ``Session``.
  - [x] ``[TPM-004]`` Provision ECC primary keys and sign challenge digests in ``FIDO2CredentialManager``.
