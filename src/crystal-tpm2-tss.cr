# Native Crystal TPM 2.0 Software Stack (TSS) with hardware-backed KDF
# persistence, session-based authorization, parameter encryption, and
# FIDO2/CTAP2 credential management.
module Crystal::Tpm2::Tss
  # Semantic version of `crystal-tpm2-tss`.
  VERSION = "0.4.0"
end

require "./crystal-tpm2-tss/types"
require "./crystal-tpm2-tss/p256_key"
require "./crystal-tpm2-tss/command"
require "./crystal-tpm2-tss/response"
require "./crystal-tpm2-tss/device"
require "./crystal-tpm2-tss/session"
require "./crystal-tpm2-tss/parameter_encryption"
require "./crystal-tpm2-tss/signature_r_tracker"
require "./crystal-tpm2-tss/kdf_key_manager"
require "./crystal-tpm2-tss/nv_metadata_store"
require "./crystal-tpm2-tss/fido2_credential"
require "./crystal-tpm2-tss/fido2_credential_manager"

# Top-level backwards compatibility aliases
alias TPM2 = Crystal::Tpm2::Tss::TPM2
alias P256Key = Crystal::Tpm2::Tss::P256Key
alias TPMCommand = Crystal::Tpm2::Tss::TPMCommand
alias TPMResponse = Crystal::Tpm2::Tss::TPMResponse
alias TPMDevice = Crystal::Tpm2::Tss::TPMDevice
alias Session = Crystal::Tpm2::Tss::Session
alias KDFKeyManager = Crystal::Tpm2::Tss::KDFKeyManager
alias NVMetadataStore = Crystal::Tpm2::Tss::NVMetadataStore
alias FIDO2CredentialManager = Crystal::Tpm2::Tss::FIDO2CredentialManager
alias FIDO2Credential = Crystal::Tpm2::Tss::FIDO2Credential
alias ECDSASignature = Crystal::Tpm2::Tss::ECDSASignature
alias SignatureRTracker = Crystal::Tpm2::Tss::SignatureRTracker
alias ParameterEncryption = Crystal::Tpm2::Tss::ParameterEncryption
alias TPMError = Crystal::Tpm2::Tss::TPMError
alias SecurityError = Crystal::Tpm2::Tss::SecurityError
