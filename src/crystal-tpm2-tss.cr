# Native Crystal TPM 2.0 Software Stack (TSS) with hardware-backed KDF
# persistence, session-based authorization, parameter encryption, and
# FIDO2/CTAP2 credential management.
module Crystal::Tpm2::Tss
  # Semantic version of `crystal-tpm2-tss`.
  VERSION = "0.4.1"
end

require "./crystal-tpm2-tss/types"
require "./crystal-tpm2-tss/p256_key"
require "./crystal-tpm2-tss/tpm2b_codec"
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

# Top-level alias for `Crystal::Tpm2::Tss::TPM2`.
alias TPM2 = Crystal::Tpm2::Tss::TPM2
# Top-level alias for `Crystal::Tpm2::Tss::P256Key`.
alias P256Key = Crystal::Tpm2::Tss::P256Key
# Top-level alias for `Crystal::Tpm2::Tss::Tpm2bCodec`.
alias Tpm2bCodec = Crystal::Tpm2::Tss::Tpm2bCodec
# Top-level alias for `Crystal::Tpm2::Tss::TPMCommand`.
alias TPMCommand = Crystal::Tpm2::Tss::TPMCommand
# Top-level alias for `Crystal::Tpm2::Tss::TPMResponse`.
alias TPMResponse = Crystal::Tpm2::Tss::TPMResponse
# Top-level alias for `Crystal::Tpm2::Tss::TPMDevice`.
alias TPMDevice = Crystal::Tpm2::Tss::TPMDevice
# Top-level alias for `Crystal::Tpm2::Tss::Session`.
alias Session = Crystal::Tpm2::Tss::Session
# Top-level alias for `Crystal::Tpm2::Tss::KDFKeyManager`.
alias KDFKeyManager = Crystal::Tpm2::Tss::KDFKeyManager
# Top-level alias for `Crystal::Tpm2::Tss::NVMetadataStore`.
alias NVMetadataStore = Crystal::Tpm2::Tss::NVMetadataStore
# Top-level alias for `Crystal::Tpm2::Tss::FIDO2CredentialManager`.
alias FIDO2CredentialManager = Crystal::Tpm2::Tss::FIDO2CredentialManager
# Top-level alias for `Crystal::Tpm2::Tss::FIDO2Credential`.
alias FIDO2Credential = Crystal::Tpm2::Tss::FIDO2Credential
# Top-level alias for `Crystal::Tpm2::Tss::ECDSASignature`.
alias ECDSASignature = Crystal::Tpm2::Tss::ECDSASignature
# Top-level alias for `Crystal::Tpm2::Tss::SignatureRTracker`.
alias SignatureRTracker = Crystal::Tpm2::Tss::SignatureRTracker
# Top-level alias for `Crystal::Tpm2::Tss::ParameterEncryption`.
alias ParameterEncryption = Crystal::Tpm2::Tss::ParameterEncryption
# Top-level alias for `Crystal::Tpm2::Tss::TPMError`.
alias TPMError = Crystal::Tpm2::Tss::TPMError
# Top-level alias for `Crystal::Tpm2::Tss::SecurityError`.
alias SecurityError = Crystal::Tpm2::Tss::SecurityError
