module Crystal::Tpm2::Tss
  VERSION = "0.2.0"
end

require "./crystal-tpm2-tss/types"
require "./crystal-tpm2-tss/command"
require "./crystal-tpm2-tss/response"
require "./crystal-tpm2-tss/device"
require "./crystal-tpm2-tss/session"
require "./crystal-tpm2-tss/parameter_encryption"
require "./crystal-tpm2-tss/signature_r_tracker"
require "./crystal-tpm2-tss/kdf_key_manager"
require "./crystal-tpm2-tss/fido2_credential_manager"

# Top-level backwards compatibility aliases
alias TPM2 = Crystal::Tpm2::Tss::TPM2
alias TPMCommand = Crystal::Tpm2::Tss::TPMCommand
alias TPMResponse = Crystal::Tpm2::Tss::TPMResponse
alias TPMDevice = Crystal::Tpm2::Tss::TPMDevice
alias Session = Crystal::Tpm2::Tss::Session
alias KDFKeyManager = Crystal::Tpm2::Tss::KDFKeyManager
alias FIDO2CredentialManager = Crystal::Tpm2::Tss::FIDO2CredentialManager
alias FIDO2Credential = Crystal::Tpm2::Tss::FIDO2Credential
alias ECDSASignature = Crystal::Tpm2::Tss::ECDSASignature
alias SignatureRTracker = Crystal::Tpm2::Tss::SignatureRTracker
alias ParameterEncryption = Crystal::Tpm2::Tss::ParameterEncryption
alias TPMError = Crystal::Tpm2::Tss::TPMError
alias SecurityError = Crystal::Tpm2::Tss::SecurityError
