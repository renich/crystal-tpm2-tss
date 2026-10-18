module Crystal::Tpm2::Tss
  # Hardware-backed FIDO2/CTAP2 credential bound to a persistent TPM 2.0 NIST P-256 key handle.
  class FIDO2Credential
    # Persistent TPM 2.0 object handle (`0x8101xxxx`) storing the credential signing key.
    getter persistent_handle : UInt32

    # Relying party credential identifier string.
    getter credential_id : String

    # 32-byte HMAC-SHA256 authorization value derived from the hardware KDF key.
    getter auth_value : Bytes

    # 32-byte affine `x` coordinate of the credential's NIST P-256 public key.
    getter public_key_x : Bytes

    # 32-byte affine `y` coordinate of the credential's NIST P-256 public key.
    getter public_key_y : Bytes

    # Owning `FIDO2CredentialManager` instance coordinating TPM command execution.
    getter manager : FIDO2CredentialManager

    # Initializes a `FIDO2Credential` with its persistent handle, auth value, and public key coordinates.
    def initialize(
      @persistent_handle : UInt32,
      @credential_id : String,
      @auth_value : Bytes,
      @manager : FIDO2CredentialManager,
      @public_key_x : Bytes = Bytes.empty,
      @public_key_y : Bytes = Bytes.empty,
    ) : Nil
      return unless @public_key_x.empty? || @public_key_y.empty?
      @public_key_x, @public_key_y = @manager.read_public_key(@persistent_handle)
    end

    # Returns the 32-byte `(x, y)` affine coordinates of the NIST P-256 public key.
    def public_key_xy : Tuple(Bytes, Bytes)
      {@public_key_x, @public_key_y}
    end

    # Signs a 32-byte digest using the TPM-resident NIST P-256 signing key.
    def sign(digest : Bytes) : ECDSASignature
      @manager.sign(@persistent_handle, @auth_value, digest)
    end

    # Verifies an `ECDSASignature` against `digest` using this credential's NIST P-256 public key.
    def verify(digest : Bytes, signature : ECDSASignature) : Bool
      P256Key.verify_public_key(@public_key_x, @public_key_y, digest, signature)
    end
  end
end
