require "openssl/hmac"
require "openssl"

module Crystal::Tpm2::Tss
  class FIDO2Credential
    getter persistent_handle : UInt32
    getter credential_id : String
    getter auth_value : Bytes
    getter manager : FIDO2CredentialManager

    def initialize(@persistent_handle : UInt32, @credential_id : String, @auth_value : Bytes, @manager : FIDO2CredentialManager)
    end

    def sign(digest : Bytes) : ECDSASignature
      @manager.sign(@persistent_handle, @auth_value, digest)
    end
  end

  class FIDO2CredentialManager
    getter tpm : TPMDevice
    getter kdf_manager : KDFKeyManager
    getter r_tracker : SignatureRTracker

    def initialize(@tpm : TPMDevice, platform_secret : Bytes? = nil)
      secret = platform_secret || Random::Secure.random_bytes(32)
      @kdf_manager = KDFKeyManager.new(@tpm, secret)
      @r_tracker = SignatureRTracker.new(max_size: 10_000)
    end

    def derive_auth_value(credential_id : String) : Bytes
      kdf_key = @kdf_manager.kdf_key
      label = "FIDO2-AUTH-v1"
      context = credential_id.to_slice
      OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, kdf_key, label.to_slice + context)
    end

    def get_or_create_credential(credential_id : String) : FIDO2Credential
      nv_index = credential_id_to_nv_index(credential_id)
      auth_value = derive_auth_value(credential_id)

      begin
        metadata = read_credential_metadata(nv_index)
        FIDO2Credential.new(
          persistent_handle: metadata[:persistent_handle],
          credential_id: credential_id,
          auth_value: auth_value,
          manager: self
        )
      rescue TPMError
        create_fido2_credential(credential_id, auth_value)
      end
    end

    def sign(
      key_handle : UInt32,
      auth_value : Bytes,
      digest : Bytes,
      session : Session? = nil,
    ) : ECDSASignature
      command = build_sign_command(key_handle, digest, session, auth_value)
      response = @tpm.execute(command, session)

      unless response.success?
        raise TPMError.new("Sign failed", response.code)
      end

      sig = parse_ecdsa_signature(response.params)
      r_hex = sig.r.hexstring
      if @r_tracker.includes?(r_hex)
        raise SecurityError.new("ECDSA nonce reuse detected!")
      end
      @r_tracker.add(r_hex)

      sig
    end

    private def create_fido2_credential(credential_id : String, auth_value : Bytes) : FIDO2Credential
      primary_handle = create_primary_key(auth_value)

      begin
        signing_key = create_signing_key(primary_handle, auth_value)
        loaded_handle = load_key(primary_handle, signing_key, auth_value)
        persistent_handle = evict_control(loaded_handle, auth_value)
        nv_index = credential_id_to_nv_index(credential_id)
        store_credential_metadata(nv_index, persistent_handle, credential_id)

        FIDO2Credential.new(
          persistent_handle: persistent_handle,
          credential_id: credential_id,
          auth_value: auth_value,
          manager: self
        )
      ensure
        flush_context(primary_handle)
      end
    end

    private def create_primary_key(auth_value : Bytes) : UInt32
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::CreatePrimary)
      command.add_handle(TPM2::Handles::OWNER)
      command.auth_area = build_password_auth(auth_value)
      command.params = build_primary_params(auth_value)

      response = @tpm.execute(command)
      unless response.success?
        raise TPMError.new("CreatePrimary failed", response.code)
      end

      parse_create_primary_response(response.params)[:handle]
    end

    private def build_primary_params(auth_value : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
      io.write(auth_value)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)

      io.write_bytes(TPM2::Algorithms::ECC, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      io.write_bytes(
        TPM2::ObjectAttributes::USER_WITH_AUTH |
        TPM2::ObjectAttributes::SIGN_ENCRYPT |
        TPM2::ObjectAttributes::FIXEDTPM |
        TPM2::ObjectAttributes::FIXEDPARENT |
        TPM2::ObjectAttributes::SENSITIVEDATAORIGIN,
        TPM2::ENDIAN
      )
      io.write_bytes(0_u16, TPM2::ENDIAN)

      io.write_bytes(TPM2::ECCCurves::NIST_P256, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::NULL, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::ECDSA, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(0_u32, TPM2::ENDIAN)

      io.to_slice
    end

    private def credential_id_to_nv_index(credential_id : String) : UInt32
      digest = OpenSSL::Digest.new("SHA256").update(credential_id).final
      base = IO::Memory.new(digest[0..3]).read_bytes(UInt32, TPM2::ENDIAN)
      0x01000000_u32 | (base & 0x00FFFFFF)
    end

    private def build_password_auth(auth_value : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(1_u32, TPM2::ENDIAN)
      io.write_bytes(TPM2::Handles::PW, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_byte(TPM2::SessionAttributes::CONTINUESESSION)
      io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
      io.write(auth_value)
      io.to_slice
    end

    private def parse_create_primary_response(params : Bytes) : NamedTuple(handle: UInt32)
      io = IO::Memory.new(params)
      handle = io.read_bytes(UInt32, TPM2::ENDIAN)
      {handle: handle}
    end

    private def parse_ecdsa_signature(params : Bytes) : ECDSASignature
      io = IO::Memory.new(params)
      _sig_alg = io.read_bytes(UInt16, TPM2::ENDIAN)
      _hash_alg = io.read_bytes(UInt16, TPM2::ENDIAN)

      r_len = io.read_bytes(UInt16, TPM2::ENDIAN)
      r = Bytes.new(r_len.to_i)
      io.read_fully(r)

      s_len = io.read_bytes(UInt16, TPM2::ENDIAN)
      s = Bytes.new(s_len.to_i)
      io.read_fully(s)

      ECDSASignature.new(r, s)
    end

    private def create_signing_key(parent : UInt32, auth : Bytes) : Bytes
      Bytes.empty
    end

    private def load_key(parent : UInt32, key : Bytes, auth : Bytes) : UInt32
      0_u32
    end

    private def evict_control(handle : UInt32, auth : Bytes) : UInt32
      0_u32
    end

    private def flush_context(handle : UInt32) : Nil
    end

    private def read_credential_metadata(index : UInt32) : NamedTuple(persistent_handle: UInt32)
      {persistent_handle: 0_u32}
    end

    private def store_credential_metadata(index : UInt32, handle : UInt32, id : String) : Nil
    end

    private def build_sign_command(handle : UInt32, digest : Bytes, session : Session?, auth : Bytes) : TPMCommand
      TPMCommand.new(0_u16, 0_u32)
    end
  end
end
