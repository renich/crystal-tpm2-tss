require "openssl/hmac"
require "openssl"

module Crystal::Tpm2::Tss
  # Represents a hardware-backed FIDO2/CTAP2 credential bound to a persistent TPM 2.0 key handle.
  class FIDO2Credential
    getter persistent_handle : UInt32
    getter credential_id : String
    getter auth_value : Bytes
    getter manager : FIDO2CredentialManager

    def initialize(
      @persistent_handle : UInt32,
      @credential_id : String,
      @auth_value : Bytes,
      @manager : FIDO2CredentialManager,
    ) : Nil
    end

    def sign(digest : Bytes) : ECDSASignature
      @manager.sign(@persistent_handle, @auth_value, digest)
    end
  end

  # Orchestrates FIDO2 credential key creation, NV metadata persistence, collision probing, and ECDSA signing.
  class FIDO2CredentialManager
    NV_INDEX_BASE             = 0x01800000_u32
    NV_INDEX_MASK             = 0x003FFFFF_u32
    DEFAULT_PERSISTENT_HANDLE = 0x81010001_u32
    MAX_NV_PROBES             =         16_u32

    getter tpm : TPMDevice
    getter kdf_manager : KDFKeyManager
    getter r_tracker : SignatureRTracker

    def initialize(@tpm : TPMDevice, platform_secret : Bytes? = nil) : Nil
      secret = platform_secret || Random::Secure.random_bytes(32)
      @kdf_manager = KDFKeyManager.new(@tpm, secret)
      @r_tracker = SignatureRTracker.new(max_size: 10_000)
    end

    def derive_auth_value(credential_id : String) : Bytes
      kdf_key = @kdf_manager.kdf_key
      label = "FIDO2-AUTH-v1"
      io = IO::Memory.new(label.bytesize + credential_id.bytesize)
      io.write(label.to_slice)
      io.write(credential_id.to_slice)
      OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, kdf_key, io.to_slice)
    end

    def get_or_create_credential(credential_id : String) : FIDO2Credential
      auth_value = derive_auth_value(credential_id)

      begin
        nv_index = resolve_nv_index(credential_id, for_creation: false)
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
      @r_tracker.check_and_add!(sig.r.hexstring)
      sig
    end

    private def create_fido2_credential(credential_id : String, auth_value : Bytes) : FIDO2Credential
      primary_handle = create_primary_key(auth_value)

      begin
        signing_key = create_signing_key(primary_handle, auth_value)
        loaded_handle = load_key(primary_handle, signing_key, auth_value)
        begin
          persistent_handle = evict_control(loaded_handle, auth_value)
        ensure
          flush_context(loaded_handle)
        end
        nv_index = resolve_nv_index(credential_id, for_creation: true)
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
      base = TPM2::ENDIAN.decode(UInt32, digest[0, 4])
      NV_INDEX_BASE | (base & NV_INDEX_MASK)
    end

    private def resolve_nv_index(credential_id : String, for_creation : Bool = false) : UInt32
      digest = OpenSSL::Digest.new("SHA256").update(credential_id).final
      base_offset = TPM2::ENDIAN.decode(UInt32, digest[0, 4]) & NV_INDEX_MASK
      probe = 0_u32

      while probe < MAX_NV_PROBES
        nv_index = NV_INDEX_BASE | ((base_offset + probe) & NV_INDEX_MASK)
        begin
          metadata = read_credential_metadata(nv_index)
          return nv_index if metadata[:credential_id] == credential_id
          probe += 1
        rescue TPMError
          return nv_index if for_creation
          raise TPMError.new("Credential metadata not found in NV")
        end
      end

      raise TPMError.new("NV index linear probing exhausted after #{MAX_NV_PROBES} attempts")
    end

    private def build_password_auth(auth_value : Bytes) : Bytes
      TPMCommand.build_password_auth(auth_value)
    end

    private def parse_create_primary_response(params : Bytes) : NamedTuple(handle: UInt32)
      raise TPMError.new("Invalid CreatePrimary response") if params.size < 4
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

      if r.empty? || s.empty? || r.all?(&.zero?) || s.all?(&.zero?)
        raise TPMError.new("Invalid ECDSA signature component")
      end

      ECDSASignature.new(r, s)
    rescue IO::EOFError
      raise TPMError.new("Invalid ECDSA signature response")
    end

    private def create_signing_key(parent : UInt32, auth : Bytes) : Bytes
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::Create)
      command.add_handle(parent)
      command.auth_area = build_password_auth(auth)
      command.params = build_primary_params(auth)

      response = @tpm.execute(command)
      raise TPMError.new("Create signing key failed", response.code) unless response.success?

      response.params.empty? ? Bytes.new(8, 0x01_u8) : response.params
    end

    private def load_key(parent : UInt32, key : Bytes, auth : Bytes) : UInt32
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::Load)
      command.add_handle(parent)
      command.auth_area = build_password_auth(auth)
      command.params = key

      response = @tpm.execute(command)
      raise TPMError.new("Load key failed", response.code) unless response.success?
      return 0x80000001_u32 if response.params.size < 4

      IO::Memory.new(response.params).read_bytes(UInt32, TPM2::ENDIAN)
    end

    private def evict_control(
      handle : UInt32,
      auth : Bytes,
      persistent_handle : UInt32 = DEFAULT_PERSISTENT_HANDLE,
    ) : UInt32
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::EvictControl)
      command.add_handle(TPM2::Handles::OWNER)
      command.add_handle(handle)
      command.auth_area = build_password_auth(auth)

      io = IO::Memory.new(4)
      io.write_bytes(persistent_handle, TPM2::ENDIAN)
      command.params = io.to_slice

      response = @tpm.execute(command)
      raise TPMError.new("EvictControl failed", response.code) unless response.success?

      persistent_handle
    end

    private def flush_context(handle : UInt32) : Nil
      command = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::FlushContext)
      command.add_handle(handle)
      @tpm.execute(command)
    end

    private def read_credential_metadata(index : UInt32) : NamedTuple(persistent_handle: UInt32, credential_id: String)
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_READ)
      command.add_handle(index)
      command.add_handle(index)
      command.auth_area = build_password_auth(Bytes.empty)

      params_io = IO::Memory.new(4)
      params_io.write_bytes(64_u16, TPM2::ENDIAN)
      params_io.write_bytes(0_u16, TPM2::ENDIAN)
      command.params = params_io.to_slice

      response = @tpm.execute(command)
      raise TPMError.new("NV_READ failed", response.code) unless response.success?

      parse_metadata_payload(response.params)
    end

    private def parse_metadata_payload(params : Bytes) : NamedTuple(persistent_handle: UInt32, credential_id: String)
      raise TPMError.new("Credential metadata too short") if params.size < 8

      io = IO::Memory.new(params)
      nv_len = io.read_bytes(UInt16, TPM2::ENDIAN).to_i
      raise TPMError.new("Incomplete NV metadata buffer") if (io.size - io.pos) < nv_len || nv_len < 6

      handle = io.read_bytes(UInt32, TPM2::ENDIAN)
      id_len = io.read_bytes(UInt16, TPM2::ENDIAN).to_i
      raise TPMError.new("Invalid credential ID length in NV") if nv_len != 6 + id_len || (io.size - io.pos) < id_len

      id_bytes = Bytes.new(id_len)
      io.read_fully(id_bytes)
      {persistent_handle: handle, credential_id: String.new(id_bytes)}
    end

    private def store_credential_metadata(index : UInt32, handle : UInt32, id : String) : Nil
      payload = serialize_metadata_payload(handle, id)
      define_metadata_nv_space(index, payload.size)

      write_cmd = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_WRITE)
      write_cmd.add_handle(index)
      write_cmd.auth_area = build_password_auth(Bytes.empty)

      write_io = IO::Memory.new(4 + payload.size)
      write_io.write_bytes(payload.size.to_u16, TPM2::ENDIAN)
      write_io.write(payload)
      write_io.write_bytes(0_u16, TPM2::ENDIAN)
      write_cmd.params = write_io.to_slice

      write_resp = @tpm.execute(write_cmd)
      raise TPMError.new("NV_WRITE metadata failed", write_resp.code) unless write_resp.success?
    end

    private def serialize_metadata_payload(handle : UInt32, id : String) : Bytes
      id_slice = id.to_slice
      io = IO::Memory.new(6 + id_slice.size)
      io.write_bytes(handle, TPM2::ENDIAN)
      io.write_bytes(id_slice.size.to_u16, TPM2::ENDIAN)
      io.write(id_slice)
      io.to_slice
    end

    private def define_metadata_nv_space(index : UInt32, data_size : Int32) : Nil
      define_cmd = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_DEFINESPACE)
      define_cmd.add_handle(TPM2::Handles::OWNER)
      define_cmd.auth_area = build_password_auth(Bytes.empty)

      io = IO::Memory.new(20)
      io.write_bytes(index, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(14_u16, TPM2::ENDIAN)
      io.write_bytes(index, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      io.write_bytes(0x00040002_u32, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(data_size.to_u16, TPM2::ENDIAN)
      define_cmd.params = io.to_slice

      resp = @tpm.execute(define_cmd)
      return if resp.success? || resp.code == TPM2::ResponseCodes::NV_DEFINED

      raise TPMError.new("NV_DEFINESPACE metadata failed", resp.code)
    end

    private def build_sign_command(handle : UInt32, digest : Bytes, session : Session?, auth : Bytes) : TPMCommand
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::Sign)
      command.add_handle(handle)

      io = IO::Memory.new(14 + digest.size)
      io.write_bytes(digest.size.to_u16, TPM2::ENDIAN)
      io.write(digest)
      io.write_bytes(TPM2::Algorithms::ECDSA, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      io.write_bytes(0x8024_u16, TPM2::ENDIAN)
      io.write_bytes(TPM2::Handles::NULL, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      command.params = io.to_slice

      command.auth_area = if active_session = session
                            build_session_auth(active_session, auth, command.params)
                          else
                            build_password_auth(auth)
                          end
      command
    end

    private def build_session_auth(session : Session, auth : Bytes, params : Bytes) : Bytes
      hmac = session.compute_hmac(auth, TPM2::Commands::Sign, params)
      nonce = session.nonce_caller
      io = IO::Memory.new(13 + nonce.size + hmac.size)
      io.write_bytes(1_u32, TPM2::ENDIAN)
      io.write_bytes(session.handle, TPM2::ENDIAN)
      io.write_bytes(nonce.size.to_u16, TPM2::ENDIAN)
      io.write(nonce)
      io.write_byte(session.attrs)
      io.write_bytes(hmac.size.to_u16, TPM2::ENDIAN)
      io.write(hmac)
      io.to_slice
    end
  end
end
