require "openssl/hmac"
require "openssl"

module Crystal::Tpm2::Tss
  # Orchestrates FIDO2 credential key creation, NV metadata persistence, public key inspection, and ECDSA signing.
  class FIDO2CredentialManager
    # Disjoint NV index base address (`0x01800000`) reserved for FIDO2 credential metadata.
    NV_INDEX_BASE = NVMetadataStore::NV_INDEX_BASE
    # 22-bit offset mask (`0x003FFFFF`) bounding credential NV indices below `0x01C00000`.
    NV_INDEX_MASK = NVMetadataStore::NV_INDEX_MASK
    # Base persistent object handle prefix (`0x81010000`) for FIDO2 signing keys.
    PERSISTENT_HANDLE_BASE = 0x81010000_u32
    # Fallback persistent object handle (`0x81010001`).
    DEFAULT_PERSISTENT_HANDLE = 0x81010001_u32
    # Maximum linear probe attempts when resolving NV index hash collisions.
    MAX_NV_PROBES = NVMetadataStore::MAX_NV_PROBES

    # Underlying `TPMDevice` interface.
    getter tpm : TPMDevice
    # Hardware-backed KDF master key manager.
    getter kdf_manager : KDFKeyManager
    # Bounded O(1) ECDSA `r`-component nonce reuse detector.
    getter r_tracker : SignatureRTracker
    # TPM NV metadata persistence store with collision probing.
    getter nv_store : NVMetadataStore

    # Initializes a new `FIDO2CredentialManager` bound to `tpm` and an optional `platform_secret`.
    def initialize(@tpm : TPMDevice, platform_secret : Bytes? = nil) : Nil
      secret = platform_secret || Random::Secure.random_bytes(32)
      @kdf_manager = KDFKeyManager.new(@tpm, secret)
      @r_tracker = SignatureRTracker.new(max_size: 10_000)
      @nv_store = NVMetadataStore.new(@tpm)
    end

    # Derives a domain-separated 32-byte HMAC-SHA256 authorization value for `credential_id`.
    def derive_auth_value(credential_id : String) : Bytes
      kdf_key = @kdf_manager.kdf_key
      label = "FIDO2-AUTH-v1"
      io = IO::Memory.new(label.bytesize + credential_id.bytesize)
      io.write(label.to_slice)
      io.write(credential_id.to_slice)
      OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, kdf_key, io.to_slice)
    end

    # Derives a credential-specific persistent handle (`0x81010001..0x8101FFFF`) from `credential_id`.
    def derive_persistent_handle(credential_id : String) : UInt32
      digest = OpenSSL::Digest.new("SHA256").update(credential_id).final
      hash_u16 = TPM2::ENDIAN.decode(UInt16, digest[0, 2])
      PERSISTENT_HANDLE_BASE | (hash_u16 == 0_u16 ? 1_u32 : hash_u16.to_u32)
    end

    # Retrieves an existing FIDO2 credential from TPM NV metadata or provisions a new persistent keypair.
    def get_or_create_credential(credential_id : String) : FIDO2Credential
      auth_value = derive_auth_value(credential_id)
      nv_index = @nv_store.resolve_nv_index(credential_id, for_creation: false)
      metadata = @nv_store.read_credential_metadata(nv_index)
      pub_x, pub_y = read_public_key(metadata[:persistent_handle])
      FIDO2Credential.new(metadata[:persistent_handle], credential_id, auth_value, self, pub_x, pub_y)
    rescue TPMError
      create_fido2_credential(credential_id, auth_value || derive_auth_value(credential_id))
    end

    # Executes `TPM2_ReadPublic` on `persistent_handle` to extract 32-byte `(x, y)` NIST P-256 coordinates.
    def read_public_key(persistent_handle : UInt32) : Tuple(Bytes, Bytes)
      command = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::ReadPublic)
      command.add_handle(persistent_handle)
      response = @tpm.execute(command)
      raise TPMError.new("ReadPublic failed", response.code) unless response.success?
      TPMResponse.parse_read_public_xy(response.params)
    end

    # Signs `digest` using `key_handle` and verifies that the ECDSA `r` nonce has never been reused.
    def sign(key_handle : UInt32, auth_value : Bytes, digest : Bytes, session : Session? = nil) : ECDSASignature
      command = build_sign_command(key_handle, digest, session, auth_value)
      response = @tpm.execute(command, session)
      raise TPMError.new("Sign failed", response.code) unless response.success?
      sig = TPMResponse.parse_ecdsa_signature(response.params)
      @r_tracker.check_and_add!(sig.r.hexstring)
      sig
    end

    private def create_fido2_credential(credential_id : String, auth_value : Bytes) : FIDO2Credential
      primary_handle = create_primary_key(auth_value)
      target_handle = derive_persistent_handle(credential_id)
      begin
        loaded_handle = load_key(primary_handle, create_signing_key(primary_handle, auth_value), auth_value)
        begin
          persistent_handle = evict_control(loaded_handle, auth_value, target_handle)
        ensure
          flush_context(loaded_handle)
        end
        nv_index = @nv_store.resolve_nv_index(credential_id, for_creation: true)
        @nv_store.store_credential_metadata(nv_index, persistent_handle, credential_id)
        pub_x, pub_y = read_public_key(persistent_handle)
        FIDO2Credential.new(persistent_handle, credential_id, auth_value, self, pub_x, pub_y)
      ensure
        flush_context(primary_handle)
      end
    end

    private def create_primary_key(auth_value : Bytes) : UInt32
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::CreatePrimary)
      command.add_handle(TPM2::Handles::OWNER)
      command.auth_area = TPMCommand.build_password_auth(auth_value)
      command.params = TPMCommand.build_ecc_p256_create_params(auth_value)
      response = @tpm.execute(command)
      raise TPMError.new("CreatePrimary failed", response.code) unless response.success?
      raise TPMError.new("Invalid CreatePrimary response") if response.params.size < 4
      IO::Memory.new(response.params).read_bytes(UInt32, TPM2::ENDIAN)
    end

    private def create_signing_key(parent : UInt32, auth : Bytes) : Bytes
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::Create)
      command.add_handle(parent)
      command.auth_area = TPMCommand.build_password_auth(auth)
      command.params = TPMCommand.build_ecc_p256_create_params(auth)
      response = @tpm.execute(command)
      raise TPMError.new("Create signing key failed", response.code) unless response.success?
      response.params.empty? ? Bytes.new(8, 0x01_u8) : response.params
    end

    private def load_key(parent : UInt32, key : Bytes, auth : Bytes) : UInt32
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::Load)
      command.add_handle(parent)
      command.auth_area = TPMCommand.build_password_auth(auth)
      command.params = key
      response = @tpm.execute(command)
      raise TPMError.new("Load key failed", response.code) unless response.success?
      response.params.size < 4 ? 0x80000001_u32 : IO::Memory.new(response.params).read_bytes(UInt32, TPM2::ENDIAN)
    end

    private def evict_control(handle : UInt32, auth : Bytes, target : UInt32 = DEFAULT_PERSISTENT_HANDLE) : UInt32
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::EvictControl)
      command.add_handle(TPM2::Handles::OWNER)
      command.add_handle(handle)
      command.auth_area = TPMCommand.build_password_auth(auth)
      io = IO::Memory.new(4)
      io.write_bytes(target, TPM2::ENDIAN)
      command.params = io.to_slice
      response = @tpm.execute(command)
      raise TPMError.new("EvictControl failed", response.code) unless response.success?
      target
    end

    private def flush_context(handle : UInt32) : Nil
      command = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::FlushContext)
      command.add_handle(handle)
      @tpm.execute(command)
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
      command.auth_area = if active = session
                            TPMCommand.build_session_auth(active, auth, TPM2::Commands::Sign, command.params)
                          else
                            TPMCommand.build_password_auth(auth)
                          end
      command
    end
  end
end
