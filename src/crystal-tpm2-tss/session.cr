require "openssl"
require "openssl/hmac"
require "sync/mutex"
require "crypto/subtle"

module Crystal::Tpm2::Tss
  # Manages a TPM 2.0 authorization session with thread-safe nonce rolling, `cpHash`/`rpHash`, and `PolicyPCR`.
  class Session
    # Session handle (`TPM_SH`), type (`TPM_SE`), hash algorithm (`TPM_ALG_ID`), and attributes (`TPMA_SESSION`).
    getter handle : UInt32, type : UInt8, hash_alg : UInt16, attrs : UInt8 = TPM2::SessionAttributes::CONTINUESESSION

    @nonce_tpm : Bytes = Bytes.empty
    @session_key : Bytes = Bytes.empty
    @nonce_caller : Bytes = Bytes.empty
    @last_auth_value : Bytes = Bytes.empty
    @policy_digest : Bytes = Bytes.new(32, 0_u8)
    @flushed : Bool = false
    @mutex : Sync::Mutex = Sync::Mutex.new

    # Initializes a new `Session` with `CONTINUESESSION` enabled by default.
    def initialize(@handle : UInt32, @type : UInt8, @hash_alg : UInt16) : Nil
    end

    # Establishes a hardware or simulated session via `TPM2_StartAuthSession` with KDFa session key derivation.
    def self.start_auth_session(
      device : TPMDevice, session_type : UInt8 = 0x00_u8,
      auth_value : Bytes = Bytes.empty, salt : Bytes = Bytes.empty, bind_key : Bytes = Bytes.empty,
    ) : self
      nonce_caller = Random::Secure.random_bytes(32)
      resp = device.execute(build_start_auth_command(nonce_caller, salt, session_type))
      raise TPMError.new("StartAuthSession failed", resp.code) unless resp.success?
      handle, nonce_tpm = parse_start_auth_response(resp.params)
      session = new(handle, session_type, TPM2::Algorithms::SHA256)
      session.nonce_caller = nonce_caller
      session.update_nonce_tpm(nonce_tpm)
      unless auth_value.empty? && bind_key.empty?
        seed = IO::Memory.new(auth_value.size + bind_key.size)
        seed.write(auth_value)
        seed.write(bind_key)
        session.session_key = ParameterEncryption.kdfa("SHA256", seed.to_slice, "ATH", nonce_tpm, nonce_caller, 256)
      end
      session
    end

    # Returns a copy of the latest TPM-generated nonce (`nonceTPM`).
    def nonce_tpm : Bytes
      @mutex.synchronize { @nonce_tpm.dup }
    end

    # Returns a copy of the session HMAC/encryption key (`sessionKey`).
    def session_key : Bytes
      @mutex.synchronize { @session_key.dup }
    end

    # Returns a copy of the latest caller-generated nonce (`nonceCaller`).
    def nonce_caller : Bytes
      @mutex.synchronize { @nonce_caller.dup }
    end

    # Returns a copy of the most recent command authorization value (`authValue`).
    def last_auth_value : Bytes
      @mutex.synchronize { @last_auth_value.dup }
    end

    # Returns a copy of the current 32-byte `PolicyPCR` digest.
    def policy_digest : Bytes
      @mutex.synchronize { @policy_digest.dup }
    end

    # Returns `true` if this session has been terminated via `TPM2_FlushContext`.
    def flushed? : Bool
      @mutex.synchronize { @flushed }
    end

    # Sets the session HMAC/encryption key in a thread-safe manner.
    def session_key=(val : Bytes) : Bytes
      @mutex.synchronize { @session_key = val.dup }
    end

    # Sets the caller nonce (`nonceCaller`) in a thread-safe manner.
    def nonce_caller=(val : Bytes) : Bytes
      @mutex.synchronize { @nonce_caller = val.dup }
    end

    # Updates the TPM nonce (`nonceTPM`) extracted from a response authorization area.
    def update_nonce_tpm(nonce : Bytes) : Nil
      @mutex.synchronize { @nonce_tpm = nonce.dup }
    end

    # Executes `TPM2_PolicyPCR` to extend `@policy_digest` with `pcr_index` and `pcr_digest`.
    def policy_pcr(device : TPMDevice, pcr_index : UInt32, pcr_digest : Bytes) : Bytes
      raise TPMError.new("Session is already flushed") if flushed?
      raise TPMError.new("PCR digest cannot be empty") if pcr_digest.empty?
      cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::PolicyPCR)
      cmd.add_handle(@handle)
      io = IO::Memory.new(6 + pcr_digest.size)
      Tpm2bCodec.write_tpm2b(io, pcr_digest)
      io.write_bytes(pcr_index, TPM2::ENDIAN)
      cmd.params = io.to_slice
      resp = device.execute(cmd)
      raise TPMError.new("PolicyPCR failed", resp.code) unless resp.success?
      extend_policy_digest(pcr_index, pcr_digest)
    end

    # Terminates the session on `device` via `TPM2_FlushContext` and marks it flushed.
    def flush(device : TPMDevice) : Nil
      cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::FlushContext)
      cmd.add_handle(@handle)
      resp = device.execute(cmd)
      raise TPMError.new("FlushContext failed", resp.code) unless resp.success?
      @mutex.synchronize { @flushed = true }
    end

    # Computes the TCG TPM 2.0 Part 1 §19.6.5 command parameter hash (`cpHash`).
    def compute_cp_hash(command_code : UInt32, params : Bytes, handles : Array(UInt32) = Array(UInt32).new) : Bytes
      io = IO::Memory.new(4 + (handles.size * 4) + params.size)
      io.write_bytes(command_code, TPM2::ENDIAN)
      handles.each { |handle| io.write_bytes(handle, TPM2::ENDIAN) }
      io.write(params)
      OpenSSL::Digest.new(hash_alg_name).update(io.to_slice).final
    end

    # Computes the TCG TPM 2.0 Part 1 §19.6.5 response parameter hash (`rpHash`).
    def compute_rp_hash(response_code : UInt32, command_code : UInt32, params : Bytes) : Bytes
      io = IO::Memory.new(8 + params.size)
      io.write_bytes(response_code, TPM2::ENDIAN)
      io.write_bytes(command_code, TPM2::ENDIAN)
      io.write(params)
      OpenSSL::Digest.new(hash_alg_name).update(io.to_slice).final
    end

    # Computes the command authorization HMAC over `(nonceCaller, nonceTPM, attrs, command_code, params)`.
    def compute_hmac(auth_value : Bytes, command_code : UInt32, params : Bytes) : Bytes
      @mutex.synchronize do
        @last_auth_value = auth_value.dup
        compute_directional_hmac(auth_value, @nonce_caller, @nonce_tpm, command_code, params)
      end
    end

    # Computes the response authorization HMAC over `(nonceTPM, nonceCaller, attrs, response_code, params)`.
    def compute_response_hmac(auth_value : Bytes, response_code : UInt32, params : Bytes) : Bytes
      @mutex.synchronize { compute_directional_hmac(auth_value, @nonce_tpm, @nonce_caller, response_code, params) }
    end

    # Verifies a response authorization HMAC in constant time using `Crypto::Subtle.constant_time_compare`.
    def verify_response_hmac(auth_value : Bytes, response_code : UInt32, params : Bytes, received_hmac : Bytes) : Bool
      expected = compute_response_hmac(auth_value, response_code, params)
      Crypto::Subtle.constant_time_compare(expected, received_hmac)
    end

    # Generates and stores a fresh cryptographically random `nonceCaller` matching the session hash length.
    def roll_nonce : Bytes
      @mutex.synchronize { (@nonce_caller = Random::Secure.random_bytes(hash_output_size)).dup }
    end

    # Returns the OpenSSL digest algorithm name corresponding to `@hash_alg`.
    def hash_alg_name : String
      hash_info[0]
    end

    # Returns the digest output byte length for `@hash_alg`.
    def hash_output_size : Int32
      hash_info[1]
    end

    private def hash_info : Tuple(String, Int32)
      case @hash_alg
      when TPM2::Algorithms::SHA256 then {"SHA256", 32}
      when TPM2::Algorithms::SHA384 then {"SHA384", 48}
      when TPM2::Algorithms::SHA512 then {"SHA512", 64}
      else
        raise ArgumentError.new("Unsupported TPM hash algorithm: 0x#{@hash_alg.to_s(16)}")
      end
    end

    private def self.build_start_auth_command(nonce_caller : Bytes, salt : Bytes, session_type : UInt8) : TPMCommand
      cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::StartAuthSession)
      cmd.add_handle(TPM2::Handles::NULL)
      cmd.add_handle(TPM2::Handles::NULL)
      io = IO::Memory.new(9 + nonce_caller.size + salt.size)
      Tpm2bCodec.write_tpm2b(io, nonce_caller)
      Tpm2bCodec.write_tpm2b(io, salt)
      io.write_byte(session_type)
      io.write_bytes(TPM2::Algorithms::NULL, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      cmd.params = io.to_slice
      cmd
    end

    private def self.parse_start_auth_response(params : Bytes) : Tuple(UInt32, Bytes)
      raise TPMError.new("StartAuthSession response too short") if params.size < 6
      io = IO::Memory.new(params)
      {io.read_bytes(UInt32, TPM2::ENDIAN), Tpm2bCodec.read_tpm2b(io)}
    end

    private def extend_policy_digest(pcr_index : UInt32, pcr_digest : Bytes) : Bytes
      @mutex.synchronize do
        io = IO::Memory.new(@policy_digest.size + 8 + pcr_digest.size)
        io.write(@policy_digest)
        io.write_bytes(TPM2::Commands::PolicyPCR, TPM2::ENDIAN)
        io.write_bytes(pcr_index, TPM2::ENDIAN)
        io.write(pcr_digest)
        (@policy_digest = OpenSSL::Digest.new(hash_alg_name).update(io.to_slice).final).dup
      end
    end

    private def compute_directional_hmac(auth : Bytes, n1 : Bytes, n2 : Bytes, code : UInt32, params : Bytes) : Bytes
      key = IO::Memory.new(@session_key.size + auth.size)
      key.write(@session_key)
      key.write(auth)
      buf = IO::Memory.new(n1.size + n2.size + 5 + params.size)
      buf.write(n1)
      buf.write(n2)
      buf.write_byte(@attrs)
      buf.write_bytes(code, TPM2::ENDIAN)
      buf.write(params)
      OpenSSL::HMAC.digest(OpenSSL::Algorithm.parse(hash_alg_name), key.to_slice, buf.to_slice)
    end
  end
end
