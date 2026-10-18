require "openssl"
require "openssl/hmac"
require "sync/mutex"
require "crypto/subtle"

module Crystal::Tpm2::Tss
  # Manages a TPM 2.0 authorization session with thread-safe nonce rolling, `cpHash`/`rpHash`, and HMAC verification.
  class Session
    # Session handle (`TPM_SH`) returned by `TPM2_StartAuthSession`.
    getter handle : UInt32

    # Session type (`TPM_SE_HMAC`, `TPM_SE_POLICY`, or `TPM_SE_TRIAL`).
    getter type : UInt8

    # Session hash algorithm identifier (`TPM2::Algorithms::SHA256`, `SHA384`, or `SHA512`).
    getter hash_alg : UInt16

    # Session attribute bitmask (`TPMA_SESSION`).
    getter attrs : UInt8

    @nonce_tpm : Bytes
    @session_key : Bytes
    @nonce_caller : Bytes
    @mutex : Sync::Mutex

    # Initializes a new `Session` with `CONTINUESESSION` enabled by default.
    def initialize(@handle : UInt32, @type : UInt8, @hash_alg : UInt16) : Nil
      @session_key = Bytes.empty
      @nonce_tpm = Bytes.empty
      @nonce_caller = Bytes.empty
      @attrs = TPM2::SessionAttributes::CONTINUESESSION
      @mutex = Sync::Mutex.new
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

    # Computes the TCG TPM 2.0 Part 1 §19.6.5 command parameter hash (`cpHash`).
    def compute_cp_hash(
      command_code : UInt32,
      params : Bytes,
      handles : Array(UInt32) = Array(UInt32).new,
    ) : Bytes
      io = IO::Memory.new(4 + (handles.size * 4) + params.size)
      io.write_bytes(command_code, TPM2::ENDIAN)
      handles.each do |handle|
        io.write_bytes(handle, TPM2::ENDIAN)
      end
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
        compute_directional_hmac(auth_value, @nonce_caller, @nonce_tpm, command_code, params)
      end
    end

    # Computes the response authorization HMAC over `(nonceTPM, nonceCaller, attrs, response_code, params)`.
    def compute_response_hmac(auth_value : Bytes, response_code : UInt32, params : Bytes) : Bytes
      @mutex.synchronize do
        compute_directional_hmac(auth_value, @nonce_tpm, @nonce_caller, response_code, params)
      end
    end

    # Verifies a response authorization HMAC in constant time using `Crypto::Subtle.constant_time_compare`.
    def verify_response_hmac(auth_value : Bytes, response_code : UInt32, params : Bytes, received_hmac : Bytes) : Bool
      expected = compute_response_hmac(auth_value, response_code, params)
      Crypto::Subtle.constant_time_compare(expected, received_hmac)
    end

    # Generates and stores a fresh cryptographically random `nonceCaller` matching the session hash length.
    def roll_nonce : Bytes
      @mutex.synchronize do
        size = hash_output_size
        @nonce_caller = Random::Secure.random_bytes(size)
        @nonce_caller.dup
      end
    end

    # Returns the OpenSSL digest algorithm name corresponding to `@hash_alg`.
    def hash_alg_name : String
      case @hash_alg
      when TPM2::Algorithms::SHA256 then "SHA256"
      when TPM2::Algorithms::SHA384 then "SHA384"
      when TPM2::Algorithms::SHA512 then "SHA512"
      else
        raise ArgumentError.new("Unsupported TPM hash algorithm: 0x#{@hash_alg.to_s(16)}")
      end
    end

    # Returns the digest output byte length for `@hash_alg`.
    def hash_output_size : Int32
      case @hash_alg
      when TPM2::Algorithms::SHA256 then 32
      when TPM2::Algorithms::SHA384 then 48
      when TPM2::Algorithms::SHA512 then 64
      else
        raise ArgumentError.new("Unsupported TPM hash algorithm: 0x#{@hash_alg.to_s(16)}")
      end
    end

    private def compute_directional_hmac(
      auth_value : Bytes,
      first_nonce : Bytes,
      second_nonce : Bytes,
      code : UInt32,
      params : Bytes,
    ) : Bytes
      hmac_key = build_hmac_key(auth_value)
      hash_alg_val = OpenSSL::Algorithm.parse(hash_alg_name)

      buffer = IO::Memory.new
      buffer.write(first_nonce)
      buffer.write(second_nonce)
      buffer.write_byte(@attrs)
      buffer.write_bytes(code, TPM2::ENDIAN)
      buffer.write(params)

      OpenSSL::HMAC.digest(hash_alg_val, hmac_key, buffer.to_slice)
    end

    private def build_hmac_key(auth_value : Bytes) : Bytes
      key = Bytes.new(@session_key.size + auth_value.size)
      @session_key.copy_to(key.to_unsafe, @session_key.size)
      auth_value.copy_to(key.to_unsafe + @session_key.size, auth_value.size)
      key
    end
  end
end
