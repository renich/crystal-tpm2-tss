require "openssl/hmac"
require "sync/mutex"
require "crypto/subtle"

module Crystal::Tpm2::Tss
  class Session
    getter handle : UInt32
    getter type : UInt8
    getter hash_alg : UInt16
    getter attrs : UInt8
    getter nonce_tpm : Bytes
    getter session_key : Bytes
    getter nonce_caller : Bytes

    @mutex : Sync::Mutex

    def initialize(@handle : UInt32, @type : UInt8, @hash_alg : UInt16)
      @session_key = Bytes.empty
      @nonce_tpm = Bytes.empty
      @nonce_caller = Bytes.empty
      @attrs = TPM2::SessionAttributes::CONTINUESESSION
      @mutex = Sync::Mutex.new
    end

    def session_key=(val : Bytes)
      @mutex.synchronize { @session_key = val.dup }
    end

    def nonce_caller=(val : Bytes)
      @mutex.synchronize { @nonce_caller = val.dup }
    end

    def update_nonce_tpm(nonce : Bytes) : Nil
      @mutex.synchronize { @nonce_tpm = nonce.dup }
    end

    def compute_hmac(auth_value : Bytes, command_code : UInt32, params : Bytes) : Bytes
      @mutex.synchronize do
        hmac_key = build_hmac_key(auth_value)
        hash_alg_val = OpenSSL::Algorithm.parse(hash_alg_name)

        buffer = IO::Memory.new
        buffer.write(@nonce_caller)
        buffer.write(@nonce_tpm)
        buffer.write_byte(@attrs)
        buffer.write_bytes(command_code, TPM2::ENDIAN)
        buffer.write(params)

        OpenSSL::HMAC.digest(hash_alg_val, hmac_key, buffer.to_slice)
      end
    end

    def compute_response_hmac(auth_value : Bytes, response_code : UInt32, params : Bytes) : Bytes
      @mutex.synchronize do
        hmac_key = build_hmac_key(auth_value)
        hash_alg_val = OpenSSL::Algorithm.parse(hash_alg_name)

        buffer = IO::Memory.new
        buffer.write(@nonce_tpm)
        buffer.write(@nonce_caller)
        buffer.write_byte(@attrs)
        buffer.write_bytes(response_code, TPM2::ENDIAN)
        buffer.write(params)

        OpenSSL::HMAC.digest(hash_alg_val, hmac_key, buffer.to_slice)
      end
    end

    def verify_response_hmac(auth_value : Bytes, response_code : UInt32, params : Bytes, received_hmac : Bytes) : Bool
      expected = compute_response_hmac(auth_value, response_code, params)
      Crypto::Subtle.constant_time_compare(expected, received_hmac)
    end

    def roll_nonce : Bytes
      @mutex.synchronize do
        size = hash_output_size
        @nonce_caller = Random::Secure.random_bytes(size)
        @nonce_caller.dup
      end
    end

    def hash_alg_name : String
      case @hash_alg
      when TPM2::Algorithms::SHA256 then "SHA256"
      when TPM2::Algorithms::SHA384 then "SHA384"
      when TPM2::Algorithms::SHA512 then "SHA512"
      else                               "SHA256"
      end
    end

    def hash_output_size : Int32
      case @hash_alg
      when TPM2::Algorithms::SHA256 then 32
      when TPM2::Algorithms::SHA384 then 48
      when TPM2::Algorithms::SHA512 then 64
      else                               32
      end
    end

    private def build_hmac_key(auth_value : Bytes) : Bytes
      key = Bytes.new(@session_key.size + auth_value.size)
      @session_key.copy_to(key.to_unsafe, @session_key.size)
      auth_value.copy_to(key.to_unsafe + @session_key.size, auth_value.size)
      key
    end
  end
end
