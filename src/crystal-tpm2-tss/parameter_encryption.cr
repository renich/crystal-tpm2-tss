require "openssl/cipher"
require "openssl/hmac"

module Crystal::Tpm2::Tss
  # Implements TCG TPM 2.0 Part 1 KDFa counter-mode key derivation and session parameter encryption.
  module ParameterEncryption
    def self.kdfa(
      hash_alg : String,
      key : Bytes,
      label : String,
      context_u : Bytes,
      context_v : Bytes,
      bits : Int32,
    ) : Bytes
      return Bytes.empty if bits <= 0
      bytes_needed = ((bits.to_i64 + 7) // 8).to_i32

      hash_alg_val = OpenSSL::Algorithm.parse(hash_alg)
      result = IO::Memory.new(bytes_needed)
      buf = IO::Memory.new
      counter = 1_u32

      while result.size < bytes_needed
        buf.clear
        IO::ByteFormat::BigEndian.encode(counter, buf)
        buf.write(label.to_slice)
        buf.write_byte(0_u8)
        buf.write(context_u)
        buf.write(context_v)
        IO::ByteFormat::BigEndian.encode(bits.to_u32, buf)

        digest = OpenSSL::HMAC.digest(hash_alg_val, key, buf.to_slice)
        remaining = bytes_needed - result.size
        take_bytes = Math.min(digest.size, remaining)
        result.write(digest[0, take_bytes])
        counter &+= 1
      end

      result.to_slice
    end

    def self.encrypt(data : Bytes, session : Session, alg : String = "XOR") : Bytes
      transform(data, session, alg, encrypt_mode: true)
    end

    def self.decrypt(data : Bytes, session : Session, alg : String = "XOR") : Bytes
      transform(data, session, alg, encrypt_mode: false)
    end

    private def self.transform(data : Bytes, session : Session, alg : String, encrypt_mode : Bool) : Bytes
      return Bytes.empty if data.empty?

      if session.session_key.empty?
        raise SecurityError.new("Session key is required for parameter encryption")
      end

      case alg.upcase
      when "XOR"
        validate_session_nonces!(session)
        raise ArgumentError.new("Data payload too large for KDFa bit count") if data.size > (Int32::MAX // 8)
        mask = kdfa(
          session.hash_alg_name,
          session.session_key,
          "XOR",
          session.nonce_caller,
          session.nonce_tpm,
          data.size * 8
        )
        xor_bytes(data, mask)
      when "CFB", "AES-CFB"
        validate_session_nonces!(session)
        aes_cfb_transform(data, session, encrypt_mode)
      else
        raise ArgumentError.new("Unsupported parameter encryption algorithm: #{alg}")
      end
    end

    private def self.validate_session_nonces!(session : Session) : Nil
      return unless session.nonce_caller.empty? || session.nonce_tpm.empty?

      raise SecurityError.new("Session nonces are required for parameter encryption")
    end

    private def self.aes_cfb_transform(data : Bytes, session : Session, encrypt_mode : Bool) : Bytes
      derived = kdfa(
        session.hash_alg_name,
        session.session_key,
        "CFB",
        session.nonce_caller,
        session.nonce_tpm,
        256
      )
      cipher = OpenSSL::Cipher.new("aes-128-cfb")
      encrypt_mode ? cipher.encrypt : cipher.decrypt
      cipher.key = derived[0, 16]
      cipher.iv = derived[16, 16]
      io = IO::Memory.new(data.size)
      io.write(cipher.update(data))
      io.write(cipher.final)
      io.to_slice
    end

    private def self.xor_bytes(data : Bytes, mask : Bytes) : Bytes
      result = Bytes.new(data.size)
      data.size.times do |i|
        result[i] = data[i] ^ mask[i]
      end
      result
    end
  end
end
