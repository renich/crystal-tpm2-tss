require "openssl/hmac"

module Crystal::Tpm2::Tss
  module ParameterEncryption
    def self.kdfa(
      hash_alg : String,
      key : Bytes,
      label : String,
      context_u : Bytes,
      context_v : Bytes,
      bits : Int32,
    ) : Bytes
      bytes_needed = (bits + 7) // 8
      return Bytes.empty if bytes_needed <= 0

      hash_alg_val = OpenSSL::Algorithm.parse(hash_alg)
      result = IO::Memory.new(bytes_needed)
      counter = 1_u32

      while result.size < bytes_needed
        buf = IO::Memory.new
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
      return Bytes.empty if data.empty?

      if session.session_key.empty?
        raise SecurityError.new("Session key is required for parameter encryption")
      end

      case alg.upcase
      when "XOR"
        mask = kdfa(session.hash_alg_name, session.session_key, "XOR", session.nonce_caller, session.nonce_tpm, data.size * 8)
        xor_bytes(data, mask)
      else
        raise ArgumentError.new("Unsupported parameter encryption algorithm: #{alg}")
      end
    end

    def self.decrypt(data : Bytes, session : Session, alg : String = "XOR") : Bytes
      encrypt(data, session, alg)
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
