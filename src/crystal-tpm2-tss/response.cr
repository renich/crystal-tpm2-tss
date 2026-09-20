module Crystal::Tpm2::Tss
  class TPMResponse
    getter tag : UInt16
    getter size : UInt32
    getter code : UInt32
    property params : Bytes
    property auth_area : Bytes

    def initialize(@tag : UInt16, @size : UInt32, @code : UInt32)
      @params = Bytes.empty
      @auth_area = Bytes.empty
    end

    def self.parse(data : Bytes, session : Session? = nil) : self
      raise TPMError.new("Response too short") if data.size < 10

      io = IO::Memory.new(data)
      tag = io.read_bytes(UInt16, TPM2::ENDIAN)
      size = io.read_bytes(UInt32, TPM2::ENDIAN)
      code = io.read_bytes(UInt32, TPM2::ENDIAN)
      resp = new(tag, size, code)

      if tag == TPM2::Tag::SESSIONS && data.size > 10
        auth_size = io.read_bytes(UInt32, TPM2::ENDIAN)
        if (io.size - io.pos) >= 8
          _session_count = io.read_bytes(UInt32, TPM2::ENDIAN)
          _handle = io.read_bytes(UInt32, TPM2::ENDIAN)
          nonce_size = io.read_bytes(UInt16, TPM2::ENDIAN)
          if (io.size - io.pos) >= nonce_size
            nonce = Bytes.new(nonce_size.to_i)
            io.read_fully(nonce)
            _attr = io.read_byte
            _hmac_size = ((io.size - io.pos) >= 2) ? io.read_bytes(UInt16, TPM2::ENDIAN) : 0_u16

            resp.auth_area = data[10, auth_size] if data.size >= 10 + auth_size
            session.try(&.update_nonce_tpm(nonce))
          end
        end
      end
      resp
    end

    def success? : Bool
      @code == 0_u32
    end
  end
end
