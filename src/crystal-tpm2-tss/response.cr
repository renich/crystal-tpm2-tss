module Crystal::Tpm2::Tss
  # Represents a parsed TPM 2.0 response packet with status code, parameters, and authorization area.
  class TPMResponse
    getter tag : UInt16
    getter size : UInt32
    getter code : UInt32
    property params : Bytes
    property auth_area : Bytes

    def initialize(@tag : UInt16, @size : UInt32, @code : UInt32) : Nil
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

      if data.size > 10
        if tag == TPM2::Tag::SESSIONS
          parse_session_area(io, data, resp, session)
        else
          resp.params = data[10, data.size - 10].dup
        end
      end

      resp
    end

    def success? : Bool
      @code == 0_u32
    end

    private def self.parse_session_area(
      io : IO::Memory,
      data : Bytes,
      resp : TPMResponse,
      session : Session?,
    ) : Nil
      if data.size < 14
        resp.params = data[10, data.size - 10].dup
        return
      end

      auth_size = io.read_bytes(UInt32, TPM2::ENDIAN)
      auth_end = 14_u64 + auth_size.to_u64
      if auth_end > data.size.to_u64
        resp.params = data[10, data.size - 10].dup
        return
      end

      resp.auth_area = data[14, auth_size.to_i].dup
      if auth_end < data.size.to_u64
        params_offset = auth_end.to_i
        resp.params = data[params_offset, data.size - params_offset].dup
      end

      extract_session_nonce(resp.auth_area, session)
    end

    private def self.extract_session_nonce(auth_area : Bytes, session : Session?) : Nil
      return unless session
      return if auth_area.size < 10

      auth_io = IO::Memory.new(auth_area)
      _session_count = auth_io.read_bytes(UInt32, TPM2::ENDIAN)
      _handle = auth_io.read_bytes(UInt32, TPM2::ENDIAN)
      nonce_size = auth_io.read_bytes(UInt16, TPM2::ENDIAN)
      return if (auth_io.size - auth_io.pos) < nonce_size.to_i

      nonce = Bytes.new(nonce_size.to_i)
      auth_io.read_fully(nonce)
      session.update_nonce_tpm(nonce)
    end
  end
end
