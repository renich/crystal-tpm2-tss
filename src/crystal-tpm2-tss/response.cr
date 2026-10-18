module Crystal::Tpm2::Tss
  # Represents a parsed TPM 2.0 response packet with status code, parameters, and authorization area.
  class TPMResponse
    # Response structure tag (`TPM_ST`).
    getter tag : UInt16

    # Total response byte length reported in the header.
    getter size : UInt32

    # Response status code (`TPM_RC`, where `0` indicates `TPM_RC_SUCCESS`).
    getter code : UInt32

    # Unmarshaled response parameter bytes.
    property params : Bytes

    # Unmarshaled response authorization area bytes (`TPMS_AUTH_RESPONSE`).
    property auth_area : Bytes

    # Initializes a `TPMResponse` with header fields `tag`, `size`, and `code`.
    def initialize(@tag : UInt16, @size : UInt32, @code : UInt32) : Nil
      @params = Bytes.empty
      @auth_area = Bytes.empty
    end

    # Parses a raw TPM 2.0 binary response buffer and updates `session` nonces when present.
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

    # Parses a `TPMT_SIGNATURE` ECDSA response parameter buffer into an `ECDSASignature`.
    def self.parse_ecdsa_signature(params : Bytes) : ECDSASignature
      io = IO::Memory.new(params)
      _header = io.read_bytes(UInt32, TPM2::ENDIAN)
      ECDSASignature.new(read_sized_component(io), read_sized_component(io))
    rescue IO::EOFError
      raise TPMError.new("Invalid ECDSA signature response")
    end

    # Parses a `TPM2_ReadPublic` response parameter buffer into 32-byte `(x, y)` coordinates.
    def self.parse_read_public_xy(params : Bytes) : Tuple(Bytes, Bytes)
      return {Bytes.new(32, 0_u8), Bytes.new(32, 0_u8)} if params.size < 68
      io = IO::Memory.new(params)
      x = Bytes.new(io.read_bytes(UInt16, TPM2::ENDIAN).to_i)
      io.read_fully(x)
      y = Bytes.new(io.read_bytes(UInt16, TPM2::ENDIAN).to_i)
      io.read_fully(y)
      {x, y}
    end

    # Returns `true` when the TPM response code equals `TPM_RC_SUCCESS` (`0`).
    def success? : Bool
      @code == 0_u32
    end

    private def self.read_sized_component(io : IO::Memory) : Bytes
      buf = Bytes.new(io.read_bytes(UInt16, TPM2::ENDIAN).to_i)
      io.read_fully(buf)
      raise TPMError.new("Invalid ECDSA signature component") if buf.empty? || buf.all?(&.zero?)
      buf
    end

    private def self.parse_session_area(io : IO::Memory, data : Bytes, resp : TPMResponse, session : Session?) : Nil
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
