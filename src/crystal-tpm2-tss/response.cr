module Crystal::Tpm2::Tss
  # Represents a parsed TPM 2.0 response packet with status code, parameters, and authorization area.
  class TPMResponse
    # Response structure tag (`TPM_ST`).
    property tag : UInt16

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
      Tpm2bCodec.decode_tpmt_signature(params)
    end

    # Parses a `TPM2_ReadPublic` response parameter buffer into 32-byte `(x, y)` coordinates.
    def self.parse_read_public_xy(params : Bytes) : Tuple(Bytes, Bytes)
      raise TPMError.new("Truncated ReadPublic response payload") if params.size < 68
      if params.size > 68
        decoded = Tpm2bCodec.decode_ecc_public(params)
        return {decoded[:x], decoded[:y]}
      end

      io = IO::Memory.new(params)
      x_len = io.read_bytes(UInt16, TPM2::ENDIAN).to_i
      raise TPMError.new("Invalid ReadPublic X coordinate length") if x_len != 32
      x = Bytes.new(32)
      io.read_fully(x)
      y_len = io.read_bytes(UInt16, TPM2::ENDIAN).to_i
      raise TPMError.new("Invalid ReadPublic Y coordinate length") if y_len != 32
      y = Bytes.new(32)
      io.read_fully(y)
      {x, y}
    end

    # Returns `true` when the TPM response code equals `TPM_RC_SUCCESS` (`0`).
    def success? : Bool
      @code == 0_u32
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
      decoded = Tpm2bCodec.decode_auth_response(auth_area)
      session.update_nonce_tpm(decoded[:nonce])
    rescue TPMError
    end
  end
end
