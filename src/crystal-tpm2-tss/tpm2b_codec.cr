module Crystal::Tpm2::Tss
  # Deterministic TCG TPM 2.0 Part 2 binary structure encoders and overflow-safe decoders.
  module Tpm2bCodec
    # Encodes a `TPMS_AUTH_COMMAND` authorization record in big-endian wire format.
    def self.encode_auth_command(
      session_handle : UInt32,
      nonce : Bytes,
      session_attributes : UInt8,
      hmac : Bytes,
    ) : Bytes
      io = IO::Memory.new(9 + nonce.size + hmac.size)
      io.write_bytes(session_handle, TPM2::ENDIAN)
      write_tpm2b(io, nonce)
      io.write_byte(session_attributes)
      write_tpm2b(io, hmac)
      io.to_slice
    end

    # Decodes a `TPMS_AUTH_COMMAND` byte buffer and validates exact length boundaries.
    def self.decode_auth_command(
      bytes : Bytes,
    ) : NamedTuple(session_handle: UInt32, nonce: Bytes, session_attributes: UInt8, hmac: Bytes)
      io = IO::Memory.new(bytes)
      handle = read_u32(io)
      nonce = read_tpm2b(io)
      attrs = read_u8(io)
      hmac = read_tpm2b(io)
      ensure_eof!(io, "TPMS_AUTH_COMMAND")
      {session_handle: handle, nonce: nonce, session_attributes: attrs, hmac: hmac}
    end

    # Encodes a `TPMS_AUTH_RESPONSE` authorization record in big-endian wire format.
    def self.encode_auth_response(
      nonce : Bytes,
      session_attributes : UInt8,
      hmac : Bytes,
    ) : Bytes
      io = IO::Memory.new(5 + nonce.size + hmac.size)
      write_tpm2b(io, nonce)
      io.write_byte(session_attributes)
      write_tpm2b(io, hmac)
      io.to_slice
    end

    # Decodes a `TPMS_AUTH_RESPONSE` byte buffer and validates exact length boundaries.
    def self.decode_auth_response(
      bytes : Bytes,
    ) : NamedTuple(nonce: Bytes, session_attributes: UInt8, hmac: Bytes)
      io = IO::Memory.new(bytes)
      nonce = read_tpm2b(io)
      attrs = read_u8(io)
      hmac = read_tpm2b(io)
      ensure_eof!(io, "TPMS_AUTH_RESPONSE")
      {nonce: nonce, session_attributes: attrs, hmac: hmac}
    end

    # Encodes a `TPM2B_SENSITIVE_CREATE` structure containing `user_auth` and sensitive `data`.
    def self.encode_sensitive_create(user_auth : Bytes, data : Bytes = Bytes.empty) : Bytes
      inner = IO::Memory.new(4 + user_auth.size + data.size)
      write_tpm2b(inner, user_auth)
      write_tpm2b(inner, data)
      outer = IO::Memory.new(2 + inner.size)
      write_tpm2b(outer, inner.to_slice)
      outer.to_slice
    end

    # Decodes a `TPM2B_SENSITIVE_CREATE` byte buffer into `user_auth` and `data` slices.
    def self.decode_sensitive_create(bytes : Bytes) : NamedTuple(user_auth: Bytes, data: Bytes)
      outer_io = IO::Memory.new(bytes)
      body = read_tpm2b(outer_io)
      ensure_eof!(outer_io, "TPM2B_SENSITIVE_CREATE")

      inner_io = IO::Memory.new(body)
      user_auth = read_tpm2b(inner_io)
      data = read_tpm2b(inner_io)
      ensure_eof!(inner_io, "TPMS_SENSITIVE_CREATE")
      {user_auth: user_auth, data: data}
    end

    # Encodes a `TPM2B_PUBLIC` structure for an ECC key (`TPMS_ECC_PARMS` + `TPMS_ECC_POINT`).
    def self.encode_ecc_public(
      x : Bytes,
      y : Bytes,
      scheme : UInt16 = 0x0018_u16,
      curve_id : UInt16 = 0x0003_u16,
      name_alg : UInt16 = 0x000B_u16,
      object_attributes : UInt32 = 0x00040072_u32,
    ) : Bytes
      inner = IO::Memory.new(26 + x.size + y.size)
      inner.write_bytes(TPM2::Algorithms::ECC, TPM2::ENDIAN)
      inner.write_bytes(name_alg, TPM2::ENDIAN)
      inner.write_bytes(object_attributes, TPM2::ENDIAN)
      write_tpm2b(inner, Bytes.empty)
      inner.write_bytes(TPM2::Algorithms::NULL, TPM2::ENDIAN)
      inner.write_bytes(scheme, TPM2::ENDIAN)
      inner.write_bytes(name_alg, TPM2::ENDIAN)
      inner.write_bytes(curve_id, TPM2::ENDIAN)
      inner.write_bytes(TPM2::Algorithms::NULL, TPM2::ENDIAN)
      write_tpm2b(inner, x)
      write_tpm2b(inner, y)

      outer = IO::Memory.new(2 + inner.size)
      write_tpm2b(outer, inner.to_slice)
      outer.to_slice
    end

    # Decodes a `TPM2B_PUBLIC` ECC structure and extracts its parameters and `(x, y)` coordinates.
    def self.decode_ecc_public(
      bytes : Bytes,
    ) : NamedTuple(name_alg: UInt16, object_attributes: UInt32, scheme: UInt16, curve_id: UInt16, x: Bytes, y: Bytes)
      outer_io = IO::Memory.new(bytes)
      body = read_tpm2b(outer_io)
      ensure_eof!(outer_io, "TPM2B_PUBLIC")

      io = IO::Memory.new(body)
      alg_type = read_u16(io)
      raise TPMError.new("Unsupported TPMT_PUBLIC type: 0x#{alg_type.to_s(16)}") if alg_type != TPM2::Algorithms::ECC
      name_alg = read_u16(io)
      obj_attrs = read_u32(io)
      _auth_policy = read_tpm2b(io)
      _symmetric = read_u16(io)
      scheme = read_u16(io)
      _scheme_hash = read_u16(io)
      curve_id = read_u16(io)
      _kdf = read_u16(io)
      x = read_tpm2b(io)
      y = read_tpm2b(io)
      ensure_eof!(io, "TPMT_PUBLIC")
      {name_alg: name_alg, object_attributes: obj_attrs, scheme: scheme, curve_id: curve_id, x: x, y: y}
    end

    # Encodes a `TPMT_SIGNATURE` structure for an ECDSA `(r, s)` signature pair.
    def self.encode_tpmt_signature(
      sig : ECDSASignature,
      sig_alg : UInt16 = 0x0018_u16,
      hash_alg : UInt16 = 0x000B_u16,
    ) : Bytes
      io = IO::Memory.new(8 + sig.r.size + sig.s.size)
      io.write_bytes(sig_alg, TPM2::ENDIAN)
      io.write_bytes(hash_alg, TPM2::ENDIAN)
      write_tpm2b(io, sig.r)
      write_tpm2b(io, sig.s)
      io.to_slice
    end

    # Decodes a `TPMT_SIGNATURE` structure into a validated non-zero `ECDSASignature`.
    def self.decode_tpmt_signature(bytes : Bytes) : ECDSASignature
      io = IO::Memory.new(bytes)
      sig_alg = read_u16(io)
      raise TPMError.new("Unsupported signature algorithm: 0x#{sig_alg.to_s(16)}") if sig_alg != TPM2::Algorithms::ECDSA
      _hash_alg = read_u16(io)
      r = read_non_zero_component(io)
      s = read_non_zero_component(io)
      ensure_eof!(io, "TPMT_SIGNATURE")
      ECDSASignature.new(r, s)
    end

    # Writes a big-endian `UInt16`-prefixed `TPM2B` slice into `io`.
    def self.write_tpm2b(io : IO::Memory, slice : Bytes) : Nil
      raise TPMError.new("TPM2B payload exceeds UInt16::MAX") if slice.size > UInt16::MAX.to_i
      io.write_bytes(slice.size.to_u16, TPM2::ENDIAN)
      io.write(slice)
    end

    # Reads a big-endian `UInt16`-prefixed `TPM2B` slice from `io`.
    def self.read_tpm2b(io : IO::Memory) : Bytes
      len = read_u16(io).to_u64
      remaining = (io.size - io.pos).to_u64
      raise TPMError.new("Truncated TPM2B buffer") if len > remaining
      buf = Bytes.new(len.to_i)
      io.read_fully(buf)
      buf
    end

    private def self.read_non_zero_component(io : IO::Memory) : Bytes
      buf = read_tpm2b(io)
      raise TPMError.new("Invalid ECDSA signature component") if buf.empty? || buf.all?(&.zero?)
      buf
    end

    private def self.read_u8(io : IO::Memory) : UInt8
      raise TPMError.new("Unexpected EOF reading UInt8") if (io.size - io.pos).to_u64 < 1_u64
      io.read_bytes(UInt8, TPM2::ENDIAN)
    end

    private def self.read_u16(io : IO::Memory) : UInt16
      raise TPMError.new("Unexpected EOF reading UInt16") if (io.size - io.pos).to_u64 < 2_u64
      io.read_bytes(UInt16, TPM2::ENDIAN)
    end

    private def self.read_u32(io : IO::Memory) : UInt32
      raise TPMError.new("Unexpected EOF reading UInt32") if (io.size - io.pos).to_u64 < 4_u64
      io.read_bytes(UInt32, TPM2::ENDIAN)
    end

    private def self.ensure_eof!(io : IO::Memory, struct_name : String) : Nil
      raise TPMError.new("Trailing bytes in #{struct_name}") if io.pos != io.size
    end
  end
end
