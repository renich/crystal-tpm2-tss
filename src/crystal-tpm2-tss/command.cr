module Crystal::Tpm2::Tss
  # Represents a TPM 2.0 command packet with header, handles, authorization area, and parameters.
  class TPMCommand
    # Structure tag (`TPM2::Tag::NO_SESSIONS` or `TPM2::Tag::SESSIONS`).
    property tag : UInt16

    # Command code (`TPM_CC`).
    getter code : UInt32

    # Ordered list of 32-bit object/hierarchy handles in the command handle area.
    getter handles : Array(UInt32)

    # Serialized authorization area (`TPMS_AUTH_COMMAND` records).
    property auth_area : Bytes

    # Serialized command parameter area bytes.
    property params : Bytes

    # Initializes an empty `TPMCommand` packet with `tag` and `code`.
    def initialize(@tag : UInt16, @code : UInt32) : Nil
      @handles = Array(UInt32).new
      @auth_area = Bytes.empty
      @params = Bytes.empty
    end

    # Builds a TPM 2.0 `TPM_RS_PW` password authorization area (`TPMS_AUTH_COMMAND`).
    def self.build_password_auth(auth_value : Bytes) : Bytes
      Tpm2bCodec.encode_auth_command(
        TPM2::Handles::PW,
        Bytes.empty,
        TPM2::SessionAttributes::CONTINUESESSION,
        auth_value
      )
    end

    # Builds an HMAC session authorization area (`TPMS_AUTH_COMMAND`) for `command_code` and `params`.
    def self.build_session_auth(
      session : Session,
      auth_value : Bytes,
      command_code : UInt32,
      params : Bytes,
    ) : Bytes
      hmac = session.compute_hmac(auth_value, command_code, params)
      Tpm2bCodec.encode_auth_command(session.handle, session.nonce_caller, session.attrs, hmac)
    end

    # Builds the `TPM2B_SENSITIVE_CREATE` and `TPM2B_PUBLIC` parameters for a NIST P-256 ECDSA key.
    def self.build_ecc_p256_create_params(auth_value : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
      io.write(auth_value)
      io.write_bytes(0_u32, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::ECC, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      attrs = TPM2::ObjectAttributes::USER_WITH_AUTH | TPM2::ObjectAttributes::SIGN_ENCRYPT |
              TPM2::ObjectAttributes::FIXEDTPM | TPM2::ObjectAttributes::FIXEDPARENT |
              TPM2::ObjectAttributes::SENSITIVEDATAORIGIN
      io.write_bytes(attrs, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(TPM2::ECCCurves::NIST_P256, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::NULL, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::ECDSA, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(0_u32, TPM2::ENDIAN)
      io.to_slice
    end

    # Appends a 32-bit TPM handle to the command handle area.
    def add_handle(handle : UInt32) : Nil
      @handles << handle
    end

    # Serializes the complete TPM 2.0 command frame in Big-Endian wire format.
    def to_slice : Bytes
      io = IO::Memory.new
      io.write_bytes(@tag, TPM2::ENDIAN)

      total_size = 10_u32 + (@handles.size * 4).to_u32
      total_size += (4 + @auth_area.size).to_u32 if @tag == TPM2::Tag::SESSIONS
      total_size += @params.size.to_u32

      io.write_bytes(total_size, TPM2::ENDIAN)
      io.write_bytes(@code, TPM2::ENDIAN)

      @handles.each do |handle|
        io.write_bytes(handle, TPM2::ENDIAN)
      end

      if @tag == TPM2::Tag::SESSIONS
        io.write_bytes(@auth_area.size.to_u32, TPM2::ENDIAN)
        io.write(@auth_area)
      end

      io.write(@params)
      io.to_slice
    end
  end
end
