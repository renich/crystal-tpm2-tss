module Crystal::Tpm2::Tss
  # Represents a TPM 2.0 command packet with header, handles, authorization area, and parameters.
  class TPMCommand
    getter tag : UInt16
    getter code : UInt32
    getter handles : Array(UInt32)
    property auth_area : Bytes
    property params : Bytes

    def initialize(@tag : UInt16, @code : UInt32) : Nil
      @handles = Array(UInt32).new
      @auth_area = Bytes.empty
      @params = Bytes.empty
    end

    # Builds a TPM 2.0 `TPM_RS_PW` password authorization area (`TPMS_AUTH_COMMAND`).
    def self.build_password_auth(auth_value : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(1_u32, TPM2::ENDIAN)
      io.write_bytes(TPM2::Handles::PW, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_byte(TPM2::SessionAttributes::CONTINUESESSION)
      io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
      io.write(auth_value)
      io.to_slice
    end

    def add_handle(handle : UInt32) : Nil
      @handles << handle
    end

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
