require "sync/mutex"
require "openssl"

module Crystal::Tpm2::Tss
  class KDFKeyManager
    getter tpm : TPMDevice
    getter kdf_nv_index : UInt32
    getter platform_secret : Bytes

    @kdf_key : Bytes?
    @mutex : Sync::Mutex

    def initialize(
      @tpm : TPMDevice,
      @platform_secret : Bytes = Random::Secure.random_bytes(32),
      @kdf_nv_index : UInt32 = 0x01C00000_u32,
    )
      @mutex = Sync::Mutex.new
      @kdf_key = nil
    end

    def kdf_key : Bytes
      if kdf_key_val = @kdf_key
        return kdf_key_val
      end

      @mutex.synchronize do
        if kdf_key_val = @kdf_key
          return kdf_key_val
        end

        begin
          key_data = read_kdf_key_from_nv
          @kdf_key = key_data
          key_data
        rescue TPMError
          create_and_store_kdf_key
        end
      end
    end

    private def read_kdf_key_from_nv : Bytes
      auth_value = derive_nv_auth
      command = build_nv_read_command(@kdf_nv_index, 0_u16, 32_u16, auth_value)
      response = @tpm.execute(command)

      unless response.success?
        raise TPMError.new("Failed to read KDF key", response.code)
      end

      parse_nv_read_response(response.params)
    end

    private def create_and_store_kdf_key : Bytes
      new_kdf_key = Random::Secure.random_bytes(32)
      define_nv_index(@kdf_nv_index, 32)

      auth_value = derive_nv_auth
      write_kdf_key_to_nv(new_kdf_key, auth_value)

      @kdf_key = new_kdf_key
      new_kdf_key
    end

    private def define_nv_index(nv_index : UInt32, size : Int32) : Nil
      public_info = build_nv_public_info(size)
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_DEFINESPACE)
      command.add_handle(TPM2::Handles::OWNER)
      command.auth_area = build_password_auth(Bytes.empty)
      command.params = serialize_nv_define_params(nv_index, public_info)

      response = @tpm.execute(command)
      unless response.success? || response.code == TPM2::ResponseCodes::NV_DEFINED
        raise TPMError.new("Failed to define NV index", response.code)
      end
    end

    private def write_kdf_key_to_nv(key : Bytes, auth_value : Bytes) : Nil
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_WRITE)
      command.add_handle(@kdf_nv_index)
      command.auth_area = build_password_auth(auth_value)
      command.params = serialize_nv_write_params(0_u16, key)

      response = @tpm.execute(command)
      unless response.success?
        raise TPMError.new("Failed to write KDF key", response.code)
      end
    end

    private def derive_nv_auth : Bytes
      OpenSSL::Digest.new("SHA256").update(@platform_secret).final
    end

    private def build_nv_public_info(size : Int32) : Bytes
      io = IO::Memory.new
      nv_index_type = 0x00000001_u32
      nv_attributes = 0x00040002_u32

      io.write_bytes(nv_index_type, TPM2::ENDIAN)
      io.write_bytes(nv_attributes, TPM2::ENDIAN)
      io.write_bytes(0x0000_u16, TPM2::ENDIAN)
      io.write_bytes(0x0000_u16, TPM2::ENDIAN)
      io.write_bytes(size.to_u16, TPM2::ENDIAN)
      io.to_slice
    end

    private def build_nv_read_command(index : UInt32, offset : UInt16, size : UInt16, auth_value : Bytes) : TPMCommand
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_READ)
      command.add_handle(index)
      command.add_handle(index)
      command.auth_area = build_password_auth(auth_value)

      io = IO::Memory.new
      io.write_bytes(size, TPM2::ENDIAN)
      io.write_bytes(offset, TPM2::ENDIAN)
      command.params = io.to_slice
      command
    end

    private def build_password_auth(auth_value : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(1_u32, TPM2::ENDIAN)
      io.write_bytes(TPM2::Handles::PW, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_byte(TPM2::SessionAttributes::CONTINUESESSION)
      io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
      io.write(auth_value)
      io.to_slice
    end

    private def serialize_nv_define_params(nv_index : UInt32, public_info : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(nv_index, TPM2::ENDIAN)
      io.write_bytes(0x0000_u16, TPM2::ENDIAN)
      io.write_bytes(public_info.size.to_u16, TPM2::ENDIAN)
      io.write(public_info)
      io.to_slice
    end

    private def serialize_nv_write_params(offset : UInt16, data : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(data.size.to_u16, TPM2::ENDIAN)
      io.write(data)
      io.write_bytes(offset, TPM2::ENDIAN)
      io.to_slice
    end

    private def parse_nv_read_response(params : Bytes) : Bytes
      raise TPMError.new("Empty NV read response") if params.empty?
      io = IO::Memory.new(params)
      size = io.read_bytes(UInt16, TPM2::ENDIAN)
      raise TPMError.new("Invalid NV read response format") if (io.size - io.pos) < size
      data = Bytes.new(size.to_i)
      io.read_fully(data)
      data
    rescue IO::EOFError
      raise TPMError.new("Invalid NV read response format")
    end
  end
end
