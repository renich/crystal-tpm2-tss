require "sync/mutex"

module Crystal::Tpm2::Tss
  # Hardware and virtual transport interface for executing TPM 2.0 commands.
  class TPMDevice
    getter device_path : String?

    @nv_store : Hash(UInt32, Bytes)
    @mutex : Sync::Mutex

    def initialize(@device_path : String? = nil) : Nil
      @nv_store = Hash(UInt32, Bytes).new
      @mutex = Sync::Mutex.new
    end

    def execute(command : TPMCommand, session : Session? = nil) : TPMResponse
      if path = @device_path
        execute_hardware(path, command, session)
      else
        execute_virtual(command, session)
      end
    end

    private def execute_hardware(path : String, command : TPMCommand, session : Session?) : TPMResponse
      File.open(path, "r+") do |file|
        file.write(command.to_slice)
        file.flush
        buffer = uninitialized StaticArray(UInt8, 4096)
        bytes_read = file.read(buffer.to_slice)
        TPMResponse.parse(buffer.to_slice[0, bytes_read], session)
      end
    rescue ex : IO::Error | File::Error
      raise TPMError.new("TPM device I/O error on #{path}: #{ex.message}")
    end

    private def execute_virtual(command : TPMCommand, session : Session?) : TPMResponse
      @mutex.synchronize do
        session.try(&.update_nonce_tpm(Random::Secure.random_bytes(session.hash_output_size)))
        dispatch_virtual_command(command)
      end
    end

    private def dispatch_virtual_command(command : TPMCommand) : TPMResponse
      case command.code
      when TPM2::Commands::CreatePrimary
        build_u32_response(TPM2::Tag::SESSIONS, 0x80000000_u32)
      when TPM2::Commands::Create
        resp = TPMResponse.new(TPM2::Tag::SESSIONS, 18_u32, 0_u32)
        resp.params = Bytes.new(8, 0x01_u8)
        resp
      when TPM2::Commands::Load
        build_u32_response(TPM2::Tag::SESSIONS, 0x80000001_u32)
      when TPM2::Commands::EvictControl
        TPMResponse.new(TPM2::Tag::SESSIONS, 10_u32, 0_u32)
      when TPM2::Commands::NV_DEFINESPACE
        simulate_nv_define(command)
      when TPM2::Commands::NV_WRITE
        simulate_nv_write(command)
      when TPM2::Commands::NV_READ
        simulate_nv_read(command)
      when TPM2::Commands::Sign
        simulate_sign
      else
        TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10_u32, 0_u32)
      end
    end

    private def build_u32_response(tag : UInt16, value : UInt32) : TPMResponse
      io = IO::Memory.new(4)
      io.write_bytes(value, TPM2::ENDIAN)
      resp = TPMResponse.new(tag, 14_u32, 0_u32)
      resp.params = io.to_slice
      resp
    end

    private def simulate_nv_define(command : TPMCommand) : TPMResponse
      if command.params.size >= 4
        nv_index = IO::Memory.new(command.params).read_bytes(UInt32, TPM2::ENDIAN)
        @nv_store[nv_index] ||= Bytes.empty
      end
      TPMResponse.new(TPM2::Tag::SESSIONS, 10_u32, 0_u32)
    end

    private def simulate_nv_write(command : TPMCommand) : TPMResponse
      nv_index = command.handles.last? || 0_u32
      if command.params.size >= 2
        io = IO::Memory.new(command.params)
        size = io.read_bytes(UInt16, TPM2::ENDIAN).to_i
        if (io.size - io.pos) >= size
          data = Bytes.new(size)
          io.read_fully(data)
          @nv_store[nv_index] = data
        end
      end
      TPMResponse.new(TPM2::Tag::SESSIONS, 10_u32, 0_u32)
    end

    private def simulate_nv_read(command : TPMCommand) : TPMResponse
      nv_index = command.handles.last? || 0_u32
      stored = @nv_store[nv_index]?
      if stored && !stored.empty?
        io = IO::Memory.new(2 + stored.size)
        io.write_bytes(stored.size.to_u16, TPM2::ENDIAN)
        io.write(stored)
        resp = TPMResponse.new(TPM2::Tag::SESSIONS, (12 + stored.size).to_u32, 0_u32)
        resp.params = io.to_slice
        resp
      else
        TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10_u32, 0x00000146_u32)
      end
    end

    private def simulate_sign : TPMResponse
      io = IO::Memory.new(72)
      io.write_bytes(TPM2::Algorithms::ECDSA, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      io.write_bytes(32_u16, TPM2::ENDIAN)
      io.write(Random::Secure.random_bytes(32))
      io.write_bytes(32_u16, TPM2::ENDIAN)
      io.write(Random::Secure.random_bytes(32))
      resp = TPMResponse.new(TPM2::Tag::SESSIONS, 82_u32, 0_u32)
      resp.params = io.to_slice
      resp
    end
  end
end
