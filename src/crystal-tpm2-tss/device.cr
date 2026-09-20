module Crystal::Tpm2::Tss
  class TPMDevice
    getter device_path : String?

    def initialize(@device_path : String? = nil)
    end

    def execute(command : TPMCommand, session : Session? = nil) : TPMResponse
      if path = @device_path
        if File.exists?(path)
          File.open(path, "r+") do |file|
            file.write(command.to_slice)
            file.flush
            buffer = Bytes.new(4096)
            bytes_read = file.read(buffer)
            return TPMResponse.parse(buffer[0, bytes_read], session)
          end
        end
      end

      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10_u32, 0_u32)
    end
  end
end
