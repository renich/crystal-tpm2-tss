require "spec"
require "../src/crystal-tpm2-tss"

class MockTPMDevice < TPMDevice
  property next_response : TPMResponse?
  property executed_commands = [] of TPMCommand

  def execute(command : TPMCommand, session : Session? = nil) : TPMResponse
    @executed_commands << command
    @next_response || TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0)
  end
end
