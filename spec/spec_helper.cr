require "spec"
require "../src/crystal-tpm2-tss"

# Configurable mock TPM device supporting queued and single-response test scenarios.
class MockTPMDevice < TPMDevice
  property next_response : TPMResponse?
  property response_queue : Deque(TPMResponse) = Deque(TPMResponse).new
  property executed_commands : Array(TPMCommand) = Array(TPMCommand).new

  def enqueue_response(resp : TPMResponse) : Nil
    @response_queue << resp
  end

  def execute(command : TPMCommand, session : Session? = nil) : TPMResponse
    @executed_commands << command
    if queued = @response_queue.shift?
      return queued
    end
    @next_response || TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10_u32, 0_u32)
  end
end
