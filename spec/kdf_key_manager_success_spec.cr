require "./spec_helper"

# Mock TPM device returning an ordered sequence of pre-configured responses.
class MultiResponseMockTPM < TPMDevice
  property responses : Array(TPMResponse)

  def initialize(@responses : Array(TPMResponse)) : Nil
    super("/dev/null")
  end

  def execute(command : TPMCommand, session : Session? = nil) : TPMResponse
    if @responses.empty?
      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0)
    else
      @responses.shift
    end
  end
end

describe "KDFKeyManager Success" do
  it "creates and stores KDF key successfully" do
    responses = [
      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0x0146_u32),
      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0),
      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0),
    ]
    tpm = MultiResponseMockTPM.new(responses)
    manager = KDFKeyManager.new(tpm)

    key = manager.kdf_key
    key.size.should eq(32)
  end

  it "reads existing KDF key successfully" do
    io = IO::Memory.new
    io.write_bytes(32_u16, TPM2::ENDIAN)
    io.write(Bytes.new(32, 0x77_u8))

    resp = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 44, 0)
    resp.params = io.to_slice

    tpm = MultiResponseMockTPM.new([resp])
    manager = KDFKeyManager.new(tpm)

    key = manager.kdf_key
    key.should eq(Bytes.new(32, 0x77_u8))
  end
end
