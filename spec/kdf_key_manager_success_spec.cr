require "./spec_helper"

class MultiResponseMockTPM < TPMDevice
  property responses : Array(TPMResponse)
  def initialize(@responses)
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
    # 1. read fails (raises TPMError)
    # 2. define_nv_index succeeds (code 0)
    # 3. write_kdf_key_to_nv succeeds (code 0)
    
    responses = [
      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0x0146_u32), # fail read
      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0),          # define success
      TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0)           # write success
    ]
    tpm = MultiResponseMockTPM.new(responses)
    manager = KDFKeyManager.new(tpm)
    
    key = manager.get_kdf_key
    key.size.should eq(32)
  end

  it "reads existing KDF key successfully" do
    # mock read success
    io = IO::Memory.new
    io.write_bytes(32_u16, TPM2::ENDIAN)
    io.write(Bytes.new(32, 0x77_u8))
    
    resp = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 44, 0)
    resp.params = io.to_slice
    
    tpm = MultiResponseMockTPM.new([resp])
    manager = KDFKeyManager.new(tpm)
    
    key = manager.get_kdf_key
    key.should eq(Bytes.new(32, 0x77_u8))
  end
end
