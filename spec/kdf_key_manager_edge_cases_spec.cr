require "./spec_helper"

class KDFKeyManager
  def public_parse_nv_read_response(params : Bytes)
    parse_nv_read_response(params)
  end
end

describe "KDFKeyManager Edge Cases" do
  it "raises on empty NV read response" do
    tpm = MockTPMDevice.new
    manager = KDFKeyManager.new(tpm)
    
    expect_raises(TPMError, "Empty NV read response") do
      manager.public_parse_nv_read_response(Bytes.empty)
    end
  end

  it "raises on invalid NV read response format (too short)" do
    tpm = MockTPMDevice.new
    manager = KDFKeyManager.new(tpm)
    
    # Needs a 16-bit size, we provide 1 byte
    expect_raises(TPMError, "Invalid NV read response format") do
      manager.public_parse_nv_read_response(Bytes.new(1, 0))
    end
  end

  it "raises on invalid NV read response format (data missing)" do
    tpm = MockTPMDevice.new
    manager = KDFKeyManager.new(tpm)
    
    io = IO::Memory.new
    io.write_bytes(10_u16, TPM2::ENDIAN)
    io.write(Bytes.new(5, 0)) # only 5 bytes, expects 10

    expect_raises(TPMError, "Invalid NV read response format") do
      manager.public_parse_nv_read_response(io.to_slice)
    end
  end
end
