require "./spec_helper"

# Verifies [FUNC-004] / [TECH-003], [TECH-005]
# Reopens KDFKeyManager to expose NV response parser for edge-case specification testing.
class Crystal::Tpm2::Tss::KDFKeyManager
  def public_parse_nv_read_response(params : Bytes) : Bytes
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

    expect_raises(TPMError, "Invalid NV read response format") do
      manager.public_parse_nv_read_response(Bytes.new(1, 0))
    end
  end

  it "raises on invalid NV read response format (data missing)" do
    tpm = MockTPMDevice.new
    manager = KDFKeyManager.new(tpm)

    io = IO::Memory.new
    io.write_bytes(10_u16, TPM2::ENDIAN)
    io.write(Bytes.new(5, 0))

    expect_raises(TPMError, "Invalid NV read response format") do
      manager.public_parse_nv_read_response(io.to_slice)
    end
  end
end
