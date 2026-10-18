require "./spec_helper"

describe "TPMDevice" do
  it "returns default response in virtual mode" do
    tpm = TPMDevice.new
    cmd = TPMCommand.new(0_u16, 0_u32)
    resp = tpm.execute(cmd)
    resp.code.should eq(0)
  end

  it "raises TPMError when configured hardware device path is inaccessible" do
    tpm = TPMDevice.new("/nonexistent/tpmrm0")
    cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::GetCapability)
    expect_raises(TPMError, "TPM device I/O error") do
      tpm.execute(cmd)
    end
  end
end
