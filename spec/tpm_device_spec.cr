require "./spec_helper"

# Verifies [FUNC-001], [FUNC-002] / [TECH-001], [TECH-002]
describe "TPMDevice" do
  it "returns default response in virtual mode" do
    tpm = TPMDevice.new
    cmd = TPMCommand.new(0_u16, 0_u32)
    resp = tpm.execute(cmd)
    resp.code.should eq(0)
  end

  it "simulates StartAuthSession and ReadPublic in virtual mode" do
    tpm = TPMDevice.new
    auth_cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::StartAuthSession)
    auth_resp = tpm.execute(auth_cmd)
    auth_resp.success?.should be_true
    auth_resp.params.size.should eq(38)
    TPM2::ENDIAN.decode(UInt32, auth_resp.params[0, 4]).should eq(0x02000001_u32)

    pub_cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::ReadPublic)
    pub_cmd.add_handle(0x81010001_u32)
    pub_resp = tpm.execute(pub_cmd)
    pub_resp.success?.should be_true
    pub_resp.params.size.should eq(68)
  end

  it "raises TPMError when configured hardware device path is inaccessible" do
    tpm = TPMDevice.new("/nonexistent/tpmrm0")
    cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::GetCapability)
    expect_raises(TPMError, "TPM device I/O error") do
      tpm.execute(cmd)
    end
  end
end
