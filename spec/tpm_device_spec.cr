require "./spec_helper"

describe "TPMDevice" do
  it "returns default response" do
    tpm = TPMDevice.new
    cmd = TPMCommand.new(0_u16, 0_u32)
    resp = tpm.execute(cmd)
    resp.code.should eq(0)
  end
end
