require "./spec_helper"

# Verifies [FUNC-004] / [TECH-003]
describe "KDFKeyManager" do
  it "creates and caches KDF key when NV read initially fails" do
    tpm = MockTPMDevice.new
    tpm.enqueue_response(TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10_u32, 0x00000146_u32))
    tpm.enqueue_response(TPMResponse.new(TPM2::Tag::SESSIONS, 10_u32, 0_u32))
    tpm.enqueue_response(TPMResponse.new(TPM2::Tag::SESSIONS, 10_u32, 0_u32))

    manager = KDFKeyManager.new(tpm)
    key = manager.kdf_key
    key.size.should eq(32)
    manager.kdf_key.should eq(key)
    tpm.executed_commands.size.should eq(3)
  end

  it "raises TPMError when NV definition fails after missing key" do
    tpm = MockTPMDevice.new
    tpm.next_response = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10_u32, 0x00000146_u32)

    manager = KDFKeyManager.new(tpm)

    expect_raises(TPMError, "Failed to define NV index") do
      manager.kdf_key
    end
  end
end
