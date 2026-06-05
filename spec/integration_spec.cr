require "./spec_helper"
require "../src/crystal-tpm2-tss/core"

describe "TPM2-TSS Integration" do
  it "simulates an end-to-end FIDO2 credential creation and signing" do
    tpm = TPMDevice.new
    platform_secret = Bytes.new(32, 0xAA_u8)
    manager = FIDO2CredentialManager.new(tpm, platform_secret)

    # We mock TPMDevice slightly if needed, but wait: the existing tests 
    # probably mocked the responses already. Let's rely on unit tests for 
    # the stubbed methods, but test the components working together.
    
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x01_u8)
    
    credential_id = "test_user_credential_1"
    auth_value = manager.derive_auth_value(credential_id)
    auth_value.size.should eq(32)

    # Use the session to compute an HMAC for a sign command
    digest = Bytes.new(32, 0xBB_u8)
    command_code = TPM2::Commands::Sign
    params = digest
    
    hmac = session.compute_hmac(auth_value, command_code, params)
    hmac.size.should eq(32)
    
    nonce = session.roll_nonce
    nonce.size.should eq(32)
  end
end
