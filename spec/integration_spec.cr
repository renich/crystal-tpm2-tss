require "./spec_helper"

describe "TPM2-TSS Integration" do
  it "executes an end-to-end FIDO2 credential creation, NV retrieval, and ECDSA signing flow" do
    tpm = TPMDevice.new
    platform_secret = Bytes.new(32, 0xAA_u8)
    manager = FIDO2CredentialManager.new(tpm, platform_secret)

    credential_id = "test_user_credential_1"
    credential = manager.get_or_create_credential(credential_id)
    credential.credential_id.should eq(credential_id)
    credential.persistent_handle.should eq(0x81010001_u32)

    retrieved = manager.get_or_create_credential(credential_id)
    retrieved.persistent_handle.should eq(credential.persistent_handle)
    retrieved.auth_value.should eq(credential.auth_value)

    digest = Bytes.new(32, 0xBB_u8)
    signature = retrieved.sign(digest)
    signature.r.size.should eq(32)
    signature.s.size.should eq(32)

    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x01_u8)
    nonce = session.roll_nonce
    nonce.size.should eq(32)

    sig_with_session = manager.sign(retrieved.persistent_handle, retrieved.auth_value, digest, session)
    sig_with_session.r.size.should eq(32)
    session.nonce_tpm.size.should eq(32)
  end
end
