require "./spec_helper"

class FIDO2CredentialManager
  def public_create_fido2_credential(id : String, auth : Bytes)
    create_fido2_credential(id, auth)
  end
  def public_credential_id_to_nv_index(id : String)
    credential_id_to_nv_index(id)
  end
end

describe "FIDO2CredentialManager" do
  it "derives deterministic auth values" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)
    auth1 = manager.derive_auth_value("test_credential_1")
    auth2 = manager.derive_auth_value("test_credential_1")
    auth3 = manager.derive_auth_value("test_credential_2")
    auth1.should eq(auth2)
    auth1.should_not eq(auth3)
  end

  it "rejects reused r values on signing" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)

    sig_params = IO::Memory.new
    sig_params.write_bytes(TPM2::Algorithms::ECDSA, TPM2::ENDIAN)
    sig_params.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
    sig_params.write_bytes(32_u16, TPM2::ENDIAN)
    sig_params.write(Bytes.new(32, 0xAA_u8))
    sig_params.write_bytes(32_u16, TPM2::ENDIAN)
    sig_params.write(Bytes.new(32, 0xBB_u8))

    resp = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 0, 0)
    resp.params = sig_params.to_slice
    tpm.next_response = resp

    digest = Bytes.new(32, 0x01_u8)
    auth = Bytes.new(32, 0x02_u8)

    sig = manager.sign(12345_u32, auth, digest)
    sig.r.should eq(Bytes.new(32, 0xAA_u8))

    expect_raises(SecurityError, "ECDSA nonce reuse detected!") do
      manager.sign(12345_u32, auth, digest)
    end
  end

  it "calls create_fido2_credential successfully" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)
    
    resp = TPMResponse.new(TPM2::Tag::SESSIONS, 14, 0)
    io = IO::Memory.new
    io.write_bytes(12345_u32, TPM2::ENDIAN)
    resp.params = io.to_slice
    tpm.next_response = resp

    auth = Bytes.new(32, 0_u8)
    cred = manager.public_create_fido2_credential("test_id", auth)
    cred.should be_a(FIDO2Credential)
  end

  it "credential_id_to_nv_index generates correct indices" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)
    
    index1 = manager.public_credential_id_to_nv_index("cred1")
    index2 = manager.public_credential_id_to_nv_index("cred1")
    index3 = manager.public_credential_id_to_nv_index("cred2")
    
    index1.should eq(index2)
    index1.should_not eq(index3)
    (index1 & 0xFF000000_u32).should eq(0x01000000_u32)
  end

  it "handles failure in sign gracefully" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)
    tpm.next_response = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0x0143) # TPM error code
    
    digest = Bytes.new(32, 0x01_u8)
    auth = Bytes.new(32, 0x02_u8)

    expect_raises(TPMError, "Sign failed") do
      manager.sign(12345_u32, auth, digest)
    end
  end

  it "handles create_primary_key failure" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)
    tpm.next_response = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0x0143)
    
    auth = Bytes.new(32, 0_u8)
    expect_raises(TPMError, "CreatePrimary failed") do
      manager.public_create_fido2_credential("test_id", auth)
    end
  end
end
