require "./spec_helper"

# Reopens FIDO2CredentialManager to expose internal credential helpers for specification testing.
class Crystal::Tpm2::Tss::FIDO2CredentialManager
  def public_create_fido2_credential(id : String, auth : Bytes) : FIDO2Credential
    create_fido2_credential(id, auth)
  end

  def public_credential_id_to_nv_index(id : String) : UInt32
    credential_id_to_nv_index(id)
  end

  def public_store_credential_metadata(index : UInt32, handle : UInt32, id : String) : Nil
    store_credential_metadata(index, handle, id)
  end

  def public_resolve_nv_index(id : String, for_creation : Bool = false) : UInt32
    resolve_nv_index(id, for_creation)
  end
end

describe "FIDO2CredentialManager" do
  it "derives deterministic auth values" do
    tpm = TPMDevice.new
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

  it "rejects all-zero ECDSA signature components" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)

    sig_params = IO::Memory.new
    sig_params.write_bytes(TPM2::Algorithms::ECDSA, TPM2::ENDIAN)
    sig_params.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
    sig_params.write_bytes(32_u16, TPM2::ENDIAN)
    sig_params.write(Bytes.new(32, 0x00_u8))
    sig_params.write_bytes(32_u16, TPM2::ENDIAN)
    sig_params.write(Bytes.new(32, 0xBB_u8))

    resp = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 0, 0)
    resp.params = sig_params.to_slice
    tpm.next_response = resp

    expect_raises(TPMError, "Invalid ECDSA signature component") do
      manager.sign(12345_u32, Bytes.new(32, 0x02_u8), Bytes.new(32, 0x01_u8))
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
    cred.persistent_handle.should eq(0x81010001_u32)
  end

  it "resolves NV index collisions using linear probing" do
    tpm = TPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)

    base_index = manager.public_credential_id_to_nv_index("colliding_cred")
    manager.public_store_credential_metadata(base_index, 0x81010009_u32, "other_cred_occupying_slot")

    probed_index = manager.public_resolve_nv_index("colliding_cred", for_creation: true)
    probed_index.should eq(base_index + 1_u32)
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
    index1.should_not eq(0x01C00000_u32)
  end

  it "handles failure in sign gracefully" do
    tpm = MockTPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)
    tpm.next_response = TPMResponse.new(TPM2::Tag::NO_SESSIONS, 10, 0x0143)

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
