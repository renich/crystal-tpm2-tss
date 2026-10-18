require "./spec_helper"

# Verifies [FUNC-002], [FUNC-003], [FUNC-005] / [TECH-002], [TECH-005]
# Reopens FIDO2CredentialManager to expose internal credential helpers for specification testing.
class Crystal::Tpm2::Tss::FIDO2CredentialManager
  # Exposes `create_fido2_credential` for unit testing.
  def public_create_fido2_credential(id : String, auth : Bytes) : FIDO2Credential
    create_fido2_credential(id, auth)
  end

  # Exposes `credential_id_to_nv_index` for unit testing.
  def public_credential_id_to_nv_index(id : String) : UInt32
    @nv_store.credential_id_to_nv_index(id)
  end

  # Exposes `store_credential_metadata` for unit testing.
  def public_store_credential_metadata(index : UInt32, handle : UInt32, id : String) : Nil
    @nv_store.store_credential_metadata(index, handle, id)
  end

  # Exposes `resolve_nv_index` for unit testing.
  def public_resolve_nv_index(id : String, for_creation : Bool = false) : UInt32
    @nv_store.resolve_nv_index(id, for_creation)
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

    resp = TPMResponse.new(TPM2::Tag::SESSIONS, 78, 0)
    io = IO::Memory.new(68)
    io.write_bytes(32_u16, TPM2::ENDIAN)
    io.write(Bytes.new(32, 0x11_u8))
    io.write_bytes(32_u16, TPM2::ENDIAN)
    io.write(Bytes.new(32, 0x22_u8))
    resp.params = io.to_slice
    tpm.next_response = resp

    auth = Bytes.new(32, 0_u8)
    cred = manager.public_create_fido2_credential("test_id", auth)
    cred.should be_a(FIDO2Credential)
    cred.persistent_handle.should eq(manager.derive_persistent_handle("test_id"))
    (cred.persistent_handle & 0xFFFF0000_u32).should eq(0x81010000_u32)
  end

  it "derives distinct persistent handles and verifies real NIST P-256 ECDSA signatures" do
    tpm = TPMDevice.new
    manager = FIDO2CredentialManager.new(tpm)

    cred1 = manager.get_or_create_credential("fido2_cred_alpha")
    cred2 = manager.get_or_create_credential("fido2_cred_beta")
    cred1.persistent_handle.should_not eq(cred2.persistent_handle)

    pub_x, pub_y = cred1.public_key_xy
    pub_x.size.should eq(32)
    pub_y.size.should eq(32)
    pub_x.all?(&.zero?).should be_false
    pub_y.all?(&.zero?).should be_false

    digest = Bytes.new(32, 0x42_u8)
    sig = cred1.sign(digest)
    cred1.verify(digest, sig).should be_true
    cred1.verify(Bytes.new(32, 0x99_u8), sig).should be_false
    cred2.verify(digest, sig).should be_false
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
