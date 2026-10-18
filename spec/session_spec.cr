require "./spec_helper"

# Verifies [FUNC-004], [FUNC-007] / [TECH-003], [TECH-005], [TECH-007]
describe "Session" do
  it "initializes with CONTINUESESSION" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.attrs.should eq(TPM2::SessionAttributes::CONTINUESESSION)
    session.flushed?.should be_false
  end

  it "rolls nonce properly" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    nonce = session.roll_nonce
    nonce.size.should eq(32)
    session.nonce_caller.should eq(nonce)

    nonce2 = session.roll_nonce
    nonce2.should_not eq(nonce)
  end

  it "computes and verifies command and response HMACs" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x01_u8)
    session.update_nonce_tpm(Bytes.new(32, 0x02_u8))
    session.nonce_caller = Bytes.new(32, 0x03_u8)

    auth_value = Bytes.new(32, 0x04_u8)
    command_code = TPM2::Commands::Sign
    params = Bytes[0xAA, 0xBB]

    hmac = session.compute_hmac(auth_value, command_code, params)
    hmac.size.should eq(32)

    resp_hmac = session.compute_response_hmac(auth_value, 0_u32, params)
    session.verify_response_hmac(auth_value, 0_u32, params, resp_hmac).should be_true
    session.verify_response_hmac(auth_value, 0_u32, params, Bytes.new(32, 0xFF_u8)).should be_false
  end

  it "computes TCG TPM 2.0 Part 1 §19.6.5 cpHash and rpHash" do
    session = Session.new(0x02000001_u32, 0_u8, TPM2::Algorithms::SHA256)
    params = Bytes[0x01, 0x02, 0x03, 0x04]
    cp_hash = session.compute_cp_hash(TPM2::Commands::Sign, params, [0x81010001_u32])
    cp_hash.size.should eq(32)
    cp_hash.should_not eq(session.compute_cp_hash(TPM2::Commands::Sign, params))

    rp_hash = session.compute_rp_hash(0_u32, TPM2::Commands::Sign, params)
    rp_hash.size.should eq(32)
    rp_hash.should_not eq(session.compute_rp_hash(1_u32, TPM2::Commands::Sign, params))
  end

  # Verifies [FUNC-007] / [TECH-005], [TECH-007]
  describe ".start_auth_session, #policy_pcr, and #flush" do
    it "establishes a salted/bound session, extends PolicyPCR digest, auto-attaches auth frames, and flushes" do
      device = TPMDevice.new
      auth_val = Bytes.new(32, 0x11_u8)
      salt = Bytes.new(32, 0x22_u8)
      bind_key = Bytes.new(32, 0x33_u8)

      session = Session.start_auth_session(
        device,
        session_type: 0x01_u8,
        auth_value: auth_val,
        salt: salt,
        bind_key: bind_key
      )

      session.handle.should eq(0x02000001_u32)
      session.nonce_caller.size.should eq(32)
      session.nonce_tpm.size.should eq(32)
      session.session_key.size.should eq(32)

      pcr_digest = Bytes.new(32, 0x44_u8)
      digest_1 = session.policy_pcr(device, 0_u32, pcr_digest)
      digest_1.size.should eq(32)
      digest_1.should eq(session.policy_digest)

      digest_2 = session.policy_pcr(device, 7_u32, pcr_digest)
      digest_2.should_not eq(digest_1)

      cmd = TPMCommand.new(TPM2::Tag::NO_SESSIONS, TPM2::Commands::GetCapability)
      cmd.params = Bytes[0x00, 0x00, 0x00, 0x06]
      initial_nonce = session.nonce_caller
      resp = device.execute(cmd, session)
      resp.success?.should be_true
      cmd.tag.should eq(TPM2::Tag::SESSIONS)
      cmd.auth_area.empty?.should be_false
      resp.auth_area.empty?.should be_false
      first_cmd_nonce = session.nonce_caller
      first_cmd_nonce.should_not eq(initial_nonce)

      decoded_resp_auth = Tpm2bCodec.decode_auth_response(resp.auth_area)
      session.verify_response_hmac(Bytes.empty, resp.code, resp.params, decoded_resp_auth[:hmac]).should be_true

      resp_2 = device.execute(cmd, session)
      resp_2.success?.should be_true
      session.nonce_caller.should_not eq(first_cmd_nonce)

      session.flush(device)
      session.flushed?.should be_true
      expect_raises(TPMError) { session.policy_pcr(device, 0_u32, pcr_digest) }
    end
  end
end
