require "./spec_helper"

describe "Session" do
  it "initializes with CONTINUESESSION" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.attrs.should eq(TPM2::SessionAttributes::CONTINUESESSION)
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
end
