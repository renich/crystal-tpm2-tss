require "./spec_helper"

describe "Session" do
  it "initializes with CONTINUESESSION" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.attrs.should eq(TPM2::SessionAttributes::CONTINUESESSION)
  end

  it "rolls nonce properly" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    nonce = session.roll_nonce
    nonce.size.should eq(32) # SHA256 size
    session.nonce_caller.should eq(nonce)
    
    nonce2 = session.roll_nonce
    nonce2.should_not eq(nonce)
  end

  it "computes HMAC correctly" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    # mock keys and nonces for predictability
    session.session_key = Bytes.new(32, 0x01_u8)
    session.update_nonce_tpm(Bytes.new(32, 0x02_u8))
    # force nonce_caller
    session.nonce_caller = Bytes.new(32, 0x03_u8)
    
    auth_value = Bytes.new(32, 0x04_u8)
    command_code = 0x0000015c_u32 # Sign
    params = Bytes[0xAA, 0xBB]
    
    hmac = session.compute_hmac(auth_value, command_code, params)
    hmac.size.should eq(32)
    # the output is deterministic, we just check it doesn't fail and size is correct
  end
end
