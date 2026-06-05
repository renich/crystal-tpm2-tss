require "./spec_helper"

class Session
  def public_hash_output_size
    hash_output_size
  end
end

describe "Session Edge Cases" do
  it "supports SHA384 hash size" do
    session = Session.new(123_u32, 0_u8, TPM2::Algorithms::SHA384)
    session.public_hash_output_size.should eq(48)
  end

  it "supports SHA512 hash size" do
    session = Session.new(123_u32, 0_u8, TPM2::Algorithms::SHA512)
    session.public_hash_output_size.should eq(64)
  end

  it "supports unexpected hash size fallback" do
    session = Session.new(123_u32, 0_u8, 0xFFFF_u16)
    session.public_hash_output_size.should eq(32)
  end
end
