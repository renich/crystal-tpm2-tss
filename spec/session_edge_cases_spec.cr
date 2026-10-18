require "./spec_helper"

# Reopens Session to expose hash output size for specification testing.
class Crystal::Tpm2::Tss::Session
  def public_hash_output_size : Int32
    hash_output_size
  end
end

describe "Session Edge Cases" do
  it "supports SHA384 hash size" do
    session = Session.new(123_u32, 0_u8, TPM2::Algorithms::SHA384)
    session.public_hash_output_size.should eq(48)
    session.hash_alg_name.should eq("SHA384")
  end

  it "supports SHA512 hash size" do
    session = Session.new(123_u32, 0_u8, TPM2::Algorithms::SHA512)
    session.public_hash_output_size.should eq(64)
    session.hash_alg_name.should eq("SHA512")
  end

  it "raises ArgumentError on unsupported hash algorithm" do
    session = Session.new(123_u32, 0_u8, 0xFFFF_u16)
    expect_raises(ArgumentError, "Unsupported TPM hash algorithm") do
      session.public_hash_output_size
    end
  end
end
