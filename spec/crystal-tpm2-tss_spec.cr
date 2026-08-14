require "./spec_helper"

describe Crystal::Tpm2::Tss do
  it "defines library version" do
    Crystal::Tpm2::Tss::VERSION.should eq("0.1.0")
  end
end
