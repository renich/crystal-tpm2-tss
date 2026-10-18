require "./spec_helper"

# Verifies [FUNC-001] / [TECH-001]
describe Crystal::Tpm2::Tss do
  it "defines library version" do
    Crystal::Tpm2::Tss::VERSION.should eq("0.4.1")
  end
end
