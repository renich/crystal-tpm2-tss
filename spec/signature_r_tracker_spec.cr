require "./spec_helper"

describe "SignatureRTracker" do
  it "rejects non-positive max_size" do
    expect_raises(ArgumentError, "max_size must be positive") do
      SignatureRTracker.new(0)
    end
  end

  it "adds and tracks elements and detects reuse via check_and_add!" do
    tracker = SignatureRTracker.new(10)
    tracker.check_and_add!("AABBCC")
    tracker.includes?("AABBCC").should be_true
    tracker.includes?("DDEEFF").should be_false

    expect_raises(SecurityError, "ECDSA nonce reuse detected!") do
      tracker.check_and_add!("AABBCC")
    end
  end

  it "evicts oldest elements in true FIFO insertion order regardless of lexicographical order" do
    tracker = SignatureRTracker.new(4)
    tracker.add("FF")
    tracker.add("AA")
    tracker.add("BB")
    tracker.add("CC")
    tracker.add("DD")

    tracker.includes?("FF").should be_false
    tracker.includes?("AA").should be_false
    tracker.includes?("BB").should be_true
    tracker.includes?("CC").should be_true
    tracker.includes?("DD").should be_true
  end

  it "evicts properly when max_size is 1" do
    tracker = SignatureRTracker.new(1)
    tracker.add("first")
    tracker.add("second")
    tracker.includes?("first").should be_false
    tracker.includes?("second").should be_true
  end
end
