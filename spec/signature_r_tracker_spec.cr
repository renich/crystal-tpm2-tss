require "./spec_helper"

describe "SignatureRTracker" do
  it "adds and tracks elements" do
    tracker = SignatureRTracker.new(10)
    tracker.add("AABBCC")
    tracker.includes?("AABBCC").should be_true
    tracker.includes?("DDEEFF").should be_false
  end

  it "trims elements when max size is reached" do
    tracker = SignatureRTracker.new(4)
    tracker.add("11")
    tracker.add("22")
    tracker.add("33")
    tracker.add("44")
    tracker.add("55") # exceeding size (4)
    
    # max_size is 4. When it reaches 5 (> 4), it keeps the latest half or sorted half.
    # As per implementation: sorted = @r_values.to_a.sort; @r_values = sorted[@max_size//2..-1].to_set
    # "11", "22", "33", "44", "55" -> sort -> "11", "22", "33", "44", "55"
    # size=4, 4//2 = 2. sorted[2..-1] -> "33", "44", "55"
    # So "11" and "22" should be gone, "33", "44", "55" should be kept
    tracker.includes?("11").should be_false
    tracker.includes?("33").should be_true
    tracker.includes?("55").should be_true
  end
end
