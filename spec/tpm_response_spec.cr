require "./spec_helper"

# Verifies [FUNC-001], [FUNC-002], [FUNC-006] / [TECH-001], [TECH-002], [TECH-005], [TECH-006]
describe "TPMResponse" do
  it "raises TPMError when response buffer is shorter than 10 bytes" do
    expect_raises(TPMError, "Response too short") do
      TPMResponse.parse(Bytes[0x80, 0x01, 0x00])
    end
  end

  it "parses response with NO_SESSIONS tag and extracts parameters" do
    data = Bytes[0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD]
    resp = TPMResponse.parse(data)
    resp.tag.should eq(TPM2::Tag::NO_SESSIONS)
    resp.size.should eq(12)
    resp.code.should eq(0)
    resp.params.should eq(Bytes[0xDE, 0xAD])
    resp.auth_area.size.should eq(0)
  end

  it "parses response with SESSIONS tag and extracts nonceTPM and params" do
    auth_resp = Tpm2bCodec.encode_auth_response(Bytes[0xAA, 0xBB, 0xCC, 0xDD], 0x01_u8, Bytes.empty)
    io = IO::Memory.new
    io.write_bytes(0x8002_u16, TPM2::ENDIAN)
    io.write_bytes((16 + auth_resp.size).to_u32, TPM2::ENDIAN)
    io.write_bytes(0_u32, TPM2::ENDIAN)
    io.write_bytes(auth_resp.size.to_u32, TPM2::ENDIAN)
    io.write(auth_resp)
    io.write(Bytes[0xCA, 0xFE])

    mock_session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    resp = TPMResponse.parse(io.to_slice, mock_session)

    resp.tag.should eq(TPM2::Tag::SESSIONS)
    resp.auth_area.size.should eq(auth_resp.size)
    resp.params.should eq(Bytes[0xCA, 0xFE])
    mock_session.nonce_tpm.should eq(Bytes[0xAA, 0xBB, 0xCC, 0xDD])
  end

  it "validates ReadPublic payload bounds and decodes both compact and full TPM2B_PUBLIC formats" do
    expect_raises(TPMError, "Truncated ReadPublic response payload") do
      TPMResponse.parse_read_public_xy(Bytes.new(10, 0_u8))
    end

    bad_compact = Bytes.new(68, 0_u8)
    expect_raises(TPMError, "Invalid ReadPublic X coordinate length") do
      TPMResponse.parse_read_public_xy(bad_compact)
    end

    expected_x = Bytes.new(32, 0x33_u8)
    expected_y = Bytes.new(32, 0x44_u8)
    full_pub = Tpm2bCodec.encode_ecc_public(expected_x, expected_y)
    parsed_x, parsed_y = TPMResponse.parse_read_public_xy(full_pub)
    parsed_x.should eq(expected_x)
    parsed_y.should eq(expected_y)
  end
end
