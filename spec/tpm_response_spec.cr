require "./spec_helper"

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
    io = IO::Memory.new
    io.write_bytes(0x8002_u16, TPM2::ENDIAN) # tag
    io.write_bytes(33_u32, TPM2::ENDIAN)     # size
    io.write_bytes(0_u32, TPM2::ENDIAN)      # code

    # auth_size = 4 (session_count) + 4 (handle) + 2 (nonce size) + 4 (nonce) + 1 (attr) + 2 (hmac size) = 17
    io.write_bytes(17_u32, TPM2::ENDIAN)
    io.write_bytes(1_u32, TPM2::ENDIAN)
    io.write_bytes(0x02000000_u32, TPM2::ENDIAN)
    io.write_bytes(4_u16, TPM2::ENDIAN)
    io.write(Bytes[0xAA, 0xBB, 0xCC, 0xDD])
    io.write_byte(0x01_u8)
    io.write_bytes(0_u16, TPM2::ENDIAN)
    io.write(Bytes[0xCA, 0xFE])

    data = io.to_slice

    mock_session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    resp = TPMResponse.parse(data, mock_session)

    resp.tag.should eq(TPM2::Tag::SESSIONS)
    resp.auth_area.size.should eq(17)
    resp.params.should eq(Bytes[0xCA, 0xFE])
    mock_session.nonce_tpm.should eq(Bytes[0xAA, 0xBB, 0xCC, 0xDD])
  end
end
