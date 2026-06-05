require "./spec_helper"

describe "TPMResponse" do
  it "parses response with NO_SESSIONS tag" do
    # 0x8001 (NO_SESSIONS), size 10, code 0
    data = Bytes[0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00]
    resp = TPMResponse.parse(data)
    resp.tag.should eq(TPM2::Tag::NO_SESSIONS)
    resp.size.should eq(10)
    resp.code.should eq(0)
    resp.params.size.should eq(0)
    resp.auth_area.size.should eq(0)
  end

  it "parses response with SESSIONS tag and extracts nonceTPM" do
    # 0x8002 (SESSIONS), size 31, code 0
    # Auth area size: 17 bytes -> [0x00, 0x00, 0x00, 0x11]
    # Session count: 1 -> [0x00, 0x00, 0x00, 0x01]
    # Handle: 0x02000000 -> [0x02, 0x00, 0x00, 0x00]
    # Nonce size: 4 bytes -> [0x00, 0x04]
    # Nonce: [0xAA, 0xBB, 0xCC, 0xDD]
    # Session Attr: 0x01
    # HMAC Size: 0
    io = IO::Memory.new
    io.write_bytes(0x8002_u16, TPM2::ENDIAN) # tag
    io.write_bytes(31_u32, TPM2::ENDIAN)     # size
    io.write_bytes(0_u32, TPM2::ENDIAN)      # code
    
    # auth_size = 4 (session_count) + 4 (handle) + 2 (nonce size) + 4 (nonce) + 1 (attr) + 2 (hmac size) = 17
    io.write_bytes(17_u32, TPM2::ENDIAN)
    io.write_bytes(1_u32, TPM2::ENDIAN)
    io.write_bytes(0x02000000_u32, TPM2::ENDIAN)
    io.write_bytes(4_u16, TPM2::ENDIAN)
    io.write(Bytes[0xAA, 0xBB, 0xCC, 0xDD])
    io.write_byte(0x01_u8)
    io.write_bytes(0_u16, TPM2::ENDIAN)
    
    data = io.to_slice
    
    mock_session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    resp = TPMResponse.parse(data, mock_session)
    
    resp.tag.should eq(TPM2::Tag::SESSIONS)
    resp.auth_area.size.should eq(17)
    
    # Check that mock_session nonce was updated
    mock_session.nonce_tpm.should eq(Bytes[0xAA, 0xBB, 0xCC, 0xDD])
  end
end
