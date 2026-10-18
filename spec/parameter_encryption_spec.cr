require "./spec_helper"

# Verifies [FUNC-004] / [TECH-003], [TECH-005]
describe "ParameterEncryption" do
  it "encrypts and decrypts parameters using KDFa XOR" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x01_u8)
    session.update_nonce_tpm(Bytes.new(32, 0x02_u8))
    session.nonce_caller = Bytes.new(32, 0x03_u8)

    plaintext = Bytes[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    ciphertext = ParameterEncryption.encrypt(plaintext, session, "XOR")

    ciphertext.size.should eq(plaintext.size)
    ciphertext.should_not eq(plaintext)

    decrypted = ParameterEncryption.decrypt(ciphertext, session, "XOR")
    decrypted.should eq(plaintext)
  end

  it "encrypts and decrypts parameters using KDFa AES-CFB" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x11_u8)
    session.update_nonce_tpm(Bytes.new(32, 0x22_u8))
    session.nonce_caller = Bytes.new(32, 0x33_u8)

    plaintext = "Sensitive FIDO2 TPM2 parameter payload".to_slice
    ciphertext = ParameterEncryption.encrypt(plaintext, session, "AES-CFB")

    ciphertext.size.should eq(plaintext.size)
    ciphertext.should_not eq(plaintext)

    decrypted = ParameterEncryption.decrypt(ciphertext, session, "CFB")
    decrypted.should eq(plaintext)
  end

  it "handles empty data cleanly" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x01_u8)
    ParameterEncryption.encrypt(Bytes.empty, session).should eq(Bytes.empty)
    ParameterEncryption.decrypt(Bytes.empty, session).should eq(Bytes.empty)
  end

  it "raises SecurityError when session key is empty" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    expect_raises(SecurityError, "Session key is required") do
      ParameterEncryption.encrypt(Bytes[0x01], session)
    end
  end

  it "raises SecurityError when session nonces are empty" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x01_u8)
    expect_raises(SecurityError, "Session nonces are required") do
      ParameterEncryption.encrypt(Bytes[0x01], session, "XOR")
    end
  end

  it "raises ArgumentError on unsupported encryption algorithm" do
    session = Session.new(0x02000000_u32, 0_u8, TPM2::Algorithms::SHA256)
    session.session_key = Bytes.new(32, 0x01_u8)
    expect_raises(ArgumentError, "Unsupported parameter encryption algorithm") do
      ParameterEncryption.encrypt(Bytes[0x01], session, "DES")
    end
  end
end
