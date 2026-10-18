require "./spec_helper"

# Verifies [FUNC-006] / [TECH-005], [TECH-006]
describe Crystal::Tpm2::Tss::Tpm2bCodec do
  describe ".encode_auth_command and .decode_auth_command" do
    # Verifies [FUNC-006] / [TECH-006]
    it "roundtrips a TPMS_AUTH_COMMAND structure in big-endian wire format" do
      nonce = Bytes.new(32, 0xAA_u8)
      hmac = Bytes.new(32, 0xBB_u8)
      attrs = TPM2::SessionAttributes::CONTINUESESSION | TPM2::SessionAttributes::DECRYPT

      encoded = Tpm2bCodec.encode_auth_command(0x02000001_u32, nonce, attrs, hmac)
      decoded = Tpm2bCodec.decode_auth_command(encoded)

      decoded[:session_handle].should eq(0x02000001_u32)
      decoded[:nonce].should eq(nonce)
      decoded[:session_attributes].should eq(attrs)
      decoded[:hmac].should eq(hmac)
    end

    # Verifies [FUNC-006] / [TECH-005], [TECH-006]
    it "raises TPMError on truncated or trailing bytes in TPMS_AUTH_COMMAND" do
      expect_raises(TPMError) { Tpm2bCodec.decode_auth_command(Bytes[0x01, 0x02]) }

      valid = Tpm2bCodec.encode_auth_command(0x02000001_u32, Bytes[1_u8, 2_u8], 0x01_u8, Bytes[3_u8, 4_u8])
      expect_raises(TPMError) { Tpm2bCodec.decode_auth_command(valid[0, valid.size - 1]) }

      trailing = Bytes.new(valid.size + 1, 0_u8)
      valid.copy_to(trailing)
      expect_raises(TPMError) { Tpm2bCodec.decode_auth_command(trailing) }
    end
  end

  describe ".encode_auth_response and .decode_auth_response" do
    # Verifies [FUNC-006] / [TECH-006]
    it "roundtrips a TPMS_AUTH_RESPONSE structure in big-endian wire format" do
      nonce = Bytes.new(32, 0xCC_u8)
      hmac = Bytes.new(32, 0xDD_u8)
      attrs = TPM2::SessionAttributes::CONTINUESESSION

      encoded = Tpm2bCodec.encode_auth_response(nonce, attrs, hmac)
      decoded = Tpm2bCodec.decode_auth_response(encoded)

      decoded[:nonce].should eq(nonce)
      decoded[:session_attributes].should eq(attrs)
      decoded[:hmac].should eq(hmac)
    end

    # Verifies [FUNC-006] / [TECH-005], [TECH-006]
    it "raises TPMError on truncated or trailing bytes in TPMS_AUTH_RESPONSE" do
      expect_raises(TPMError) { Tpm2bCodec.decode_auth_response(Bytes.empty) }

      valid = Tpm2bCodec.encode_auth_response(Bytes[1_u8, 2_u8], 0x01_u8, Bytes[3_u8, 4_u8])
      expect_raises(TPMError) { Tpm2bCodec.decode_auth_response(valid[0, valid.size - 1]) }

      trailing = Bytes.new(valid.size + 2, 0xFF_u8)
      valid.copy_to(trailing)
      expect_raises(TPMError) { Tpm2bCodec.decode_auth_response(trailing) }
    end
  end

  describe ".encode_sensitive_create and .decode_sensitive_create" do
    # Verifies [FUNC-006] / [TECH-006]
    it "roundtrips a TPM2B_SENSITIVE_CREATE structure with user_auth and sensitive data" do
      auth = "fido2-pin-secret".to_slice
      data = Bytes[0x10_u8, 0x20_u8, 0x30_u8, 0x40_u8]

      encoded = Tpm2bCodec.encode_sensitive_create(auth, data)
      decoded = Tpm2bCodec.decode_sensitive_create(encoded)

      decoded[:user_auth].should eq(auth)
      decoded[:data].should eq(data)
    end

    # Verifies [FUNC-006] / [TECH-005], [TECH-006]
    it "raises TPMError when TPM2B_SENSITIVE_CREATE outer or inner length prefix is invalid" do
      expect_raises(TPMError) { Tpm2bCodec.decode_sensitive_create(Bytes[0x00, 0x10, 0x00]) }

      valid = Tpm2bCodec.encode_sensitive_create(Bytes[0x01_u8, 0x02_u8])
      trailing = Bytes.new(valid.size + 1, 0_u8)
      valid.copy_to(trailing)
      expect_raises(TPMError) { Tpm2bCodec.decode_sensitive_create(trailing) }
    end
  end

  describe ".encode_ecc_public and .decode_ecc_public" do
    # Verifies [FUNC-006] / [TECH-006]
    it "roundtrips a TPM2B_PUBLIC NIST P-256 structure with affine coordinates" do
      x = Bytes.new(32) { |idx| (idx + 1).to_u8 }
      y = Bytes.new(32) { |idx| (idx + 33).to_u8 }

      encoded = Tpm2bCodec.encode_ecc_public(x, y)
      decoded = Tpm2bCodec.decode_ecc_public(encoded)

      decoded[:name_alg].should eq(TPM2::Algorithms::SHA256)
      decoded[:object_attributes].should eq(0x00040072_u32)
      decoded[:scheme].should eq(TPM2::Algorithms::ECDSA)
      decoded[:curve_id].should eq(TPM2::ECCCurves::NIST_P256)
      decoded[:x].should eq(x)
      decoded[:y].should eq(y)
    end

    # Verifies [FUNC-006] / [TECH-005], [TECH-006]
    it "raises TPMError on malformed or truncated TPM2B_PUBLIC payloads" do
      x = Bytes.new(32, 0x11_u8)
      y = Bytes.new(32, 0x22_u8)
      valid = Tpm2bCodec.encode_ecc_public(x, y)

      expect_raises(TPMError) { Tpm2bCodec.decode_ecc_public(valid[0, 12]) }
      expect_raises(TPMError) { Tpm2bCodec.decode_ecc_public(valid[0, valid.size - 2]) }

      trailing = Bytes.new(valid.size + 1, 0_u8)
      valid.copy_to(trailing)
      expect_raises(TPMError) { Tpm2bCodec.decode_ecc_public(trailing) }
    end
  end

  describe ".encode_tpmt_signature and .decode_tpmt_signature" do
    # Verifies [FUNC-006] / [TECH-006]
    it "roundtrips a TPMT_SIGNATURE structure for NIST P-256 ECDSA" do
      r = Bytes.new(32, 0x55_u8)
      s = Bytes.new(32, 0x66_u8)
      sig = ECDSASignature.new(r, s)

      encoded = Tpm2bCodec.encode_tpmt_signature(sig)
      decoded = Tpm2bCodec.decode_tpmt_signature(encoded)

      decoded.r.should eq(r)
      decoded.s.should eq(s)
    end

    # Verifies [FUNC-006] / [TECH-005], [TECH-006]
    it "rejects all-zero ECDSA components or trailing bytes in TPMT_SIGNATURE" do
      zero_sig = ECDSASignature.new(Bytes.new(32, 0_u8), Bytes.new(32, 1_u8))
      encoded_zero = Tpm2bCodec.encode_tpmt_signature(zero_sig)
      expect_raises(TPMError) { Tpm2bCodec.decode_tpmt_signature(encoded_zero) }

      valid = Tpm2bCodec.encode_tpmt_signature(ECDSASignature.new(Bytes.new(32, 1_u8), Bytes.new(32, 2_u8)))
      trailing = Bytes.new(valid.size + 1, 0_u8)
      valid.copy_to(trailing)
      expect_raises(TPMError) { Tpm2bCodec.decode_tpmt_signature(trailing) }
    end
  end
end
