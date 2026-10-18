module Crystal::Tpm2::Tss
  # Low-level OpenSSL 3.5 `libcrypto` C bindings for NIST P-256 key generation and ECDSA operations.
  @[Link("crypto")]
  lib LibCryptoP256
    fun evp_pkey_q_keygen = EVP_PKEY_Q_keygen(libctx : Void*, propq : LibC::Char*, type : LibC::Char*, ...) : Void*
    fun evp_pkey_free = EVP_PKEY_free(pkey : Void*) : Void
    fun evp_pkey_get_octet_string_param = EVP_PKEY_get_octet_string_param(
      pkey : Void*, key_name : LibC::Char*, buf : UInt8*, max_buf_sz : LibC::SizeT, out_sz : LibC::SizeT*,
    ) : LibC::Int
    fun evp_pkey_ctx_new_from_pkey = EVP_PKEY_CTX_new_from_pkey(
      libctx : Void*, pkey : Void*, propq : LibC::Char*,
    ) : Void*
    fun evp_pkey_ctx_free = EVP_PKEY_CTX_free(ctx : Void*) : Void
    fun evp_pkey_sign_init = EVP_PKEY_sign_init(ctx : Void*) : LibC::Int
    fun evp_pkey_sign = EVP_PKEY_sign(
      ctx : Void*, sig : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT,
    ) : LibC::Int
    fun evp_pkey_verify_init = EVP_PKEY_verify_init(ctx : Void*) : LibC::Int
    fun evp_pkey_verify = EVP_PKEY_verify(
      ctx : Void*, sig : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT,
    ) : LibC::Int
    fun d2i_ecdsa_sig = d2i_ECDSA_SIG(sig : Void**, pp : UInt8**, len : LibC::Long) : Void*
    fun i2d_ecdsa_sig = i2d_ECDSA_SIG(sig : Void*, pp : UInt8**) : LibC::Int
    fun ecdsa_sig_new = ECDSA_SIG_new : Void*
    fun ecdsa_sig_free = ECDSA_SIG_free(sig : Void*) : Void
    fun ecdsa_sig_get0 = ECDSA_SIG_get0(sig : Void*, pr : Void**, ps : Void**) : Void
    fun ecdsa_sig_set0 = ECDSA_SIG_set0(sig : Void*, r : Void*, s : Void*) : LibC::Int
    fun bn_bn2binpad = BN_bn2binpad(a : Void*, to : UInt8*, tolen : LibC::Int) : LibC::Int
    fun bn_bin2bn = BN_bin2bn(s : UInt8*, len : LibC::Int, ret : Void*) : Void*
    fun bn_free = BN_free(a : Void*) : Void
    fun d2i_pubkey = d2i_PUBKEY(a : Void**, pp : UInt8**, length : LibC::Long) : Void*
  end

  # OpenSSL 3.5-backed NIST P-256 elliptic curve keypair for ECDSA digest signing and verification.
  class P256Key
    # ASN.1 SubjectPublicKeyInfo DER header for an uncompressed 65-byte NIST P-256 public point.
    SPKI_P256_PREFIX = Bytes[
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]

    # 32-byte affine `x` coordinate of the NIST P-256 public key.
    getter x : Bytes

    # 32-byte affine `y` coordinate of the NIST P-256 public key.
    getter y : Bytes

    @pkey : Void*

    # Generates a new NIST P-256 keypair using OpenSSL `EVP_PKEY_Q_keygen`.
    def initialize : Nil
      @pkey = LibCryptoP256.evp_pkey_q_keygen(Pointer(Void).null, Pointer(LibC::Char).null, "EC", "P-256")
      raise TPMError.new("Failed to generate NIST P-256 keypair") if @pkey.null?
      @x, @y = extract_public_xy(@pkey)
    end

    # Initializes a public-only `P256Key` from 32-byte `x` and `y` affine coordinates.
    protected def initialize(@pkey : Void*, @x : Bytes, @y : Bytes) : Nil
    end

    # Constructs a public-only `P256Key` verifier from 32-byte `x` and `y` coordinates.
    def self.from_public_xy(x : Bytes, y : Bytes) : self
      raise TPMError.new("NIST P-256 public coordinates must be 32 bytes each") if x.size != 32 || y.size != 32
      der = build_spki_der(x, y)
      ptr = der.to_unsafe
      pkey = LibCryptoP256.d2i_pubkey(Pointer(Void*).null, pointerof(ptr), der.size.to_i64)
      raise TPMError.new("Failed to decode NIST P-256 public key coordinates") if pkey.null?
      new(pkey, x.dup, y.dup)
    end

    # Verifies an ECDSA signature against a digest using raw 32-byte `(x, y)` public coordinates.
    def self.verify_public_key(x : Bytes, y : Bytes, digest : Bytes, sig : ECDSASignature) : Bool
      return false if x.size != 32 || y.size != 32
      from_public_xy(x, y).verify_digest(digest, sig)
    rescue TPMError
      false
    end

    # Frees the underlying OpenSSL `EVP_PKEY` handle upon garbage collection.
    def finalize : Nil
      LibCryptoP256.evp_pkey_free(@pkey) unless @pkey.null?
    end

    # Signs a pre-hashed digest using NIST P-256 ECDSA and returns 32-byte `(r, s)` components.
    def sign_digest(digest : Bytes) : ECDSASignature
      ctx = LibCryptoP256.evp_pkey_ctx_new_from_pkey(Pointer(Void).null, @pkey, Pointer(LibC::Char).null)
      raise TPMError.new("Failed to allocate EVP_PKEY_CTX for signing") if ctx.null?

      begin
        der_to_ecdsa_sig(execute_evp_sign(ctx, digest))
      ensure
        LibCryptoP256.evp_pkey_ctx_free(ctx)
      end
    end

    # Verifies an `ECDSASignature` `(r, s)` pair against the given digest.
    def verify_digest(digest : Bytes, sig : ECDSASignature) : Bool
      return false if sig.r.size != 32 || sig.s.size != 32
      der_sig = ecdsa_sig_to_der(sig)
      ctx = LibCryptoP256.evp_pkey_ctx_new_from_pkey(Pointer(Void).null, @pkey, Pointer(LibC::Char).null)
      return false if ctx.null?

      begin
        return false if LibCryptoP256.evp_pkey_verify_init(ctx) <= 0
        LibCryptoP256.evp_pkey_verify(ctx, der_sig.to_unsafe, der_sig.size, digest.to_unsafe, digest.size) == 1
      ensure
        LibCryptoP256.evp_pkey_ctx_free(ctx)
      end
    end

    private def self.build_spki_der(x : Bytes, y : Bytes) : Bytes
      der = Bytes.new(91)
      SPKI_P256_PREFIX.copy_to(der)
      der[26] = 0x04_u8
      x.copy_to(der[27, 32])
      y.copy_to(der[59, 32])
      der
    end

    private def extract_public_xy(pkey : Void*) : Tuple(Bytes, Bytes)
      buf = Bytes.new(65)
      out_sz = 0_u64
      rc = LibCryptoP256.evp_pkey_get_octet_string_param(pkey, "pub", buf.to_unsafe, buf.size, pointerof(out_sz))
      if rc != 1 || out_sz != 65 || buf[0] != 0x04_u8
        raise TPMError.new("Failed to extract uncompressed P-256 public point")
      end
      {buf[1, 32].dup, buf[33, 32].dup}
    end

    private def execute_evp_sign(ctx : Void*, digest : Bytes) : Bytes
      raise TPMError.new("EVP_PKEY_sign_init failed") if LibCryptoP256.evp_pkey_sign_init(ctx) <= 0
      sig_len = 0_u64
      rc = LibCryptoP256.evp_pkey_sign(ctx, Pointer(UInt8).null, pointerof(sig_len), digest.to_unsafe, digest.size)
      raise TPMError.new("EVP_PKEY_sign length query failed") if rc <= 0 || sig_len == 0

      der_buf = Bytes.new(sig_len.to_i)
      rc = LibCryptoP256.evp_pkey_sign(ctx, der_buf.to_unsafe, pointerof(sig_len), digest.to_unsafe, digest.size)
      raise TPMError.new("EVP_PKEY_sign execution failed") if rc <= 0
      der_buf[0, sig_len.to_i]
    end

    private def der_to_ecdsa_sig(der : Bytes) : ECDSASignature
      ptr = der.to_unsafe
      sig = LibCryptoP256.d2i_ecdsa_sig(Pointer(Void*).null, pointerof(ptr), der.size.to_i64)
      raise TPMError.new("Failed to decode DER ECDSA_SIG") if sig.null?

      begin
        r_bn = Pointer(Void).null
        s_bn = Pointer(Void).null
        LibCryptoP256.ecdsa_sig_get0(sig, pointerof(r_bn), pointerof(s_bn))
        r_bytes = Bytes.new(32)
        s_bytes = Bytes.new(32)
        if LibCryptoP256.bn_bn2binpad(r_bn, r_bytes.to_unsafe, 32) != 32 ||
           LibCryptoP256.bn_bn2binpad(s_bn, s_bytes.to_unsafe, 32) != 32
          raise TPMError.new("BN_bn2binpad failed to serialize 32-byte ECDSA coordinates")
        end
        ECDSASignature.new(r_bytes, s_bytes)
      ensure
        LibCryptoP256.ecdsa_sig_free(sig)
      end
    end

    private def ecdsa_sig_to_der(sig : ECDSASignature) : Bytes
      raw_sig = LibCryptoP256.ecdsa_sig_new
      raise TPMError.new("Failed to allocate ECDSA_SIG") if raw_sig.null?

      begin
        populate_ecdsa_sig(raw_sig, sig)
        der_len = LibCryptoP256.i2d_ecdsa_sig(raw_sig, Pointer(UInt8*).null)
        raise TPMError.new("i2d_ECDSA_SIG failed") if der_len <= 0
        der_out = Bytes.new(der_len)
        out_ptr = der_out.to_unsafe
        LibCryptoP256.i2d_ecdsa_sig(raw_sig, pointerof(out_ptr))
        der_out
      ensure
        LibCryptoP256.ecdsa_sig_free(raw_sig)
      end
    end

    private def populate_ecdsa_sig(raw_sig : Void*, sig : ECDSASignature) : Nil
      r_bn = LibCryptoP256.bn_bin2bn(sig.r.to_unsafe, sig.r.size, Pointer(Void).null)
      s_bn = LibCryptoP256.bn_bin2bn(sig.s.to_unsafe, sig.s.size, Pointer(Void).null)
      return if !r_bn.null? && !s_bn.null? && LibCryptoP256.ecdsa_sig_set0(raw_sig, r_bn, s_bn) == 1

      LibCryptoP256.bn_free(r_bn) unless r_bn.null?
      LibCryptoP256.bn_free(s_bn) unless s_bn.null?
      raise TPMError.new("ECDSA_SIG_set0 failed")
    end
  end
end
