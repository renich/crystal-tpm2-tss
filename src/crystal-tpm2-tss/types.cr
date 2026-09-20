module Crystal::Tpm2::Tss
  module TPM2
    ENDIAN = IO::ByteFormat::BigEndian

    module Commands
      NV_READPUBLIC    = 0x00000169_u32
      NV_DEFINESPACE   = 0x0000012a_u32
      NV_UNDEFINESPACE = 0x0000012b_u32
      NV_READ          = 0x0000014e_u32
      NV_WRITE         = 0x00000137_u32
      CreatePrimary    = 0x00000131_u32
      Create           = 0x00000153_u32
      Load             = 0x00000157_u32
      FlushContext     = 0x00000165_u32
      EvictControl     = 0x00000120_u32
      Sign             = 0x0000015c_u32
      StartAuthSession = 0x00000176_u32
      ContextSave      = 0x00000162_u32
      ContextLoad      = 0x00000161_u32
      PCR_READ         = 0x0000017e_u32
      GetCapability    = 0x0000017a_u32
    end

    module Handles
      OWNER       = 0x40000001_u32
      NULL        = 0x40000007_u32
      PW          = 0x40000009_u32
      LOCKOUT     = 0x4000000a_u32
      ENDORSEMENT = 0x4000000b_u32
      PLATFORM    = 0x4000000c_u32
    end

    module Algorithms
      ERROR  = 0x0000_u16
      RSA    = 0x0001_u16
      SHA256 = 0x000b_u16
      SHA384 = 0x000c_u16
      SHA512 = 0x000d_u16
      NULL   = 0x0010_u16
      ECC    = 0x0023_u16
      ECDSA  = 0x0018_u16
      AES    = 0x0006_u16
    end

    module ECCCurves
      NIST_P256 = 0x0003_u16
      NIST_P384 = 0x0004_u16
    end

    module ObjectAttributes
      FIXEDTPM            = 0x00000002_u32
      STCLEAR             = 0x00000004_u32
      FIXEDPARENT         = 0x00000010_u32
      SENSITIVEDATAORIGIN = 0x00000020_u32
      USER_WITH_AUTH      = 0x00000040_u32
      ADMIN_WITH_POLICY   = 0x00000080_u32
      NODA                = 0x00000400_u32
      RESTRICTED          = 0x00010000_u32
      DECRYPT             = 0x00020000_u32
      SIGN_ENCRYPT        = 0x00040000_u32
    end

    module SessionAttributes
      CONTINUESESSION = 0x01_u8
      AUDITEXCLUSIVE  = 0x02_u8
      AUDITRESET      = 0x04_u8
      DECRYPT         = 0x20_u8
      ENCRYPT         = 0x40_u8
      AUDIT           = 0x80_u8
    end

    module Tag
      NO_SESSIONS = 0x8001_u16
      SESSIONS    = 0x8002_u16
    end

    module ResponseCodes
      NV_DEFINED = 0x0000014c_u32
    end
  end

  class TPMError < Exception
    getter code : UInt32

    def initialize(msg : String, @code = 0_u32)
      super(msg)
    end
  end

  class SecurityError < Exception
  end

  class ECDSASignature
    getter r : Bytes
    getter s : Bytes

    def initialize(@r : Bytes, @s : Bytes)
    end
  end
end
