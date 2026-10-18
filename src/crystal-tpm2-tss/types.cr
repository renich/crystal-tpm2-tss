module Crystal::Tpm2::Tss
  # TCG TPM 2.0 Library Specification protocol constants, command codes,
  # handles, algorithm identifiers, and attribute bitmasks.
  module TPM2
    # Canonical Big-Endian wire byte order mandated by the TCG TPM 2.0 specification.
    ENDIAN = IO::ByteFormat::BigEndian

    # TPM 2.0 Part 3 command codes (`TPM_CC`).
    module Commands
      # `TPM2_NV_ReadPublic` command code (`0x00000169`).
      NV_READPUBLIC = 0x00000169_u32
      # `TPM2_NV_DefineSpace` command code (`0x0000012a`).
      NV_DEFINESPACE = 0x0000012a_u32
      # `TPM2_NV_UndefineSpace` command code (`0x0000012b`).
      NV_UNDEFINESPACE = 0x0000012b_u32
      # `TPM2_NV_Read` command code (`0x0000014e`).
      NV_READ = 0x0000014e_u32
      # `TPM2_NV_Write` command code (`0x00000137`).
      NV_WRITE = 0x00000137_u32
      # `TPM2_CreatePrimary` command code (`0x00000131`).
      CreatePrimary = 0x00000131_u32
      # `TPM2_Create` command code (`0x00000153`).
      Create = 0x00000153_u32
      # `TPM2_Load` command code (`0x00000157`).
      Load = 0x00000157_u32
      # `TPM2_FlushContext` command code (`0x00000165`).
      FlushContext = 0x00000165_u32
      # `TPM2_EvictControl` command code (`0x00000120`).
      EvictControl = 0x00000120_u32
      # `TPM2_Sign` command code (`0x0000015c`).
      Sign = 0x0000015c_u32
      # `TPM2_ReadPublic` command code (`0x00000173`).
      ReadPublic = 0x00000173_u32
      # `TPM2_StartAuthSession` command code (`0x00000176`).
      StartAuthSession = 0x00000176_u32
      # `TPM2_ContextSave` command code (`0x00000162`).
      ContextSave = 0x00000162_u32
      # `TPM2_ContextLoad` command code (`0x00000161`).
      ContextLoad = 0x00000161_u32
      # `TPM2_PCR_Read` command code (`0x0000017e`).
      PCR_READ = 0x0000017e_u32
      # `TPM2_GetCapability` command code (`0x0000017a`).
      GetCapability = 0x0000017a_u32
    end

    # TPM 2.0 architectural permanent handles (`TPM_RH` / `TPM_RS`).
    module Handles
      # Storage hierarchy owner handle (`TPM_RH_OWNER`).
      OWNER = 0x40000001_u32
      # Null hierarchy handle (`TPM_RH_NULL`).
      NULL = 0x40000007_u32
      # Password authorization session handle (`TPM_RS_PW`).
      PW = 0x40000009_u32
      # Dictionary attack lockout handle (`TPM_RH_LOCKOUT`).
      LOCKOUT = 0x4000000a_u32
      # Endorsement hierarchy handle (`TPM_RH_ENDORSEMENT`).
      ENDORSEMENT = 0x4000000b_u32
      # Platform hierarchy handle (`TPM_RH_PLATFORM`).
      PLATFORM = 0x4000000c_u32
    end

    # TPM 2.0 Part 2 algorithm identifiers (`TPM_ALG_ID`).
    module Algorithms
      # Error algorithm identifier (`TPM_ALG_ERROR`).
      ERROR = 0x0000_u16
      # RSA asymmetric algorithm (`TPM_ALG_RSA`).
      RSA = 0x0001_u16
      # AES symmetric block cipher (`TPM_ALG_AES`).
      AES = 0x0006_u16
      # SHA-256 cryptographic hash (`TPM_ALG_SHA256`).
      SHA256 = 0x000b_u16
      # SHA-384 cryptographic hash (`TPM_ALG_SHA384`).
      SHA384 = 0x000c_u16
      # SHA-512 cryptographic hash (`TPM_ALG_SHA512`).
      SHA512 = 0x000d_u16
      # Null algorithm selector (`TPM_ALG_NULL`).
      NULL = 0x0010_u16
      # Elliptic Curve Digital Signature Algorithm (`TPM_ALG_ECDSA`).
      ECDSA = 0x0018_u16
      # Elliptic Curve Cryptography key type (`TPM_ALG_ECC`).
      ECC = 0x0023_u16
      # Cipher Feedback symmetric mode (`TPM_ALG_CFB`).
      CFB = 0x0043_u16
    end

    # TPM 2.0 elliptic curve identifiers (`TPM_ECC_CURVE`).
    module ECCCurves
      # NIST P-256 (`secp256r1` / `prime256v1`) curve identifier.
      NIST_P256 = 0x0003_u16
      # NIST P-384 (`secp384r1`) curve identifier.
      NIST_P384 = 0x0004_u16
    end

    # TPM 2.0 object attribute flags (`TPMA_OBJECT`).
    module ObjectAttributes
      # Object hierarchy cannot change (`fixedTPM`).
      FIXEDTPM = 0x00000002_u32
      # Object does not persist across `TPM2_Clear` (`stClear`).
      STCLEAR = 0x00000004_u32
      # Object parent handle cannot change (`fixedParent`).
      FIXEDPARENT = 0x00000010_u32
      # TPM generated sensitive key material (`sensitiveDataOrigin`).
      SENSITIVEDATAORIGIN = 0x00000020_u32
      # User role authorization via HMAC or password (`userWithAuth`).
      USER_WITH_AUTH = 0x00000040_u32
      # Admin role requires policy session (`adminWithPolicy`).
      ADMIN_WITH_POLICY = 0x00000080_u32
      # Exempt from dictionary attack lockout (`noDA`).
      NODA = 0x00000400_u32
      # Key usage restricted to known TPM structures (`restricted`).
      RESTRICTED = 0x00010000_u32
      # Key may decrypt or unwrap objects (`decrypt`).
      DECRYPT = 0x00020000_u32
      # Key may sign digests or encrypt data (`sign` / `encrypt`).
      SIGN_ENCRYPT = 0x00040000_u32
    end

    # TPM 2.0 session attribute flags (`TPMA_SESSION`).
    module SessionAttributes
      # Keep session active after command completion (`continueSession`).
      CONTINUESESSION = 0x01_u8
      # Session is exclusive for command auditing (`auditExclusive`).
      AUDITEXCLUSIVE = 0x02_u8
      # Reset audit digest before command execution (`auditReset`).
      AUDITRESET = 0x04_u8
      # First command parameter is encrypted (`decrypt`).
      DECRYPT = 0x20_u8
      # First response parameter is encrypted (`encrypt`).
      ENCRYPT = 0x40_u8
      # Session is used for command auditing (`audit`).
      AUDIT = 0x80_u8
    end

    # TPM 2.0 command/response structure tags (`TPM_ST`).
    module Tag
      # Command or response carries no authorization sessions (`TPM_ST_NO_SESSIONS`).
      NO_SESSIONS = 0x8001_u16
      # Command or response carries one or more authorization sessions (`TPM_ST_SESSIONS`).
      SESSIONS = 0x8002_u16
    end

    # TPM 2.0 response codes (`TPM_RC`).
    module ResponseCodes
      # NV index is already defined (`TPM_RC_NV_DEFINED`).
      NV_DEFINED = 0x0000014c_u32
    end
  end

  # Raised when a TPM 2.0 command returns an error code or response framing is invalid.
  class TPMError < Exception
    # Raw TPM 2.0 response code (`TPM_RC`), or `0` if transport/framing error.
    getter code : UInt32

    # Initializes a new `TPMError` with a message and optional `TPM_RC` code.
    def initialize(msg : String, @code : UInt32 = 0_u32) : Nil
      super(msg)
    end
  end

  # Raised when a cryptographic or protocol security invariant is violated.
  class SecurityError < Exception
  end

  # Value container representing an ECDSA `(r, s)` signature pair.
  struct ECDSASignature
    # Big-endian `r` signature component bytes.
    getter r : Bytes

    # Big-endian `s` signature component bytes.
    getter s : Bytes

    # Initializes an immutable `ECDSASignature` from `r` and `s` byte slices.
    def initialize(@r : Bytes, @s : Bytes) : Nil
    end
  end
end
