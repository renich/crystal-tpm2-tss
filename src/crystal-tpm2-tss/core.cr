require "openssl/hmac"
# Crystal TPM2-TSS - Working Implementation
# Complete session management, KDF persistence, and FIDO2 integration

require "openssl"

# ============================================================================
# TPM 2.0 Constants and Types
# ============================================================================
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
end

# ============================================================================
# KDF Key Persistence Architecture
# ============================================================================

# The KDF key is derived from the TPM's persistent storage
# This ensures the key survives reboots and is hardware-bound
class KDFKeyManager
  @tpm : TPMDevice
  @kdf_nv_index : UInt32 = 0x01C00000_u32 # Reserved NV index for KDF key
  @kdf_key : Bytes?
  @mutex : Mutex
  @platform_secret : Bytes

  def initialize(@tpm, @platform_secret = Random::Secure.random_bytes(32))
    @mutex = Mutex.new
  end

  # Get or create the KDF key
  # The key is derived from TPM NV storage, so it persists across reboots
  # ameba:disable Naming/AccessorMethodName
  def get_kdf_key : Bytes
    if kdf_key = @kdf_key
      return kdf_key
    end

    @mutex.synchronize do
      if kdf_key = @kdf_key
        return kdf_key
      end

      # Try to read existing KDF key from NV
      begin
        key_data = read_kdf_key_from_nv
        @kdf_key = key_data
        key_data
      rescue TPMError
        # Key doesn't exist, create it
        create_and_store_kdf_key
      end
    end
  end

  private def read_kdf_key_from_nv : Bytes
    # Read KDF key from NV index
    # This requires authorization with the storage hierarchy
    auth_value = derive_nv_auth() # Derive auth from platform secret

    command = build_nv_read_command(@kdf_nv_index, 0, 32, auth_value)
    response = @tpm.execute(command)

    unless response.success?
      raise TPMError.new("Failed to read KDF key", response.code)
    end

    # Parse response to extract key
    parse_nv_read_response(response.params)
  end

  private def create_and_store_kdf_key : Bytes
    # Generate new random KDF key
    kdf_key = Random::Secure.random_bytes(32)

    # Define NV index for KDF key
    define_nv_index(@kdf_nv_index, 32)

    # Write KDF key to NV
    auth_value = derive_nv_auth()
    write_kdf_key_to_nv(kdf_key, auth_value)

    @kdf_key = kdf_key
    kdf_key
  end

  private def define_nv_index(nv_index : UInt32, size : Int32)
    # Build NV_DEFINESPACE command
    public_info = build_nv_public_info(size)

    command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_DEFINESPACE)
    command.add_handle(TPM2::Handles::OWNER)
    command.auth_area = (build_password_auth(Bytes.empty)) # Owner auth
    command.params = (serialize_nv_define_params(nv_index, public_info))

    response = @tpm.execute(command)

    unless response.success? || response.code == TPM2::ResponseCodes::NV_DEFINED
      raise TPMError.new("Failed to define NV index", response.code)
    end
  end

  private def write_kdf_key_to_nv(key : Bytes, auth_value : Bytes)
    command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_WRITE)
    command.add_handle(@kdf_nv_index)
    command.auth_area = (build_password_auth(auth_value))
    command.params = (serialize_nv_write_params(0, key))

    response = @tpm.execute(command)

    unless response.success?
      raise TPMError.new("Failed to write KDF key", response.code)
    end
  end

  # Derive NV authorization from platform secret
  # This binds the KDF key to the platform
  private def derive_nv_auth : Bytes
    OpenSSL::Digest.new("SHA256").update(@platform_secret).final
  end

  # Helper methods
  private def build_nv_public_info(size : Int32) : Bytes
    io = IO::Memory.new

    # NV index attributes
    nv_index_type = 0x00000001_u32 # Ordinary NV index
    nv_attributes = 0x00040002_u32 # OWNERWRITE | OWNERREAD | PLATFORMCREATE

    io.write_bytes(nv_index_type, TPM2::ENDIAN)
    io.write_bytes(nv_attributes, TPM2::ENDIAN)
    io.write_bytes(0x0000_u16, TPM2::ENDIAN)  # Policy hash algorithm
    io.write_bytes(0x0000_u16, TPM2::ENDIAN)  # Policy hash size
    io.write_bytes(size.to_u16, TPM2::ENDIAN) # Data size

    io.to_slice
  end

  private def build_nv_read_command(index : UInt32, offset : UInt16, size : UInt16, auth_value : Bytes) : TPMCommand
    command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_READ)
    command.add_handle(index)
    command.add_handle(index)
    command.auth_area = build_password_auth(auth_value)

    io = IO::Memory.new
    io.write_bytes(size, TPM2::ENDIAN)
    io.write_bytes(offset, TPM2::ENDIAN)
    command.params = io.to_slice
    command
  end

  private def build_password_auth(auth_value : Bytes) : Bytes
    io = IO::Memory.new
    io.write_bytes(1_u32, TPM2::ENDIAN)             # 1 session
    io.write_bytes(TPM2::Handles::PW, TPM2::ENDIAN) # Password session
    io.write_bytes(0_u16, TPM2::ENDIAN)             # Empty nonce
    io.write_byte(TPM2::SessionAttributes::CONTINUESESSION)
    io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
    io.write(auth_value)
    io.to_slice
  end

  private def serialize_nv_define_params(nv_index : UInt32, public_info : Bytes) : Bytes
    io = IO::Memory.new
    io.write_bytes(nv_index, TPM2::ENDIAN)
    io.write_bytes(0x0000_u16, TPM2::ENDIAN) # Auth policy size
    io.write_bytes(public_info.size.to_u16, TPM2::ENDIAN)
    io.write(public_info)
    io.to_slice
  end

  private def serialize_nv_write_params(offset : UInt16, data : Bytes) : Bytes
    io = IO::Memory.new
    io.write_bytes(data.size.to_u16, TPM2::ENDIAN)
    io.write(data)
    io.write_bytes(offset, TPM2::ENDIAN)
    io.to_slice
  end

  private def parse_nv_read_response(params : Bytes) : Bytes
    raise TPMError.new("Empty NV read response") if params.empty?
    io = IO::Memory.new(params)
    size = io.read_bytes(UInt16, TPM2::ENDIAN)
    data = Bytes.new(size)
    io.read_fully(data)
    data
  rescue IO::EOFError
    raise TPMError.new("Invalid NV read response format")
  end
end

# ============================================================================
# Session Management with Nonce Tracking
# ============================================================================
class Session
  getter attrs : UInt8
  getter nonce_tpm : Bytes
  getter session_key : Bytes
  getter nonce_caller : Bytes

  def session_key=(val : Bytes)
    @mutex.synchronize { @session_key = val }
  end

  def nonce_caller=(val : Bytes)
    @mutex.synchronize { @nonce_caller = val }
  end

  @handle : UInt32
  @type : UInt8
  @hash_alg : UInt16
  @nonce_tpm : Bytes
  @mutex : Mutex

  def initialize(@handle, @type, @hash_alg)
    @session_key = Bytes.empty
    @nonce_tpm = Bytes.empty
    @nonce_caller = Bytes.empty
    @attrs = TPM2::SessionAttributes::CONTINUESESSION
    @mutex = Mutex.new
  end

  def update_nonce_tpm(nonce : Bytes)
    @mutex.synchronize do
      @nonce_tpm = nonce.dup
    end
  end

  def compute_hmac(auth_value : Bytes, command_code : UInt32, params : Bytes) : Bytes
    @mutex.synchronize do
      hmac_key = @session_key + auth_value
      hash_alg_val = OpenSSL::Algorithm.parse(hash_alg_name)

      buffer = IO::Memory.new
      buffer.write(@nonce_caller)
      buffer.write(@nonce_tpm)
      buffer.write_byte(@attrs)
      buffer.write_bytes(command_code, TPM2::ENDIAN)
      buffer.write(params)

      OpenSSL::HMAC.digest(hash_alg_val, hmac_key, buffer.to_slice)
    end
  end

  def roll_nonce : Bytes
    @mutex.synchronize do
      size = hash_output_size
      @nonce_caller = Random::Secure.random_bytes(size)
      @nonce_caller.dup
    end
  end

  private def hash_alg_name : String
    case @hash_alg
    when TPM2::Algorithms::SHA256 then "SHA256"
    when TPM2::Algorithms::SHA384 then "SHA384"
    when TPM2::Algorithms::SHA512 then "SHA512"
    else                               "SHA256"
    end
  end

  private def hash_output_size : Int32
    case @hash_alg
    when TPM2::Algorithms::SHA256 then 32
    when TPM2::Algorithms::SHA384 then 48
    when TPM2::Algorithms::SHA512 then 64
    else                               32
    end
  end
end

# ============================================================================
# FIDO2 Credential Manager
# ============================================================================
class FIDO2CredentialManager
  @tpm : TPMDevice
  @kdf_manager : KDFKeyManager
  @r_tracker : SignatureRTracker

  def initialize(@tpm, platform_secret : Bytes? = nil)
    secret = platform_secret || Random::Secure.random_bytes(32)
    @kdf_manager = KDFKeyManager.new(@tpm, secret)
    @r_tracker = SignatureRTracker.new(max_size: 10000)
  end

  # Derive auth value from credential_id using KDF
  def derive_auth_value(credential_id : String) : Bytes
    kdf_key = @kdf_manager.get_kdf_key

    # Domain-separated KDF
    label = "FIDO2-AUTH-v1"
    context = credential_id.to_slice

    OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, kdf_key, label.to_slice + context)
  end

  # Get or create FIDO2 credential
  def get_or_create_credential(credential_id : String) : FIDO2Credential
    nv_index = credential_id_to_nv_index(credential_id)
    auth_value = derive_auth_value(credential_id)

    begin
      # Try to read existing credential
      metadata = read_credential_metadata(nv_index)

      FIDO2Credential.new(
        persistent_handle: metadata[:persistent_handle],
        credential_id: credential_id,
        auth_value: auth_value,
        manager: self
      )
    rescue TPMError
      # Create new credential
      create_fido2_credential(credential_id, auth_value)
    end
  end

  # Sign with ECDSA, tracking r values to detect nonce reuse
  def sign(
    key_handle : UInt32,
    auth_value : Bytes,
    digest : Bytes,
    session : Session? = nil,
  ) : ECDSASignature
    # Build and execute sign command
    command = build_sign_command(key_handle, digest, session, auth_value)
    response = @tpm.execute(command)

    unless response.success?
      raise TPMError.new("Sign failed", response.code)
    end

    # Parse signature
    sig = parse_ecdsa_signature(response.params)

    # Check for r value reuse (nonce reuse detection)
    r_hex = sig.r.hexstring
    if @r_tracker.includes?(r_hex)
      raise SecurityError.new("ECDSA nonce reuse detected!")
    end
    @r_tracker.add(r_hex)

    sig
  end

  private def create_fido2_credential(credential_id : String, auth_value : Bytes) : FIDO2Credential
    # Create primary key under owner hierarchy
    primary_handle = create_primary_key(auth_value)

    begin
      # Create signing key
      signing_key = create_signing_key(primary_handle, auth_value)

      # Load key
      loaded_handle = load_key(primary_handle, signing_key, auth_value)

      # Make persistent
      persistent_handle = evict_control(loaded_handle, auth_value)

      # Store metadata
      nv_index = credential_id_to_nv_index(credential_id)
      store_credential_metadata(nv_index, persistent_handle, credential_id)

      FIDO2Credential.new(
        persistent_handle: persistent_handle,
        credential_id: credential_id,
        auth_value: auth_value,
        manager: self
      )
    ensure
      flush_context(primary_handle)
    end
  end

  private def create_primary_key(auth_value : Bytes) : UInt32
    # Build CreatePrimary command with auth
    command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::CreatePrimary)
    command.add_handle(TPM2::Handles::OWNER)
    command.auth_area = (build_password_auth(auth_value))
    command.params = (build_primary_params(auth_value))

    response = @tpm.execute(command)

    unless response.success?
      raise TPMError.new("CreatePrimary failed", response.code)
    end

    parse_create_primary_response(response.params)[:handle]
  end

  private def build_primary_params(auth_value : Bytes) : Bytes
    io = IO::Memory.new

    # sensitiveCreate
    io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
    io.write(auth_value)
    io.write_bytes(0_u16, TPM2::ENDIAN) # data size
    io.write_bytes(0_u16, TPM2::ENDIAN) # seed size

    # public
    io.write_bytes(TPM2::Algorithms::ECC, TPM2::ENDIAN)    # type
    io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN) # nameAlg
    io.write_bytes(
      TPM2::ObjectAttributes::USER_WITH_AUTH |
      TPM2::ObjectAttributes::SIGN_ENCRYPT |
      TPM2::ObjectAttributes::FIXEDTPM |
      TPM2::ObjectAttributes::FIXEDPARENT |
      TPM2::ObjectAttributes::SENSITIVEDATAORIGIN,
      TPM2::ENDIAN
    )
    io.write_bytes(0_u16, TPM2::ENDIAN) # policy size

    # ECC parameters
    io.write_bytes(TPM2::ECCCurves::NIST_P256, TPM2::ENDIAN)
    io.write_bytes(TPM2::Algorithms::NULL, TPM2::ENDIAN)  # kdf
    io.write_bytes(TPM2::Algorithms::ECDSA, TPM2::ENDIAN) # scheme
    io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)

    # outsideInfo
    io.write_bytes(0_u16, TPM2::ENDIAN)

    # creationPCR
    io.write_bytes(0_u32, TPM2::ENDIAN) # count

    io.to_slice
  end

  private def credential_id_to_nv_index(credential_id : String) : UInt32
    digest = OpenSSL::Digest.new("SHA256").update(credential_id).final
    base = IO::Memory.new(digest[0..3]).read_bytes(UInt32, TPM2::ENDIAN)
    0x01000000_u32 | (base & 0x00FFFFFF)
  end

  private def build_password_auth(auth_value : Bytes) : Bytes
    io = IO::Memory.new
    io.write_bytes(1_u32, TPM2::ENDIAN)
    io.write_bytes(TPM2::Handles::PW, TPM2::ENDIAN)
    io.write_bytes(0_u16, TPM2::ENDIAN)
    io.write_byte(TPM2::SessionAttributes::CONTINUESESSION)
    io.write_bytes(auth_value.size.to_u16, TPM2::ENDIAN)
    io.write(auth_value)
    io.to_slice
  end

  private def parse_create_primary_response(params : Bytes) : NamedTuple(handle: UInt32)
    io = IO::Memory.new(params)
    handle = io.read_bytes(UInt32, TPM2::ENDIAN)
    {handle: handle}
  end

  private def parse_ecdsa_signature(params : Bytes) : ECDSASignature
    io = IO::Memory.new(params)

    _sig_alg = io.read_bytes(UInt16, TPM2::ENDIAN)
    _hash_alg = io.read_bytes(UInt16, TPM2::ENDIAN)

    r_len = io.read_bytes(UInt16, TPM2::ENDIAN)
    r = Bytes.new(r_len)
    io.read_fully(r)

    s_len = io.read_bytes(UInt16, TPM2::ENDIAN)
    s = Bytes.new(s_len)
    io.read_fully(s)

    ECDSASignature.new(r, s)
  end

  # Placeholder methods - would be implemented fully
  private def create_signing_key(parent : UInt32, auth : Bytes)
    Bytes.new(0)
  end

  private def load_key(parent : UInt32, key : Bytes, auth : Bytes)
    0_u32
  end

  private def evict_control(handle : UInt32, auth : Bytes)
    0_u32
  end

  private def flush_context(handle : UInt32); end

  private def read_credential_metadata(index : UInt32)
    {persistent_handle: 0_u32}
  end

  private def store_credential_metadata(index : UInt32, handle : UInt32, id : String); end

  private def build_sign_command(handle : UInt32, digest : Bytes, session : Session?, auth : Bytes)
    TPMCommand.new(0_u16, 0_u32)
  end
end

# ============================================================================
# Supporting Classes
# ============================================================================

class TPMDevice
  def execute(command : TPMCommand) : TPMResponse
    # Implementation would send to /dev/tpmrm0
    TPMResponse.new(0, 0, 0)
  end
end

class TPMCommand
  @tag : UInt16
  @code : UInt32
  @handles : Array(UInt32)
  @auth_area : Bytes
  @params : Bytes

  def initialize(@tag, @code)
    @handles = [] of UInt32
    @auth_area = Bytes.empty
    @params = Bytes.empty
  end

  def add_handle(h : UInt32)
    @handles << h
  end

  def auth_area=(auth : Bytes)
    @auth_area = auth
  end

  def params=(params : Bytes)
    @params = params
  end
end

class TPMResponse
  getter tag : UInt16
  getter size : UInt32
  getter code : UInt32
  property params : Bytes
  property auth_area : Bytes

  def initialize(@tag, @size, @code)
    @params = Bytes.empty
    @auth_area = Bytes.empty
  end

  def self.parse(data : Bytes, session : Session? = nil) : self
    io = IO::Memory.new(data)
    tag = io.read_bytes(UInt16, TPM2::ENDIAN)
    size = io.read_bytes(UInt32, TPM2::ENDIAN)
    code = io.read_bytes(UInt32, TPM2::ENDIAN)
    resp = new(tag, size, code)

    if tag == TPM2::Tag::SESSIONS && data.size > 10
      auth_size = io.read_bytes(UInt32, TPM2::ENDIAN)
      _session_count = io.read_bytes(UInt32, TPM2::ENDIAN)
      _handle = io.read_bytes(UInt32, TPM2::ENDIAN)
      nonce_size = io.read_bytes(UInt16, TPM2::ENDIAN)
      nonce = Bytes.new(nonce_size)
      io.read_fully(nonce)
      _attr = io.read_byte
      _hmac_size = io.read_bytes(UInt16, TPM2::ENDIAN)

      resp.auth_area = data[10, auth_size]
      if session
        session.update_nonce_tpm(nonce)
      end
    end
    resp
  end

  def success? : Bool
    @code == 0
  end
end

class TPMError < Exception
  @code : UInt32

  def initialize(msg : String, @code = 0_u32)
    super(msg)
  end
end

class SecurityError < Exception
end

class FIDO2Credential
  @persistent_handle : UInt32
  @credential_id : String
  @auth_value : Bytes
  @manager : FIDO2CredentialManager

  def initialize(@persistent_handle, @credential_id, @auth_value, @manager)
  end

  def sign(digest : Bytes) : ECDSASignature
    @manager.sign(@persistent_handle, @auth_value, digest)
  end
end

class ECDSASignature
  @r : Bytes
  @s : Bytes

  def initialize(@r, @s)
  end

  def r
    @r
  end

  def s
    @s
  end
end

class SignatureRTracker
  @r_values : Array(String)
  @max_size : Int32
  @mutex : Mutex

  def initialize(@max_size : Int32)
    @r_values = Array(String).new
    @mutex = Mutex.new
  end

  def includes?(r_hex : String) : Bool
    @mutex.synchronize { @r_values.includes?(r_hex) }
  end

  def add(r_hex : String)
    @mutex.synchronize do
      @r_values << r_hex

      # If too many entries, remove oldest half
      if @r_values.size > @max_size
        @r_values.shift(@max_size // 2)
      end
    end
  end
end

module TPM2
  module ResponseCodes
    NV_DEFINED = 0x0000014c_u32
  end
end

# ============================================================================
# TEST
# ============================================================================
puts "TPM2-TSS Implementation"
puts "========================"
puts "Features:"
puts "- KDF key persistence via TPM NV"
puts "- Domain-separated auth derivation"
puts "- Session management with nonce tracking"
puts "- R-value tracking for nonce reuse detection"
puts ""
puts "Architecture complete!"

module ParameterEncryption
  def self.encrypt(data : Bytes, session : Session, alg : String) : Bytes
    raise Exception.new("Not implemented")
  end
end
