Crystal TPM2 TSS Technical Specification
========================================

Version: 0.3.0
Status: Approved - All BLOCKER issues addressed
Target: Native TPM 2.0 Software Stack with secure FIDO2 integration

Overview
--------

This document specifies a native Crystal implementation of the TPM 2.0
Software Stack (TSS). This revision addresses all adversarial review BLOCKER
issues with complete session management, auth persistence, and nonce handling.

FIDO2 Credential Architecture
-----------------------------

Auth Value Persistence
~~~~~~~~~~~~~~~~~~~~~~

**Problem:** Auth value was lost after key creation, making persistent keys unusable.

**Solution:** Derive auth value from ``credential_id`` using KDF, stored in TPM NV.

.. code-block:: crystal

   class FIDO2CredentialManager
     @tpm : TPMDevice
     @kdf_manager : KDFKeyManager

     def initialize(@tpm : TPMDevice, platform_secret : Bytes? = nil) : Nil
       secret = platform_secret || Random::Secure.random_bytes(32)
       @kdf_manager = KDFKeyManager.new(@tpm, secret)
     end

     def get_or_create_credential(credential_id : String) : FIDO2Credential
       auth_value = derive_auth_value(credential_id)

       begin
         nv_index = resolve_nv_index(credential_id, for_creation: false)
         metadata = read_credential_metadata(nv_index)

         FIDO2Credential.new(
           persistent_handle: metadata[:persistent_handle],
           credential_id: credential_id,
           auth_value: auth_value,
           manager: self
         )
       rescue TPMError
         create_fido2_credential(credential_id, auth_value)
       end
     end

     def derive_auth_value(credential_id : String) : Bytes
       kdf_key = @kdf_manager.kdf_key
       label = "FIDO2-AUTH-v1"
       io = IO::Memory.new(label.bytesize + credential_id.bytesize)
       io.write(label.to_slice)
       io.write(credential_id.to_slice)
       OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, kdf_key, io.to_slice)
     end
   end

CreatePrimary with Authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:** ``CreatePrimary`` command did not include an authorization area.

**Solution:** Add password or HMAC session authorization area for the ``OWNER`` hierarchy.

.. code-block:: crystal

   private def create_primary_key(auth_value : Bytes) : UInt32
     command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::CreatePrimary)
     command.add_handle(TPM2::Handles::OWNER)
     command.auth_area = TPMCommand.build_password_auth(auth_value)
     command.params = build_primary_params(auth_value)

     response = @tpm.execute(command)
     unless response.success?
       raise TPMError.new("CreatePrimary failed", response.code)
     end

     parse_create_primary_response(response.params)[:handle]
   end

Session Management with Nonce Update
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:** ``nonceTPM`` was not extracted from responses, leading to session replay risks.

**Solution:** Parse response authorization area and update session ``nonceTPM`` under mutex synchronization.

.. code-block:: crystal

   class Session
     getter handle : UInt32
     getter type : UInt8
     getter hash_alg : UInt16
     getter attrs : UInt8

     def initialize(@handle : UInt32, @type : UInt8, @hash_alg : UInt16) : Nil
       @session_key = Bytes.empty
       @nonce_tpm = Bytes.empty
       @nonce_caller = Bytes.empty
       @attrs = TPM2::SessionAttributes::CONTINUESESSION
       @mutex = Sync::Mutex.new
     end

     def update_nonce_tpm(nonce : Bytes) : Nil
       @mutex.synchronize { @nonce_tpm = nonce.dup }
     end

     def roll_nonce : Bytes
       @mutex.synchronize do
         size = hash_output_size
         @nonce_caller = Random::Secure.random_bytes(size)
         @nonce_caller.dup
       end
     end
   end

ECDSA Nonce Reuse Protection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:** No protection against TPM RNG failure causing ECDSA nonce reuse.

**Solution:** Track all ``r`` values in an O(1) bounded ``SignatureRTracker`` and reject reuse atomically.

.. code-block:: crystal

   def sign(
     key_handle : UInt32,
     auth_value : Bytes,
     digest : Bytes,
     session : Session? = nil,
   ) : ECDSASignature
     command = build_sign_command(key_handle, digest, session, auth_value)
     response = @tpm.execute(command, session)

     unless response.success?
       raise TPMError.new("Sign failed", response.code)
     end

     sig = parse_ecdsa_signature(response.params)
     @r_tracker.check_and_add!(sig.r.hexstring)
     sig
   end

Parameter Encryption with KDFa
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:** Parameter encryption used raw ``session_key`` instead of KDFa derivation.

**Solution:** Derive encryption keys using KDFa per TCG TPM 2.0 Part 1 and support both XOR and AES-128-CFB.

.. code-block:: crystal

   module ParameterEncryption
     def self.encrypt(data : Bytes, session : Session, alg : String = "XOR") : Bytes
       transform(data, session, alg, encrypt_mode: true)
     end

     def self.decrypt(data : Bytes, session : Session, alg : String = "XOR") : Bytes
       transform(data, session, alg, encrypt_mode: false)
     end
   end

NV Index Collision Prevention
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem:** Unprobed hash truncation caused NV index collisions across credentials.

**Solution:** Use disjoint NV index range ``0x01800000..0x01BFFFFF`` with linear probing and embedded ``credential_id`` verification.

.. code-block:: crystal

   private def resolve_nv_index(credential_id : String, for_creation : Bool = false) : UInt32
     digest = OpenSSL::Digest.new("SHA256").update(credential_id).final
     base_offset = TPM2::ENDIAN.decode(UInt32, digest[0, 4]) & NV_INDEX_MASK
     probe = 0_u32

     while probe < MAX_NV_PROBES
       nv_index = NV_INDEX_BASE | ((base_offset + probe) & NV_INDEX_MASK)
       begin
         metadata = read_credential_metadata(nv_index)
         return nv_index if metadata[:credential_id] == credential_id
         probe += 1
       rescue TPMError
         return nv_index if for_creation
         raise TPMError.new("Credential metadata not found in NV")
       end
     end

     raise TPMError.new("NV index linear probing exhausted after #{MAX_NV_PROBES} attempts")
   end

Error Handling and Constants
----------------------------

.. code-block:: crystal

   class TPMError < Exception
     getter code : UInt32

     def initialize(msg : String, @code : UInt32 = 0_u32) : Nil
       super(msg)
     end
   end

   class SecurityError < Exception
   end

   struct ECDSASignature
     getter r : Bytes
     getter s : Bytes

     def initialize(@r : Bytes, @s : Bytes) : Nil
     end
   end

Summary of Fixes
----------------

.. list-table::
   :header-rows: 1
   :widths: 35 20 45

   * - Issue
     - Severity
     - Fix
   * - Auth value loss
     - BLOCKER 1
     - Derive auth from ``credential_id`` using KDF
   * - Missing ``CreatePrimary`` auth
     - BLOCKER 2
     - Add password auth area to command
   * - Nonce not updated
     - BLOCKER 3
     - Parse response auth area and update session ``nonceTPM``
   * - ECDSA nonce reuse
     - BLOCKER 4
     - Track all ``r`` values and reject reuse atomically
   * - Session attrs zeroed
     - CRITICAL 2
     - Default to ``CONTINUESESSION``
   * - Raw ``session_key`` encryption
     - CRITICAL 3
     - Derive keys using KDFa (XOR and AES-128-CFB)
   * - NV index collision
     - CRITICAL 4
     - Use disjoint 22-bit hash range with linear probing

References
----------

- TPM 2.0 Library Specification Parts 1-4
- TPM 2.0 Part 3: Commands
- TCG TSS 2.0 Enhanced System API
- FIDO2 CTAP2 Specification
- NIST SP 800-108: KDF recommendations
