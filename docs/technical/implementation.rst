Implementation Details
======================

This document highlights the core implementation details addressing adversarial review findings for the TPM 2.0 Stack.

KDF Key Persistence
-------------------

To ensure KDF key persistence across reboots, the implementation utilizes TPM NV storage.

.. code-block:: crystal

   class KDFKeyManager
     @kdf_nv_index : UInt32 = 0x01C00000_u32
     
     def get_kdf_key : Bytes
       # Try to read from NV
       # If not exists, generate and store
       # Key persists across reboots
     end
   end

Auth Value Derivation
---------------------

To derive the auth value, a domain-separated KDF is used from the ``credential_id`` to prevent cross-protocol attacks.

.. code-block:: crystal

   def derive_auth_value(credential_id : String) : Bytes
     kdf_key = @kdf_manager.get_kdf_key
     label = "FIDO2-AUTH-v1"
     OpenSSL::HMAC.digest("SHA256", kdf_key, label + credential_id)
   end

Highlights
----------

* KDF key stored in TPM NV (survives reboots)
* Domain-separated derivation prevents cross-protocol attacks
* Session nonce tracking (parse from response auth area)
* R-value tracking for ECDSA nonce reuse detection
