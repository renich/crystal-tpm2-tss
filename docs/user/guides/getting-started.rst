===============
Getting Started
===============

Installation
------------

Add ``crystal-tpm2-tss`` to your project's ``shard.yml``:

.. code-block:: yaml

   dependencies:
     crystal-tpm2-tss:
       gitlab: renich/crystal-tpm2-tss
       version: ~> 0.4.0

Install dependencies:

.. code-block:: bash

   shards install

Basic Usage
-----------

Require the library, provision a FIDO2 credential, sign a 32-byte digest, and verify the NIST P-256 ECDSA signature:

.. code-block:: crystal

   require "crystal-tpm2-tss"

   # Initialize TPM device (virtual simulator by default, or pass "/dev/tpmrm0")
   tpm = TPMDevice.new
   platform_secret = Random::Secure.random_bytes(32)

   manager = FIDO2CredentialManager.new(tpm, platform_secret)
   credential = manager.get_or_create_credential("user-credential-1234")

   pub_x, pub_y = credential.public_key_xy
   digest = Random::Secure.random_bytes(32)
   signature = credential.sign(digest)

   puts "Public key X: #{pub_x.hexstring}"
   puts "Public key Y: #{pub_y.hexstring}"
   puts "Signature valid? #{credential.verify(digest, signature)}"

Session Parameter Encryption
----------------------------

Encrypt and decrypt sensitive command parameters using TCG TPM 2.0 Part 1 KDFa ``XOR`` or ``AES-128-CFB``:

.. code-block:: crystal

   session = Session.new(0x02000001.to_u32)
   session.session_key = Random::Secure.random_bytes(32)
   session.roll_nonce
   session.update_nonce_tpm(Random::Secure.random_bytes(32))

   ciphertext = ParameterEncryption.encrypt("secret-pin".to_slice, session, "AES-CFB")
   plaintext = ParameterEncryption.decrypt(ciphertext, session, "AES-CFB")
