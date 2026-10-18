require "openssl"

module Crystal::Tpm2::Tss
  # Manages TPM 2.0 Non-Volatile (NV) index allocation, linear collision probing, and credential metadata serialization.
  class NVMetadataStore
    # Disjoint NV index base address (`0x01800000`) reserved for FIDO2 credential metadata.
    NV_INDEX_BASE = 0x01800000_u32

    # 22-bit offset mask (`0x003FFFFF`) bounding credential NV indices below `0x01C00000`.
    NV_INDEX_MASK = 0x003FFFFF_u32

    # Maximum linear probe attempts when resolving NV index hash collisions.
    MAX_NV_PROBES = 16_u32

    # Underlying `TPMDevice` executing NV commands.
    getter tpm : TPMDevice

    # Initializes an `NVMetadataStore` backed by `tpm`.
    def initialize(@tpm : TPMDevice) : Nil
    end

    # Computes the initial unprobed NV index for a `credential_id` using SHA-256 truncation.
    def credential_id_to_nv_index(credential_id : String) : UInt32
      digest = OpenSSL::Digest.new("SHA256").update(credential_id).final
      base = TPM2::ENDIAN.decode(UInt32, digest[0, 4])
      NV_INDEX_BASE | (base & NV_INDEX_MASK)
    end

    # Resolves the NV index for `credential_id` using bounded linear probing to mitigate hash collisions.
    def resolve_nv_index(credential_id : String, for_creation : Bool = false) : UInt32
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

    # Reads and parses the persistent handle and credential ID stored at NV `index`.
    def read_credential_metadata(index : UInt32) : NamedTuple(persistent_handle: UInt32, credential_id: String)
      command = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_READ)
      command.add_handle(index)
      command.add_handle(index)
      command.auth_area = TPMCommand.build_password_auth(Bytes.empty)

      params_io = IO::Memory.new(4)
      params_io.write_bytes(64_u16, TPM2::ENDIAN)
      params_io.write_bytes(0_u16, TPM2::ENDIAN)
      command.params = params_io.to_slice

      response = @tpm.execute(command)
      raise TPMError.new("NV_READ failed", response.code) unless response.success?

      parse_metadata_payload(response.params)
    end

    # Defines the NV space at `index` and writes the serialized credential metadata record.
    def store_credential_metadata(index : UInt32, handle : UInt32, id : String) : Nil
      payload = serialize_metadata_payload(handle, id)
      define_metadata_nv_space(index, payload.size)

      write_cmd = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_WRITE)
      write_cmd.add_handle(index)
      write_cmd.auth_area = TPMCommand.build_password_auth(Bytes.empty)

      write_io = IO::Memory.new(4 + payload.size)
      write_io.write_bytes(payload.size.to_u16, TPM2::ENDIAN)
      write_io.write(payload)
      write_io.write_bytes(0_u16, TPM2::ENDIAN)
      write_cmd.params = write_io.to_slice

      write_resp = @tpm.execute(write_cmd)
      raise TPMError.new("NV_WRITE metadata failed", write_resp.code) unless write_resp.success?
    end

    # Defines a TPM 2.0 NV index space of `data_size` bytes under `TPM_RH_OWNER` hierarchy.
    def define_metadata_nv_space(index : UInt32, data_size : Int32) : Nil
      define_cmd = TPMCommand.new(TPM2::Tag::SESSIONS, TPM2::Commands::NV_DEFINESPACE)
      define_cmd.add_handle(TPM2::Handles::OWNER)
      define_cmd.auth_area = TPMCommand.build_password_auth(Bytes.empty)

      io = IO::Memory.new(20)
      io.write_bytes(index, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(14_u16, TPM2::ENDIAN)
      io.write_bytes(index, TPM2::ENDIAN)
      io.write_bytes(TPM2::Algorithms::SHA256, TPM2::ENDIAN)
      io.write_bytes(0x00040002_u32, TPM2::ENDIAN)
      io.write_bytes(0_u16, TPM2::ENDIAN)
      io.write_bytes(data_size.to_u16, TPM2::ENDIAN)
      define_cmd.params = io.to_slice

      resp = @tpm.execute(define_cmd)
      return if resp.success? || resp.code == TPM2::ResponseCodes::NV_DEFINED

      raise TPMError.new("NV_DEFINESPACE metadata failed", resp.code)
    end

    # Serializes a `(persistent_handle, credential_id)` pair into a binary NV record.
    def serialize_metadata_payload(handle : UInt32, id : String) : Bytes
      id_slice = id.to_slice
      io = IO::Memory.new(6 + id_slice.size)
      io.write_bytes(handle, TPM2::ENDIAN)
      io.write_bytes(id_slice.size.to_u16, TPM2::ENDIAN)
      io.write(id_slice)
      io.to_slice
    end

    # Parses a `TPM2B_MAX_NV_BUFFER` response payload into its `persistent_handle` and `credential_id`.
    def parse_metadata_payload(params : Bytes) : NamedTuple(persistent_handle: UInt32, credential_id: String)
      raise TPMError.new("Credential metadata too short") if params.size < 8

      io = IO::Memory.new(params)
      nv_len = io.read_bytes(UInt16, TPM2::ENDIAN).to_i
      raise TPMError.new("Incomplete NV metadata buffer") if (io.size - io.pos) < nv_len || nv_len < 6

      handle = io.read_bytes(UInt32, TPM2::ENDIAN)
      id_len = io.read_bytes(UInt16, TPM2::ENDIAN).to_i
      raise TPMError.new("Invalid credential ID length in NV") if nv_len != 6 + id_len || (io.size - io.pos) < id_len

      id_bytes = Bytes.new(id_len)
      io.read_fully(id_bytes)
      {persistent_handle: handle, credential_id: String.new(id_bytes)}
    end
  end
end
