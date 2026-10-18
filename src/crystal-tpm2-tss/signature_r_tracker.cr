require "sync/mutex"

module Crystal::Tpm2::Tss
  # Thread-safe bounded tracker for detecting ECDSA signature `r`-component nonce reuse in O(1) time.
  class SignatureRTracker
    @r_set : Set(String)
    @r_order : Deque(String)
    @max_size : Int32
    @mutex : Sync::Mutex

    # Initializes a bounded `SignatureRTracker` with capacity `max_size`.
    def initialize(@max_size : Int32) : Nil
      raise ArgumentError.new("max_size must be positive") if @max_size <= 0

      @r_set = Set(String).new
      @r_order = Deque(String).new
      @mutex = Sync::Mutex.new
    end

    # Returns `true` if `r_hex` is currently recorded in the active nonce window.
    def includes?(r_hex : String) : Bool
      @mutex.synchronize { @r_set.includes?(r_hex) }
    end

    # Records `r_hex` in the tracker, evicting the oldest half of entries when capacity is exceeded.
    def add(r_hex : String) : Nil
      @mutex.synchronize do
        return if @r_set.includes?(r_hex)
        insert_unlocked(r_hex)
      end
    end

    # Atomically checks whether `r_hex` was previously seen (raising `SecurityError` on collision) and records it.
    def check_and_add!(r_hex : String) : Nil
      @mutex.synchronize do
        if @r_set.includes?(r_hex)
          raise SecurityError.new("ECDSA nonce reuse detected!")
        end
        insert_unlocked(r_hex)
      end
    end

    private def insert_unlocked(r_hex : String) : Nil
      @r_set.add(r_hex)
      @r_order << r_hex

      return unless @r_order.size > @max_size

      evict_count = Math.max(1, @max_size // 2)
      evict_count.times do
        if oldest = @r_order.shift?
          @r_set.delete(oldest)
        end
      end
    end
  end
end
