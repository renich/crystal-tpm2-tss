require "sync/mutex"

module Crystal::Tpm2::Tss
  class SignatureRTracker
    @r_set : Set(String)
    @r_order : Deque(String)
    @max_size : Int32
    @mutex : Sync::Mutex

    def initialize(@max_size : Int32)
      @r_set = Set(String).new
      @r_order = Deque(String).new
      @mutex = Sync::Mutex.new
    end

    def includes?(r_hex : String) : Bool
      @mutex.synchronize { @r_set.includes?(r_hex) }
    end

    def add(r_hex : String) : Nil
      @mutex.synchronize do
        return if @r_set.includes?(r_hex)

        @r_set.add(r_hex)
        @r_order << r_hex

        if @r_order.size > @max_size
          evict_count = @max_size // 2
          evict_count.times do
            if oldest = @r_order.shift?
              @r_set.delete(oldest)
            end
          end
        end
      end
    end
  end
end
