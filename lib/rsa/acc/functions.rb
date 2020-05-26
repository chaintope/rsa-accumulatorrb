require 'rbnacl'

module RSA
  module ACC
    module Functions

      # Convert element to prime number.
      # @param [String] element an element to be converted.
      # @return [Integer] prime number.
      def hash_to_prime(element)
        nonce = 0
        loop do
          candidate = RbNaCl::Hash.blake2b(element + even_hex(nonce)).unpack("C*")
          candidate[-1] |= 1
          candidate = candidate.pack('c*').unpack("H*").first.to_i(16)
          if candidate.to_bn.prime?
            return candidate
          end
          nonce += 1
        end
      end

      # Convert +num+ to even hex string.
      # @param [Integer] num
      # @return [String] hex string.
      def even_hex(num)
        hex = num.to_s(16)
        hex.rjust((hex.length / 2.0).ceil * 2, '0')
      end

    end
  end
end