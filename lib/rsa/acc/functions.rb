require 'blake2b'

module RSA
  module ACC
    module Functions

      # Convert element to prime number.
      # @param [String] element an element to be converted.
      # @return [Integer] prime number.
      def hash_to_prime(element)
        nonce = 0
        loop do
          candidate = Blake2b.bytes(element + nonce.to_s)
          candidate[-1] |= 1
          candidate = candidate.pack('c*').unpack("H*").first.to_i(16)
          return candidate if OpenSSL::BN.new(candidate).prime?
          nonce += 1
        end
      end

    end
  end
end