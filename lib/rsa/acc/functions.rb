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
          candidate = RbNaCl::Hash.blake2b(element + nonce.to_s).unpack("C*")
          candidate[-1] |= 1
          candidate = candidate.pack('c*').unpack("H*").first.to_i(16)
          if candidate.to_bn.prime?
            return candidate
          end
          nonce += 1
        end
      end

    end
  end
end