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

      # Computes (xy) th root of g given xth and yth roots of g. x and y is co-prime.
      # (a, b) ← Bezout(x, y)
      #
      # @param [Integer] w1 first witness.
      # @param [Integer] w2 second witness.
      # @param [Integer] x
      # @param [Integer] y
      # @return [Integer] w1^b * w2^a
      def shamir_trick(w1, w2, x, y, modulus)
        raise ArgumentError, 'w1^x != w2^y' unless w1.pow(x, modulus) == w2.pow(y, modulus)
        a, b = egcd(x, y)
        raise ArgumentError, 'Inputs does not co-prime.' unless a * x + b * y == 1
        (w1.pow(b, modulus) * w2.pow(a, modulus)) % modulus
      end

      # Computes Bezout coefficients.
      # see: https://github.com/dryruby/rsa.rb/blob/b1366970d31dba0078fd06d9f5d3ddd4952fb087/lib/rsa/math.rb#L143
      # @param [Integer] x
      # @param [Integer] y
      # @return [Array[Integer, Integer]] Bezout coefficients
      def egcd(x, y)
        return [0, 1] if x.modulo(y).zero?
        a, b = egcd(y, x.modulo(y))
        [b, a - b * x.div(y)]
      end

      # Computes a challenge from +params+.
      # @param [Array[Integer]] params
      # @return [Integer] prime number of challenge.
      def compute_challenge(*params)
        hash_to_prime(params.map{|p|even_hex(p)}.join)
      end

      # Computes hash value from +params+.
      # @param [Array[Integer]] params
      # @return [Integer] hash value.
      def blake2_hash(*params)
        RbNaCl::Hash.blake2b(params.map{|p|even_hex(p)}.join).unpack("H*").first.to_i(16)
      end

      private

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