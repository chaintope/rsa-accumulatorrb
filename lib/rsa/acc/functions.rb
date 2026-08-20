require 'rbnacl'

module RSA
  module ACC
    module Functions

      using RSA::ACC::Ext

      # Domain separation tags. Elements, Fiat-Shamir challenges and plain hashes are hashed
      # with a distinct tag each, so that a caller supplied element can never be made to
      # produce the same digest as a challenge over group elements.
      ELEMENT_DST = 'RSA-ACC/v1/element'.freeze
      CHALLENGE_DST = 'RSA-ACC/v1/challenge'.freeze
      HASH_DST = 'RSA-ACC/v1/hash'.freeze

      # Computes the canonical representative of +elem+ in the quotient group Z_n^* / {+-1}.
      # Z_n^* always contains the known order-2 element -1, and the Adaptive Root Assumption
      # which NI-PoE and NI-PoKE2 rely on does not hold in a group with a known low order
      # element. Identifying y with -y removes it, so every group element MUST be normalized
      # before it is hashed into a challenge, compared, or published as part of a proof.
      # @param [Integer] elem an element of Z_n^*.
      # @param [Integer] modulus modulus of the group.
      # @return [Integer] the smaller of +elem+ and -+elem+ modulo +modulus+.
      def normalize(elem, modulus)
        y = elem % modulus
        neg = modulus - y
        y < neg ? y : neg
      end

      # Convert element to prime number.
      # @param [String] element an element to be converted.
      # @return [Integer] prime number.
      def hash_to_prime(element)
        prime_from(ELEMENT_DST, [element])
      end

      # Converts a list of elements to an product of prime numbers.
      # @param [Array[String]] elements a list of element.
      # @return [Integer] an product of prime numbers
      def elements_to_prime(elements)
        elements.map{|e|hash_to_prime(e)}.inject(:*)
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
        w1 = normalize(w1, modulus)
        w2 = normalize(w2, modulus)
        unless normalize(w1.pow(x, modulus), modulus) == normalize(w2.pow(y, modulus), modulus)
          raise ArgumentError, 'w1^x != w2^y'
        end
        a, b = egcd(x, y)
        raise ArgumentError, 'Inputs does not co-prime.' unless a * x + b * y == 1
        normalize(w1.pow(b, modulus) * w2.pow(a, modulus), modulus)
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
        prime_from(CHALLENGE_DST, params.map { |p| even_hex(p) })
      end

      # Computes hash value from +params+.
      # @param [Array[Integer]] params
      # @return [Integer] hash value.
      def blake2_hash(*params)
        digest = RbNaCl::Hash.blake2b(encode_fields(HASH_DST, params.map { |p| even_hex(p) }))
        digest.unpack("H*").first.to_i(16)
      end

      private

      # Serializes +dst+ and +fields+ by prefixing each of them with its byte length, so that
      # the resulting byte string can only be produced by this exact sequence of inputs.
      # A plain concatenation is ambiguous: even_hex is variable length, so for example
      # (0x01, 0x2345) and (0x0123, 0x45) both join to "012345".
      # @param [String] dst domain separation tag.
      # @param [Array[String]] fields fields to be serialized.
      # @return [String] a binary string.
      def encode_fields(dst, fields)
        fields.inject(length_prefixed(dst)) { |buf, field| buf << length_prefixed(field) }
      end

      # @param [String] data
      # @return [String] +data+ prefixed with its byte length as a 64 bit big endian integer.
      def length_prefixed(data)
        bytes = data.to_s.b
        [bytes.bytesize].pack('Q>') << bytes
      end

      # Hashes +fields+ under the domain +dst+ repeatedly, incrementing a nonce, until the
      # digest is prime.
      # @param [String] dst domain separation tag.
      # @param [Array[String]] fields fields to be hashed.
      # @return [Integer] prime number.
      def prime_from(dst, fields)
        nonce = 0
        loop do
          digest = RbNaCl::Hash.blake2b(encode_fields(dst, fields + [even_hex(nonce)])).unpack("C*")
          digest[0] |= 0x80  # keep the output width fixed, a leading zero byte would shorten it
          digest[-1] |= 1    # 2 is the only even prime, so only odd candidates are worth testing
          candidate = digest.pack('C*').unpack("H*").first.to_i(16)
          return candidate if candidate.to_bn.prime?
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