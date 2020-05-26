module RSA
  module ACC

    # Non-Interactive Proof of Exponentiation
    module PoE

      include RSA::ACC::Functions

      # Computes a proof +base+ ^ H(+exp+) was performed to derive +result+.
      # @param [Integer] base The known base.
      # @param [Integer] exp The exponentiation.
      # @param [Integer] result such as result = base^exp.
      # @param [Integer] modulus modulus using computation.
      def prove(base, exp, result, modulus)
        l = compute_challenge(base, exp, result)
        q = exp / l
        base.pow(q, modulus)
      end

      # Verifies that base^exp = result using the given proof to avoid computation.
      # @param [Integer] base The known base.
      # @param [Integer] exp The exponentiation.
      # @param [Integer] result such as result = base^exp.
      # @param [Integer] proof an proof.
      # @param [Integer] modulus modulus using computation.
      def valid?(base, exp, result, proof, modulus)
        l = compute_challenge(base, exp, result)
        r = exp % l
        w = (proof.pow(l, modulus) * base.pow(r, modulus)) % n
        w == result
      end

      # Computes a challenge.
      # @param [Integer] base The known base.
      # @param [Integer] exp The exponentiation.
      # @param [Integer] result such as result = base^exp.
      def compute_challenge(base, exp, result)
        hash_to_prime(even_hex(base) + even_hex(exp) + even_hex(result))
      end

    end

  end
end