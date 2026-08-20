module RSA
  module ACC

    # Non-Interactive Proof of Exponentiation
    module PoE

      using RSA::ACC::Ext

      include RSA::ACC::Functions
      extend RSA::ACC::Functions

      module_function

      # Computes a proof +base+ ^ H(+exp+) was performed to derive +result+.
      # @param [Integer] base The known base.
      # @param [Integer] exp The exponentiation.
      # @param [Integer] result such as result = base^exp.
      # @param [Integer] modulus modulus using computation.
      def prove(base, exp, result, modulus)
        base = normalize(base, modulus)
        result = normalize(result, modulus)
        l = compute_challenge(base, exp, result)
        q = exp / l
        normalize(base.pow(q, modulus), modulus)
      end

      # Verifies that base^exp = result using the given proof to avoid computation.
      # @param [Integer] base The known base.
      # @param [Integer] exp The exponentiation.
      # @param [Integer] result such as result = base^exp.
      # @param [Integer] proof an proof.
      # @param [Integer] modulus modulus using computation.
      def verify(base, exp, result, proof, modulus)
        base = normalize(base, modulus)
        result = normalize(result, modulus)
        proof = normalize(proof, modulus)
        l = compute_challenge(base, exp, result)
        r = exp % l
        w = normalize(proof.pow(l, modulus) * base.pow(r, modulus), modulus)
        w == result
      end

    end

  end
end