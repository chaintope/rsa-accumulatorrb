module RSA
  module ACC

    class PoKE2Proof

      using RSA::ACC::Ext

      attr_reader :z
      attr_reader :q
      attr_reader :r

      def initialize(z, q, r)
        @z = z
        @q = q
        @r = r
      end

      # Check whether same proof.
      # @param [RSA::ACC::PoKE2Proof] other other proof.
      # @return [Boolean] whether same proof.
      def ==(other)
        return false unless other.is_a?(RSA::ACC::PoKE2Proof)
        z == other.z && q == other.q && r == other.r
      end

    end

    # Non-Interactive Proof of knowledge of exponent2.
    module PoKE2

      using RSA::ACC::Ext

      include RSA::ACC::Functions
      extend RSA::ACC::Functions

      module_function

      # Computes a proof that you know +exp+ s.t. +base+ ^ +exp+ = +result+.
      # @param [Integer] base
      # @param [Integer] exp
      # @param [Integer] result
      # @param [Integer] modulus
      # @return [RSA::ACC::PoKE2Proof] a proof.
      def prove(base, exp, result, modulus)
        g = RSA::Accumulator::RSA3072_UNKNOWN_ELEM
        z = g.pow(exp, modulus)
        l = compute_challenge(base, result, z)
        alpha = blake2_hash(base, result, z, l)
        q, r = exp.divmod(l)
        RSA::ACC::PoKE2Proof.new(z, ((base * g.pow(alpha, modulus)) % modulus).pow(q, modulus), r)
      end

      # Verifies that the prover knows +exp+ s.t. +base+ ^ +exp+ = +result+
      # @param [Integer] base
      # @param [Integer] result
      # @param [RSA::ACC::PoKE2Proof] proof
      # @param [Integer] modulus
      # @return [Boolean] Returns true for successful verification, false otherwise.
      def verify(base, result, proof, modulus)
        g = RSA::Accumulator::RSA3072_UNKNOWN_ELEM
        l = compute_challenge(base, result, proof.z)
        alpha = blake2_hash(base, result, proof.z, l)
        lhs = (proof.q.pow(l, modulus) * ((base * g.pow(alpha, modulus) % modulus)).pow(proof.r, modulus)) % modulus
        rhs = (result * proof.z.pow(alpha, modulus) % modulus)
        lhs == rhs
      end

    end

  end
end