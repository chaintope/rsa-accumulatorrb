module RSA
  module ACC

    # Proof of membership of the element's inclusion in the accumulator.
    class MembershipProof

      include Functions

      # witness^H(element) == acc
      attr_reader :element
      attr_reader :witness
      attr_reader :acc_value
      attr_reader :proof # prof calculated by PoE

      def initialize(element, witness, acc_value, proof)
        @element = element
        @witness = witness
        @acc_value = acc_value
        @proof = proof
      end

      # Convert element to prime number.
      # @return [Integer] prime number of element.
      def element_prime
        return nil if element.nil?
        element.is_a?(Array) ? elements_to_prime(element) : hash_to_prime(element)
      end

    end

    # Proof of non-membership of the element's not inclusion in the accumulator.
    class NonMembershipProof

      attr_reader :d            # d = g^b
      attr_reader :v            # v = A(current acc)^a
      attr_reader :gv_inv       # gv_inv = v^{-1}
      attr_reader :poke2_proof  # NI-PoKE2(A, v, a)
      attr_reader :poe_proof    # NI-PoE(d, x, g*v^{-1})

      def initialize(d, v, gv_inv, poke2_proof, poe_proof)
        @d = d
        @v = v
        @gv_inv = gv_inv
        @poke2_proof = poke2_proof
        @poe_proof = poe_proof
      end

    end

  end
end