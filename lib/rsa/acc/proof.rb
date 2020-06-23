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

  end
end