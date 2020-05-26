module RSA
  module ACC
    class Proof

      # witness^H(element) == acc
      attr_reader :element
      attr_reader :witness
      attr_reader :proof # prof calculated by PoE

      def initialize(element, witness, proof)
        @element = element
        @witness = witness
        @proof = proof
      end

    end
  end
end