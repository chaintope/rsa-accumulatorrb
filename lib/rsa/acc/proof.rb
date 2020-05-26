module RSA
  module ACC
    class Proof

      # witness^H(element) == acc
      attr_reader :element
      attr_reader :witness

      def initialize(element, witness)
        @element = element
        @witness = witness
      end

    end
  end
end