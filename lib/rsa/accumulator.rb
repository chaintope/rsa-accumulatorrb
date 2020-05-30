require 'rsa/acc'
require 'openssl'
require 'securerandom'

module RSA
  class Accumulator

    include RSA::ACC::Functions
    include RSA::ACC::PoE

    # RSA-2048 modulus(https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048).
    RSA2048_MODULUS = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357

    attr_reader :n
    attr_accessor :value

    private_class_method :new

    # Generate accumulator using RSA2048 modulus.
    # @return [RSA::Accumulator]
    def self.generate_rsa2048
      new(RSA2048_MODULUS, 2)
    end

    # Generate accumulator with random modulus.
    # @param [Integer] bit_length bit length of accumulator. Default: 3072 bits.
    # @return [RSA::Accumulator]
    def self.generate_random(bit_length = 3072)
      n = OpenSSL::PKey::RSA.generate(bit_length).n.to_i
      new(n, SecureRandom.random_number(n))
    end

    # Initialize accumulator
    # @param [Integer] n modulus
    # @param [Integer] value initial value
    # @return [RSA::Accumulator]
    def initialize(n, value)
      @n = n
      @value = value
    end

    # Add element to accumulator and get inclusion proof.
    # @param [String] elements an element to be added.
    # @return [RSA::ACC::Proof] inclusion proof.
    def add(*elements)
      current_acc = value
      p = elements.map{|e|hash_to_prime(e)}.inject(:*)
      @value = value.pow(p, n)
      RSA::ACC::Proof.new(elements, current_acc, value, prove(current_acc, p, value, n))
    end

    # Check whether +other+ is same accumulator.
    # @param [RSA::ACC:Accumulator] other other accumulator.
    # @return [Boolean] if same acc return true, otherwise return false.
    def ==(other)
      return false unless other.is_a?(Accumulator)
      self.n == other.n && self.value == other.value
    end

    # Check whether +element+ include in accumulator.
    # @param [String] element
    # @param [RSA::ACC::Proof] proof inclusion proof.
    # @return [Boolean] If element exist in acc return true, otherwise false.
    def include?(element, proof)
      p = hash_to_prime(element)
      valid?(proof.witness, p, value, proof.proof, n)
    end

    # Remove the elements in +proofs+ from the accumulator.
    # @param [RSA::ACC::Proof] proofs proofs including the elements to be removed and the witnesses.
    # @return [RSA::ACC::Proof] Proof that the accumulator before the remove contained the deleted elements.
    def delete(*proofs)
      return RSA::ACC::Proof.new(proofs.map(&:element).flatten, value, value, prove(value, 1, value, n)) if proofs.empty?

      witnesses = proofs.map do |proof|
        p = proof.element_prime
        raise RSA::ACC::Error, 'Bad witness.' unless proof.witness.pow(p, n) == value
        [p, proof.witness]
      end

      current_value = value
      proof_product = witnesses.first[0]
      new_value = witnesses.first[1]
      if witnesses.size > 1
        witnesses[1..-1].each do |w|
          new_value = shamir_trick(new_value, w[1], proof_product, w[0], n)
          proof_product *= w[0]
        end
      end

      @value = new_value
      RSA::ACC::Proof.new(proofs.map{|p|p.element}.flatten, value, current_value, prove(value, proof_product, current_value, n))
    end

  end
end
