require 'rsa/acc'
require 'openssl'
require 'securerandom'

module RSA
  class Accumulator

    using RSA::ACC::Ext

    include RSA::ACC::Functions
    include RSA::ACC::PoE

    # RSA-2048 modulus(https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048).
    RSA2048_MODULUS = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357
    RSA2048_UNKNOWN_ELEM = 2

    attr_reader :n
    attr_accessor :value
    attr_reader :g        # Initial value

    # Generate accumulator using RSA2048 modulus.
    # @return [RSA::Accumulator]
    def self.generate_rsa2048
      new(RSA2048_MODULUS, RSA2048_UNKNOWN_ELEM)
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
      @g = value
    end

    # Add element to accumulator and get inclusion proof.
    # @param [String] elements an element to be added.
    # @return [RSA::ACC::MembershipProof] inclusion proof.
    def add(*elements)
      current_acc = value
      p = elements_to_prime(elements)
      @value = value.pow(p, n)
      RSA::ACC::MembershipProof.new(elements, current_acc, value, RSA::ACC::PoE.prove(current_acc, p, value, n))
    end

    # Check whether +other+ is same accumulator.
    # @param [RSA::ACC:Accumulator] other other accumulator.
    # @return [Boolean] if same acc return true, otherwise return false.
    def ==(other)
      return false unless other.is_a?(Accumulator)
      self.n == other.n && self.value == other.value
    end

    # Check whether +proof+#element include in accumulator.
    # @param [RSA::ACC::MembershipProof] proof inclusion proof.
    # @return [Boolean] If element exist in acc return true, otherwise false.
    def member?(proof)
      RSA::ACC::PoE.verify(proof.witness, proof.element_prime, value, proof.proof, n)
    end

    # Verify non-membership proof.
    # Verifies a non-membership proof against the current accumulator and
    # elements `elems` whose non-inclusion is being proven.
    # @return [Boolean]
    def non_member?(proof)

    end

    # Generate non-membership proof using set of elements in current acc and non membership elements.
    # @param [Array[String]] members The entire set of elements contained within this accumulator.
    # @param [Array[String]] non_members Elements not included in this accumulator that you want to prove non-membership.
    # @return [RSA::ACC::NonMembershipProof] Non-membership proof.
    def prove_non_membership(members, non_members)
      s = elements_to_prime(members)
      x = elements_to_prime(non_members)

      a, b = egcd(s, x)
      raise ArgumentError, "Inputs not co-prime." unless a * x + b * s == 1

      v = value.pow(a, n)
      d = g.pow(b, n)

      [v, d]
    end

    # Remove the elements in +proofs+ from the accumulator.
    # @param [RSA::ACC::MembershipProof] proofs proofs including the elements to be removed and the witnesses.
    # @return [RSA::ACC::MembershipProof] Proof that the accumulator before the remove contained the deleted elements.
    def delete(*proofs)
      return RSA::ACC::MembershipProof.new(proofs.map(&:element).flatten, value, value, RSA::ACC::PoE.prove(value, 1, value, n)) if proofs.empty?

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
      RSA::ACC::MembershipProof.new(proofs.map{|p|p.element}.flatten, value, current_value, RSA::ACC::PoE.prove(value, proof_product, current_value, n))
    end

    # Computes an xi-th root of +y+ for all i = 1, ..., n in total time O(n log(n)).
    # @param [Array[Integer]] f factorizations of the exponent x = x1, ..., xn.
    # @return [Array{Integer}] array of xi-th root
    def root_factor(*f)
      return [value] if f.size == 1
      half_n = f.size / 2
      g_l = RSA::Accumulator.new(n, value.pow(f[0...half_n].map.inject(:*), n))
      g_r = RSA::Accumulator.new(n, value.pow(f[half_n..-1].map.inject(:*), n))
      l = g_r.root_factor(*f[0...half_n])
      r = g_l.root_factor(*f[half_n..-1])
      [l, r].flatten
    end

  end
end
