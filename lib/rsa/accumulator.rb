require 'rsa/acc'
require 'openssl'
require 'securerandom'

module RSA
  class Accumulator

    using RSA::ACC::Ext

    include RSA::ACC::Functions
    include RSA::ACC::PoE

    # RSA-3072 modulus(OpenSSL::PKey::RSA.generate(3072).n.to_i).
    RSA3072_MODULUS = 4542920471981893782333206863177251410432618509272807502707112105195640130459745756039132741864882165370241632086939443084637257437812233583093244234503109831626001083890995013466794101712705467782842807684455778787631542734706357265882869905399189597145816832124792529873102264234215053275759583909499644614169564986821286955753308374214235427458647453098845318897531531166120482421875120732235138908163071669238222602925710451470408412518660855083587194668721569144807377981197055881164818681361144469895454409735376068774575042194951983766011730388003474277842941521111677161847247558507484788005570715347589804995301491237546888325727308769175579822383555688032029139079291644585768361468176974990943389490836180327555635096401326987781629710029645360591658305980436622917685632896787032793365094991870475640647857112064288936552920042790383833338804354172343281703206448962771159479068390734039317727053366836093828647567
    RSA3072_UNKNOWN_ELEM = 2

    attr_reader :n
    attr_accessor :value
    attr_reader :g              # Initial value
    attr_reader :hold_elements  # tha flag which indicate hold product of all elements.
    attr_accessor :products     # (Optional) product of all elements in Accumulator

    # Generate accumulator using RSA3072 modulus.
    # @return [RSA::Accumulator]
    def self.generate_rsa3072(hold_elements: false)
      new(RSA3072_MODULUS, RSA3072_UNKNOWN_ELEM, RSA3072_UNKNOWN_ELEM, hold_elements)
    end

    # Generate accumulator with random modulus.
    # @param [Integer] bit_length bit length of accumulator. Default: 3072 bits.
    # @return [RSA::Accumulator]
    def self.generate_random(bit_length = 3072, hold_elements: false)
      n = OpenSSL::PKey::RSA.generate(bit_length).n.to_i
      initial_value = SecureRandom.random_number(n)
      new(n, initial_value, initial_value, hold_elements)
    end

    # Initialize accumulator
    # @param [Integer] n modulus
    # @param [Integer] value a value of acc.
    # @param [Integer] initial_acc a value of initial acc.
    # @param [Boolean] hold_elements
    # @param [Integer] products product of all elements in acc, this param is enable only +hold_elements+ set true.
    # @return [RSA::Accumulator]
    def initialize(n, value, initial_acc, hold_elements, products = 1)
      @n = n
      @value = value
      @g = initial_acc
      @hold_elements = hold_elements
      @products = products if hold_elements
      puts "The feature which hold product of all elements is practical feature." if hold_elements
    end

    # Add element to accumulator and get inclusion proof.
    # @param [Array[String]] elements a list of elements to be added.
    # @return [RSA::ACC::MembershipProof] inclusion proof.
    def add(*elements)
      current_acc = value
      p = elements_to_prime(elements)
      self.value = value.pow(p, n)
      self.products *= p if hold_elements
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

    # Verifies a non-membership proof against the current accumulator and +elements+ whose non-inclusion is being proven.
    # @param [Array[String]] elements elements whose non-inclusion is being proven.
    # @param [RSA::ACC::NonMembershipProof] proof non-membership proof.
    # @return [Boolean]
    def non_member?(elements, proof)
      x = elements_to_prime(elements)
      RSA::ACC::PoKE2.verify(value, proof.v, proof.poke2_proof, n) &&
          RSA::ACC::PoE.verify(proof.d, x, proof.gv_inv, proof.poe_proof, n)
    end

    # Generate membership proof for +elements+.
    # This method is only available if hold_elements is set to true when the accumulator is initialized.
    # @param [Array[String]] elements The elements for which you want to generate an membership proof.
    # @return [RSA::ACC::MembershipProof] a membership proof for +elements+. If +elements+ does not exist in accumulator, return nil.
    # @raise RSA::ACC::Error.new This exception is raised when hold_elements is set to false.
    def prove_membership(*elements)
      raise RSA::ACC::Error.new 'This accumulator does not hold the product of the elements.' unless hold_elements
      x = elements_to_prime(elements)
      return nil unless products.modulo(x) == 0
      witness = g.pow(products / x, n)
      RSA::ACC::MembershipProof.new(elements, witness, value, RSA::ACC::PoE.prove(witness, x, value, n))
    end

    # Generate non-membership proof using set of elements in current acc and non membership elements.
    # @param [Array[String]] members The entire set of elements contained within this accumulator.
    # @param [Array[String]] non_members Elements not included in this accumulator that you want to prove non-membership.
    # @return [RSA::ACC::NonMembershipProof] Non-membership proof.
    def prove_non_membership(members, non_members)
      s = elements_to_prime(members)
      x = elements_to_prime(non_members)

      a, b = egcd(s, x)
      raise ArgumentError, "Inputs not co-prime." unless a * s + b * x == 1

      v = value.pow(a, n)
      d = g.pow(b, n)
      gv_inv = (g * v.pow(-1, n)) % n

      poke2_proof = RSA::ACC::PoKE2.prove(value, a, v, n)
      poe_proof = RSA::ACC::PoE.prove(d, x, gv_inv, n)

      RSA::ACC::NonMembershipProof.new(d, v, gv_inv, poke2_proof, poe_proof)
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
      self.products = self.products / proof_product if hold_elements
      self.value = new_value
      RSA::ACC::MembershipProof.new(proofs.map{|p|p.element}.flatten, value, current_value, RSA::ACC::PoE.prove(value, proof_product, current_value, n))
    end

    # Computes an xi-th root of +y+ for all i = 1, ..., n in total time O(n log(n)).
    # @param [Array[Integer]] f factorizations of the exponent x = x1, ..., xn.
    # @return [Array{Integer}] array of xi-th root
    def root_factor(*f)
      return [value] if f.size == 1
      half_n = f.size / 2
      g_l = RSA::Accumulator.new(n, value.pow(f[0...half_n].map.inject(:*), n), g, false)
      g_r = RSA::Accumulator.new(n, value.pow(f[half_n..-1].map.inject(:*), n), g, false)
      l = g_r.root_factor(*f[0...half_n])
      r = g_l.root_factor(*f[half_n..-1])
      [l, r].flatten
    end

  end
end
