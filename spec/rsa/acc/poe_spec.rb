require 'spec_helper'

RSpec.describe RSA::ACC::PoE do

  include RSA::ACC::Functions

  let(:modulus) { RSA::Accumulator::RSA2048_MODULUS }

  describe 'quotient group Z_n^* / {+-1}' do
    it 'should identify a result with its negation.' do
      # -result used to be a value distinct from result, and proof = -base^q proved
      # base^exp == -result because l is always an odd prime, hence (-1)^l == -1.
      # In the quotient group there is no such distinct statement left to prove.
      base = 2
      exp = hash_to_prime('a') * hash_to_prime('b')
      result = base.pow(exp, modulus)
      expect(normalize(modulus - result, modulus)).to eq(normalize(result, modulus))
    end

    it 'should reject a result that is not +-base^exp, whichever sign the proof has.' do
      base = 2
      exp = hash_to_prime('a') * hash_to_prime('b')
      wrong = normalize(base.pow(exp + 2, modulus), modulus)
      q = exp / compute_challenge(base, exp, wrong)
      [base.pow(q, modulus), modulus - base.pow(q, modulus)].each do |forged|
        expect(RSA::ACC::PoE.verify(base, exp, wrong, forged, modulus)).to be false
      end
    end

    it 'should treat an element and its negation as the same element.' do
      base = 2
      exp = hash_to_prime('a')
      result = normalize(base.pow(exp, modulus), modulus)
      proof = RSA::ACC::PoE.prove(base, exp, result, modulus)
      expect(proof).to eq(normalize(proof, modulus))
      expect(RSA::ACC::PoE.verify(base, exp, result, proof, modulus)).to be true
      expect(RSA::ACC::PoE.verify(modulus - base, exp, modulus - result, modulus - proof, modulus)).to be true
    end
  end

  describe 'proof for small exp' do
    it 'should be proven.' do
      base = 2
      exp = 20
      result = 1_048_576 # 2^20 = 1048576
      proof = RSA::ACC::PoE.prove(base, exp, result, RSA::Accumulator::RSA2048_MODULUS)
      expect(RSA::ACC::PoE.verify(base, exp, result, proof, RSA::Accumulator::RSA2048_MODULUS)).to be true
      expect(proof).to eq(1)

      exp = 35
      result = 34_359_738_368 # 2^35 = 34359738368
      proof = RSA::ACC::PoE.prove(base, exp, result, RSA::Accumulator::RSA2048_MODULUS)
      expect(RSA::ACC::PoE.verify(base, exp, result, proof, RSA::Accumulator::RSA2048_MODULUS)).to be true
      expect(proof).to eq(1)
    end
  end

end