require 'spec_helper'

RSpec.describe RSA::ACC::PoE do

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