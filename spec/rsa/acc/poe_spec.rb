require 'spec_helper'

RSpec.describe RSA::ACC::PoE do

  let(:test_class) { Struct.new(:poe){include RSA::ACC::PoE}}
  let(:poe) {test_class.new}

  describe 'proof for small exp' do
    it 'should be proven.' do
      base = 2
      exp = 20
      result = 1_048_576 # 2^20 = 1048576
      proof = poe.prove(base, exp, result, RSA::Accumulator::RSA2048_MODULUS)
      expect(poe.valid?(base, exp, result, proof, RSA::Accumulator::RSA2048_MODULUS)).to be true
      expect(proof).to eq(1)

      exp = 35
      result = 34_359_738_368 # 2^35 = 34359738368
      proof = poe.prove(base, exp, result, RSA::Accumulator::RSA2048_MODULUS)
      expect(poe.valid?(base, exp, result, proof, RSA::Accumulator::RSA2048_MODULUS)).to be true
      expect(proof).to eq(1)
    end
  end

end