require 'spec_helper'

RSpec.describe RSA::ACC::PoKE2 do

  using RSA::ACC::Ext

  describe 'prove/verify' do

    context 'positive number' do
      it 'should generate proof and verify proof.' do
        # 2^20 = 1048576
        base = 2
        exp = 20
        result = 1_048_576
        proof = RSA::ACC::PoKE2.prove(base, exp, result, RSA::Accumulator::RSA3072_MODULUS)
        expect(RSA::ACC::PoKE2.verify(base, result, proof, RSA::Accumulator::RSA3072_MODULUS)).to be true
        expect(proof).to eq(RSA::ACC::PoKE2Proof.new(1_048_576, 1, 20))

        # 2^35 = 34359738368
        exp = 35
        result = 34_359_738_368
        proof = RSA::ACC::PoKE2.prove(base, exp, result, RSA::Accumulator::RSA3072_MODULUS)
        expect(RSA::ACC::PoKE2.verify(base, result, proof, RSA::Accumulator::RSA3072_MODULUS)).to be true
        expect(proof).to eq(RSA::ACC::PoKE2Proof.new(34_359_738_368, 1, 35))
      end
    end

    context 'negative number' do
      it 'should generate proof and verify proof.' do
        base = 2
        exp = -5
        result = base.pow(exp, RSA::Accumulator::RSA3072_MODULUS)
        proof = RSA::ACC::PoKE2.prove(base, exp, result, RSA::Accumulator::RSA3072_MODULUS)
        expect(RSA::ACC::PoKE2.verify(base, result, proof, RSA::Accumulator::RSA3072_MODULUS)).to be true
      end
    end
  end

end