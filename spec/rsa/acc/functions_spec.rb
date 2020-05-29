require 'spec_helper'

RSpec.describe RSA::ACC::Functions do

  let(:test_class) { Struct.new(:functions){include RSA::ACC::Functions}}
  let(:functions) {test_class.new}

  describe '#hash_to_prime' do
    it 'should convert element to prime' do
      p1 = functions.hash_to_prime("hoge")
      expect(p1.to_bn.prime?).to be true
      expect(functions.hash_to_prime("hoge")).to eq(p1) # same value outputs same prime number.

      p2 = functions.hash_to_prime("foge")
      expect(p1 == p2).to be false
    end
  end

  describe '#shamir_trick' do
    context 'Inputs is co-prime' do
      it 'should return xyth root.' do
        x, y, z = 13, 17 ,19
        xth_root = 2.pow(y * z, RSA::Accumulator::RSA2048_MODULUS)
        yth_root = 2.pow(x * z, RSA::Accumulator::RSA2048_MODULUS)
        xyth_root = 2.pow(z, RSA::Accumulator::RSA2048_MODULUS)
        expect(functions.shamir_trick(xth_root, yth_root, x, y, RSA::Accumulator::RSA2048_MODULUS)).to eq(xyth_root)
      end
    end

    context 'Inputs is not co-prime' do
      it 'should raise error.' do
        x, y, z = 7, 14 ,19
        xth_root = 2.pow(y * z, RSA::Accumulator::RSA2048_MODULUS)
        yth_root = 2.pow(x * z, RSA::Accumulator::RSA2048_MODULUS)
        expect{functions.shamir_trick(xth_root, yth_root, x, y, RSA::Accumulator::RSA2048_MODULUS)}.to raise_error(ArgumentError, 'Inputs does not co-prime.')
      end
    end
  end

end