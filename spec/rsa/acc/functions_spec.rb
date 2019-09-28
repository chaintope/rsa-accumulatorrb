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

end