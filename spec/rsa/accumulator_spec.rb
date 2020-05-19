require 'spec_helper'

RSpec.describe RSA::Accumulator do

  include RSA::ACC::Functions

  it "has a version number" do
    expect(RSA::ACC::VERSION).not_to be nil
  end

  describe '#initialize' do
    it 'should generate n and acc' do
      acc = RSA::Accumulator.generate_random
      expect(acc.n).is_a?(Integer)
      expect(acc.value).is_a?(Integer)
      expect(acc.value < acc.n).to be true
      expect(acc.n.bit_length).to eq(3072)
    end
  end

  describe '#add' do
    it 'should generate updated acc' do
      acc = RSA::Accumulator.generate_random
      initial = acc.value
      acc.add('a')
      acc.add('b')
      acc.add('c')
      acc.add('d')
      p = hash_to_prime('a') * hash_to_prime('b') * hash_to_prime('c') * hash_to_prime('d')
      expect(acc.value).to eq(initial.pow(p, acc.n))
    end
  end

end
