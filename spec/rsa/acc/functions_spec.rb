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

  describe 'unambiguous hashing' do
    it 'should not let a different parameter split produce the same challenge.' do
      # even_hex is variable length, so joining without a separator makes
      # (0x01, 0x2345) and (0x0123, 0x45) collide on "012345".
      expect(functions.compute_challenge(0x01, 0x2345, 0xdead))
          .not_to eq(functions.compute_challenge(0x0123, 0x45, 0xdead))
      expect(functions.blake2_hash(0x01, 0x2345, 0xdead))
          .not_to eq(functions.blake2_hash(0x0123, 0x45, 0xdead))
    end

    it 'should separate the element domain from the challenge domain.' do
      # An element is caller supplied. Without domain separation it can be set to the hex
      # encoding a challenge is built from, and land on the very same prime.
      params = [0x01, 0x2345, 0xdead]
      concatenated = params.map { |v| functions.send(:even_hex, v) }.join
      expect(functions.hash_to_prime(concatenated))
          .not_to eq(functions.compute_challenge(*params))
    end

    it 'should separate the element from the nonce.' do
      # The nonce used to be appended to the element with no separator, so element "x" at
      # nonce 0x0100 and element "x01" at nonce 0 were hashed from the same byte string.
      dst = RSA::ACC::Functions::ELEMENT_DST
      expect(functions.send(:encode_fields, dst, ['x', functions.send(:even_hex, 256)]))
          .not_to eq(functions.send(:encode_fields, dst, ['x01', functions.send(:even_hex, 0)]))
    end

    it 'should not coerce a non String element.' do
      # nil.to_s and "" are the same bytes, so coercing would merge them into one element.
      [nil, :a, 1, ['a']].each do |bad|
        expect { functions.hash_to_prime(bad) }.to raise_error(TypeError)
      end
    end

    it 'should always produce a prime of the same width.' do
      widths = %w(a b c d e f g h i j).map { |e| functions.hash_to_prime(e).bit_length }
      expect(widths.uniq).to eq([512])
    end
  end

  describe '#elements_to_prime' do
    it 'should reject anything that is not a non-empty list of String.' do
      [[], nil, 'a', [nil], ['a', 1], [['a']]].each do |bad|
        expect { functions.elements_to_prime(bad) }.to raise_error(ArgumentError)
      end
      expect(functions.elements_to_prime(%w(a b)))
          .to eq(functions.hash_to_prime('a') * functions.hash_to_prime('b'))
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