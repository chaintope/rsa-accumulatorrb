require 'spec_helper'

RSpec.describe RSA::Accumulator do

  it "has a version number" do
    expect(RSA::ACC::VERSION).not_to be nil
  end

  describe '#initialize' do
    it 'should generate n and acc' do
      acc = RSA::Accumulator.new
      expect(acc.n).is_a?(Integer)
      expect(acc.acc).is_a?(Integer)
      expect(acc.acc < acc.n).to be true
      expect(acc.n.bit_length).to eq(3072)
    end
  end

end
