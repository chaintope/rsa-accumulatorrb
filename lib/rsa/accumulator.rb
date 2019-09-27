require "rsa/acc/version"
require 'rsa/acc/functions'
require 'openssl'
require 'securerandom'

module RSA
  class Accumulator

    include RSA::ACC::Functions

    attr_reader :n
    attr_accessor :value

    # Initialize accumulator
    # @param [Integer] bit_length bit length of accumulator. Default: 3072 bits.
    # @return [RSA::Accumulator]
    def initialize(bit_length = 3072)
      @n = OpenSSL::PKey::RSA.generate(bit_length).n.to_i
      @value = SecureRandom.random_number(@n)
    end

    # Add element to accumulator
    # @param [String] element an element to be added.
    # @return [RSA::Accumulator] an updated accumulator.
    def add(element)
      p = hash_to_prime(element)
      @value = value.pow(p, n)
    end

    def member?(element)

    end

  end
end
