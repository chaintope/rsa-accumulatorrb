require "rsa/acc/version"
require 'rsa/acc/functions'
require 'openssl'
require 'securerandom'

module RSA
  class Accumulator

    attr_reader :n
    attr_reader :acc

    def initialize(key_size = 3072)
      @n = OpenSSL::PKey::RSA.generate(key_size).n.to_i
      @acc = SecureRandom.random_number(@n)
    end

  end
end
