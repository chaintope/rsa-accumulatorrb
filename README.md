# RSA Accumulator for Ruby [![Build Status](https://travis-ci.org/chaintope/rsa-accumulatorrb.svg?branch=master)](https://travis-ci.org/chaintope/rsa-accumulatorrb) [![Gem Version](https://badge.fury.io/rb/rsa-accumulator.svg)](https://badge.fury.io/rb/rsa-accumulator) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)


Cryptographic accumulator based on the strong RSA assumption [BBF18](https://eprint.iacr.org/2018/1188.pdf) in Ruby.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rsa-accumulator'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rsa-accumulator

## Usage

### Setup accumulator

First, initialize the accumulator. Since the accumulator uses groups of unknown order, it can be generated in following ways:

    require 'rsa-accumulator'
    
    # using RSA modulus published by RSA Laboratory
    acc = RSA::Accumulator.generate_rsa2048

    # using Random RSA modulus with a specified bit length(default value is )
    acc = RSA::Accumulator.generate_random(2048)

### Adding elements and membership proof

You can add arbitrary String data to the accumulator.

    acc.add('a', 'b')
    proof = acc.add('c')

You can use inclusion proof to prove that an element exists in an accumulator.

    acc.member?(proof)

### Non membership proof

You can generate non-membership proof and prove that the elements does not exist in the accumulator.

    members = %w(a b)
    non_members = %w(c, d)
    acc.add(*members)
    proof = acc.prove_non_membership(members, non_members)
    acc.non_member?(non_members, proof)
    => true

### Delete element from accumulator

You can remove elements from the accumulator by providing the inclusion proof.

    acc.add('a', 'b')
    proof = acc.add('c')
    acc.delete(proof)
    
    acc.member?(proof)
    => false
    