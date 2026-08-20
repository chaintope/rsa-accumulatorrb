# RSA Accumulator for Ruby [![Build Status](https://github.com/chaintope/rsa-accumulatorrb/actions/workflows/ruby.yml/badge.svg?branch=master)](https://github.com/chaintope/rsa-accumulatorrb/actions/workflows/ruby.yml) [![Gem Version](https://badge.fury.io/rb/rsa-accumulator.svg)](https://badge.fury.io/rb/rsa-accumulator) [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)


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

First, initialize the accumulator. The accumulator works in a group of unknown order, so its
security depends on **nobody knowing the factorization of the modulus**. There are three ways
to obtain one:

    require 'rsa-accumulator'

    # 1. RSA-2048, the modulus published by RSA Laboratories. Its factorization has never
    #    been found, so no trusted setup is required. This is the recommended default.
    acc = RSA::Accumulator.generate_rsa2048

    # 2. A modulus you obtained elsewhere, e.g. from a multi-party trusted setup ceremony.
    acc = RSA::Accumulator.generate_with_modulus(n)

    # 3. A freshly generated random RSA modulus with the given bit length (default: 3072).
    acc = RSA::Accumulator.generate_random(2048)

> [!WARNING]
> `generate_random` is a **trusted setup**. It derives the modulus from a newly generated RSA
> key, so the process that calls it learns `p` and `q`. Anyone holding the factorization can
> compute an x-th root of any value, and can therefore forge a membership proof for an element
> that was never added, as well as a non-membership proof for an element that was. Use it only
> when every verifier of the resulting proofs trusts the party that created the accumulator.
> Otherwise use `generate_rsa2048` or `generate_with_modulus`.

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
    
### Holding the product of all elements

This feature is experimental and has not been checked against large amounts of data.

    acc = RSA::Accumulator.generate_rsa2048(hold_elements: true)
    acc.add('a', 'b', 'c')
    acc.add('d', 'e')
    
    # acc has product of all elements in acc#products, so you can get membership proof.
    proof = acc.prove_membership('b')

    