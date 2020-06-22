# Extending an existing class

class Integer

  def pow_with_negative(*several_variants)
    return default_pow(*several_variants) if several_variants.size == 1
    return default_pow(*several_variants) unless several_variants.first.negative?
    exp = several_variants.first
    inv = self.to_bn.mod_inverse(several_variants[1]).to_i
    inv.default_pow(-exp, several_variants[1])
  end

  alias_method :default_pow, :pow
  alias_method :pow, :pow_with_negative
end