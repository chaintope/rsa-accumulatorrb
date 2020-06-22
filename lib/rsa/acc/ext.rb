# Extending an existing class
module RSA
  module ACC

    module Ext

      refine Integer do
        def pow(*several_variants)
          return super(*several_variants) if several_variants.size == 1
          return super(*several_variants) unless several_variants.first.negative?
          exp = several_variants.first
          inv = self.to_bn.mod_inverse(several_variants[1]).to_i
          inv.pow(-exp, several_variants[1])
        end
      end

    end

  end
end