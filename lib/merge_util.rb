class MergeUtil
  class << self
    def deep_merge(hash_a = {}, hash_b = {}, combine_arrays = false)
      return hash_a.deep_merge(hash_b || {}) unless combine_arrays

      hash_a.deep_merge(hash_b || {}) do |_k, v1, v2|
        v1.is_a?(Array) && v2.is_a?(Array) ? (v1 + v2).uniq : v2
      end
    end
  end
end
