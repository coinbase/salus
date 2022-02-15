require_relative '../spec_helper.rb'

describe MergeUtil do
  describe "deep_merge" do
    let(:a) { { active_scanners: [1, 2, 3], config: { a: true } } }
    let(:b) { { active_scanners: [3, 4, 5], config: { b: true } } }

    it "should overwite arrays by default" do
      merged = MergeUtil.deep_merge(a, b)
      expect(merged).to eq({ active_scanners: [3, 4, 5], config: { a: true, b: true } })
    end

    it "should overwrite arrays when combine is false" do
      merged = MergeUtil.deep_merge(a, b, false)
      expect(merged).to eq({ active_scanners: [3, 4, 5], config: { a: true, b: true } })
    end

    it "should concat arrays when combine is true" do
      merged = MergeUtil.deep_merge(a, b, true)
      expect(merged).to eq({ active_scanners: [1, 2, 3, 4, 5], config: { a: true, b: true } })
    end
  end
end
