require_relative '../../spec_helper'

describe Cyclonedx::PackageUrl do
  describe "purl format matches expected" do
    it 'purl format is correct with no special characters' do
      purl = Cyclonedx::PackageUrl.new(type: "npm", namespace: "prediction", version: "1.2.0")
        .to_string
      expect(purl).to eq("pkg:npm/prediction@1.2.0")
    end

    it 'purl format is correct with no version' do
      purl = Cyclonedx::PackageUrl.new(type: "npm", namespace: "prediction", version: "").to_string
      expect(purl).to eq("pkg:npm/prediction")
    end

    it 'purl format is correct with percent encoded strings' do
      purl = Cyclonedx::PackageUrl.new(type: "npm",
                                       namespace: "@magi-core/prediction",
                                       version: "1.2.0").to_string
      expect(purl).to eq("pkg:npm/%40magi-core/prediction@1.2.0")
    end

    it 'purl format removes leading and trailing / from namespace' do
      purl = Cyclonedx::PackageUrl.new(type: "npm",
                                       namespace: "/@magi-core/prediction/",
                                       version: "1.2.0").to_string
      expect(purl).to eq("pkg:npm/%40magi-core/prediction@1.2.0")
    end
  end
end
