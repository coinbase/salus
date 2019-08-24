require_relative '../../../spec_helper.rb'

describe Salus::Scanners::YarnAudit do
  describe '#should_run?' do
    it 'should return false in the absence of package.json and friends' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      expect(repo.yarn_lock_present?).to eq(false)

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(false)
    end

    it 'should return true if package.json is present' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/success')
      expect(repo.yarn_lock_present?).to eq(true)

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#run' do
    it 'should exclude dependencies when given a group' do
    end

    it 'should warn if only optionalDependencies are scanned' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/success')

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {
                                                 "exclude_groups" =>
                                                 %w[devDependencies dependencies]
                                               })

      scanner.run
      expect(scanner.report.to_h.fetch(:warn)).to include(
        scanner_misconfiguration: "Scanning only optionalDependencies!"
      )
    end

    it 'should error if all 3 groups are excluded' do
      repo = Salus::Repo.new('spec/fixtures/yarn_audit/success')

      scanner = Salus::Scanners::YarnAudit.new(repository: repo, config: {
                                                 "exclude_groups" => %w[devDependencies
                                                                        dependencies
                                                                        optionalDependencies]
                                               })
      scanner.run
      expect(scanner.report.to_h.fetch(:errors)).to include(
        message: "No dependencies were scanned!"
      )
    end
  end
end
