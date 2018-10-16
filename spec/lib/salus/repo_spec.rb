require_relative '../../spec_helper.rb'

describe Salus::Repo do
  describe 'IMPORTANT_FILES runtime defined functions' do
    it 'should create a getter and presence check method for special files' do
      repository = Salus::Repo.new('spec/fixtures/repo')
      expect(repository.gemfile_present?).to eq(true)
      expect(repository.gemfile).to match(/ruby '2\.3\.0'/)
      expect(repository.gemfile_lock_present?).to eq(false)
      expect(repository.gemfile_lock).to be_nil
    end
  end
end
