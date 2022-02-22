require_relative '../../spec_helper.rb'

describe Salus::PathValidator do
  describe 'local_to_base?' do
    it 'should return false for files outside parent directory' do
      [{ base: 'spec', path: 'spec/foo' },
       { base: 'spec', path: 'spec/foo/bar' }].each do |row|
        local = Salus::PathValidator.new(row[:base]).local_to_base?(row[:path])
        expect(local).to eq(true), "#{row} is not local"
      end
    end

    it 'should return false for folders outside parent directory' do
      local =  Salus::PathValidator.new('spec').local_to_base?('../')
      expect(local).to be false
    end
  end
end
