require_relative '../../spec_helper.rb'

describe Salus::ConfigException do
  describe '#initialize' do
    it 'should support initializing from a hash' do
      h = { 'advisory_id' => 1, 'notes' => 'none', 'changed_by' => 'Our team' }
      exception = Salus::ConfigException.new(h)
      expect(exception.valid?).to be true
      expect(exception.advisory_id).to eq(1)
      expect(exception.notes).to eq("none")
      expect(exception.changed_by).to eq("Our team")
    end

    it 'should create an invalid exception if no params are passed' do
      exception = Salus::ConfigException.new
      expect(exception.valid?).to be false
    end
  end

  describe 'validation' do
    it 'should require the expected fields' do
      expect(Salus::ConfigException.new({}).valid?).to be false
      expect(Salus::ConfigException.new({ 'advisory_id' => 1 }).valid?).to be false
      expect(Salus::ConfigException.new({ 'advisory_id' => 1, 'notes' => "" }).valid?).to be false
      nil_change_by = { 'advisory_id' => 1, 'notes' => "", "changed_by" => nil }
      expect(Salus::ConfigException.new(nil_change_by).valid?).to be false
      empty = { 'advisory_id' => 1, 'notes' => "", "changed_by" => "" }
      expect(Salus::ConfigException.new(empty).valid?).to be true
    end
  end

  describe 'active?' do
    before(:each) do
      allow(Date).to receive(:today).and_return Date.new(2021, 12, 31)
    end

    it 'should return true if no expiration was given' do
      empty = { 'advisory_id' => 1, 'notes' => "", "changed_by" => "" }
      expect(Salus::ConfigException.new(empty).active?).to be true
    end

    it 'should return true if empty expiration was given' do
      expect(Salus::ConfigException.new({ 'advisory_id' => 1,
        'notes' => "", "changed_by" => "", "expiration" => "" }).active?).to be true
    end

    it 'should return false for past dates' do
      exception = Salus::ConfigException.new({ 'advisory_id' => 1,
        'notes' => "", "changed_by" => "", "expiration" => "2000-12-31" })
      expect(exception.active?).to be false
    end

    it 'should return true for current date' do
      exception = Salus::ConfigException.new({ 'advisory_id' => 1,
        'notes' => "", "changed_by" => "", "expiration" => "2021-12-31" })
      expect(exception.active?).to be true
    end

    it 'should return true for future dates' do
      exception = Salus::ConfigException.new({ 'advisory_id' => 1,
        'notes' => "", "changed_by" => "", "expiration" => "2022-12-31" })
      expect(exception.active?).to be true
    end
  end
end
