require_relative '../../spec_helper.rb'

describe Salus::DiceCoefficient do
  let(:string_a) { 'hello' }
  let(:string_b) { 'world' }
  let(:string_c) { 'hello.' }
  let(:string_d) { 'ioklo' }

  it 'should return 1.0 if two strings are same' do
    expect(described_class.dice(string_a, string_a)).to eql(1.0)
  end

  it 'should return 0.0 if two strings are completely different' do
    expect(described_class.dice(string_a, string_b)).to eql(0.0)
  end

  it 'should return higher value if two strings are very similar' do
    expect(described_class.dice(string_a, string_c)).to be > 0.8
  end

  it 'should return lower value if two strings are less similar' do
    expect(described_class.dice(string_a, string_d)).to be < 0.3
  end
end
