require_relative '../../spec_helper.rb'

describe Salus::CLI do
  it 'returns non-zero exit when invalid params are passed' do
    expect { Salus::CLI.start(['foo bar']) }.to raise_error(SystemExit) do |error|
      expect(error.status).to eq(1)
    end
  end
end
