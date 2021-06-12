require_relative '../../spec_helper.rb'

describe Salus::CLI do
  it 'returns non-zero exit when invalid params are passed' do
    expect { Salus::CLI.start(['foo bar']) }.to raise_error(SystemExit) do |error|
      expect(error.status).to eq(1)
    end
  end

  it 'returns zero on success' do
    Salus::CLI.start([])
  rescue SystemExit => e
    expect(e.status).to eq 0 # exited with failure status
  end
end
