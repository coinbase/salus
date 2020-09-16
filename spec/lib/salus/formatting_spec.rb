require_relative '../../spec_helper.rb'

class DummyClass
  include Salus::Formatting
end

describe Salus::Formatting do
  describe 'prettify_json_string' do
    let(:instance) { DummyClass.new }
    it 'returns pretty json from valid json string' do
      json_str = '{"hello": "world"}'
      expected = %({\n  "hello": "world"\n})

      pretty = instance.prettify_json_string(json_str)
      expect(pretty).to eq(expected)
    end

    it 'returns input string if json parse fails' do
      json_str = '{"won"t ": "parse "}'
      pretty = instance.prettify_json_string(json_str)
      expect(pretty).to eq(json_str)
    end
  end
end
