require_relative '../../spec_helper.rb'
require 'json'

describe Sarif::PatternSearchSarif do
  context '#parse_issue' do
    repo = Salus::Repo.new('spec/fixtures/pattern_search')
    config = {
      'matches' => [
        { 'regex' => 'Nerv', 'required' => true, 'message' => 'important string' }
      ]
    }

    scanner = Salus::Scanners::PatternSearch.new(repository: repo, config: config)
    scanner.run
    adapter = Sarif::PatternSearchSarif.new(scanner.report)
    x = scanner.report.to_h.dig(:info, :hits)
    puts adapter.parse_issue(x[0])
    puts adapter.parse_issue(x[0])
    puts adapter.build_runs_object(true)
  end
end
