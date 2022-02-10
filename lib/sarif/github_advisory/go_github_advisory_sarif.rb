require 'sarif/github_advisory/base_sarif'

module Sarif
  class GoGithubAdvisorySarif < Sarif::GithubAdvisory::BaseSarif
    def parse_issue(issue)
      super.merge(
        {
          name: "GoGithubAdvisory"
        }
      )
    end
  end
end
