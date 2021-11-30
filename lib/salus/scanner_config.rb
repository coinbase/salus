module Salus
  class ScannerConfig
    attr_reader :config

    def initialize(_config)
      @config
    end

    def recursion?
      @config.key?('recursion')
    end

    { "pass_on_raise" => false,
     "scanner_timeout_s" => 0,
     "directory_exclusions" => %w[vendor specs],
     "recursion" => { "directories" => ["./", "payments/lhv", "infra/sso/identity_provider"], "directories_matching" => ["filename:\"BUILD.bazel\" content:\"bundle//:rails\""] },
     "static_files" => ["Gemfile", "Gemfile.lock"] }

    # {"pass_on_raise"=>false, "scanner_timeout_s"=>0},

    def matching_repos
      # TODO: delete this
      [Repo.new(@path_to_repo)]
    end

    def recurse?
      @scanner_config.key?('recursion')
    end
  end
end
