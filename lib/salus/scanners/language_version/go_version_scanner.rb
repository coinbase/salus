require 'salus/scanners/language_version/base'

module Salus::Scanners::LanguageVersion
  class GoVersionScanner < Base
    def self.supported_languages
      %w[go]
    end

    private

    def lang_version
      @lang_version ||= go_project? ? go_version : nil
    end

    def run_version_scan?
      go_project?
    end

    # If we run 'go mod edit -json' for a 'go' project,
    # it returns the details of go mod in json format.
    # We can parse the json file to get the 'go' language version used
    # Following is a sample output for running 'go mod edit -json':
    # {
    # "Module": {
    #   "Path": "example.com/mymodule"
    # },
    # "Go": "1.16",
    #  ...}
    def go_version
      shell_return = run_shell("go mod edit -json")

      shell_return_json = JSON.parse(shell_return.stdout)

      shell_return_json["Go"]
    end

    def go_project?
      @repository.go_mod_present?
    end
  end
end
