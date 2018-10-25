require 'salus/scanners/base'

# Scanner to check that the repository being scanned is not empty.
# This is part of the *strong defaults* philosophy which tries to
# ensure that misconfiguration is caught quickly and does not silently fail.

module Salus::Scanners
  class RepoNotEmpty < Base
    def run
      # We check there is at least one item in this repo.
      if directory_empty?
        report_error(
          'Salus was run on a blank directory. This may indicate misconfiguration '\
          'such as not correctly voluming in the repository to be scanned.'
        )
        report_failure
      else
        report_success
      end
    end

    def should_run?
      true
    end

    private

    def directory_empty?
      Dir["#{@repository.path_to_repo}/*"].empty?
    end
  end
end
