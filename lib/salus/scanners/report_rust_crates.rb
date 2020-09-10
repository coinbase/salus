require 'toml'
require 'salus/scanners/base'

# Report the use of any Rust Crates.

module Salus::Scanners
  class ReportRustCrates < Base
    LOCK_FILE = 'Cargo.lock'.freeze
    MANIFEST_FILE = 'Cargo.toml'.freeze

    def should_run?
      @repository.cargo_present? || @repository.cargo_lock_present?
    end

    def run
      if should_run?
        record_dependencies
      else
        raise InvalidScannerInvocationError,
              'Cannot report on crates without a manifest or lock file'
      end
    end

    private

    def with_lock_file
      manifest_path = File.join(@repository.path_to_repo, MANIFEST_FILE)
      lock_path = File.join(@repository.path_to_repo, LOCK_FILE)

      existing_lock = File.exist?(lock_path)

      # Cargo tree will generate the lock and return the list of dependencies
      # No point in coding two paths for dependencies so we'll just use
      # cargo tree's ability to generate the .lock file
      run_shell("cargo tree --manifest-path #{manifest_path}") unless existing_lock

      yield
      # Cleanup after ourselves if we generated a lock file
      File.delete(lock_path) if !existing_lock && File.exist?(lock_path)
    end

    def record_dependencies
      with_lock_file do
        record_dependencies_from_lock
      end
    end

    def record_dependencies_from_lock
      deps = TOML::Parser.new(@repository.cargo_lock).parsed

      # Sample Package
      # { "name"=>"autocfg",
      # "version"=>"0.1.7",
      # "source"=>"registry+https://github.com/rust-lang/crates.io-index",
      # "checksum"=>"1d49d90015b3c36167a20fe2810c5cd875ad504b39cff3d4eae7977e6b7c1cb2" },

      deps["package"].each do |package|
        report_dependency(
          LOCK_FILE,
          type: LOCK_FILE.parameterize.underscore,
          name: package['name'],
          reference: package['source'],
          version_tag: package['version']
        )
      end
    end
  end
end
