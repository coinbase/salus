require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportRustCrates do
  describe "#run" do
    it 'should report all the deps in the Cargo.lock if manifest is absent in cyclonedx' do
      repo = Salus::Repo.new('spec/fixtures/report_rust_crates/lock_only')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
      scanner.run

      rust_cyclonedx = Cyclonedx::ReportRustCrates.new(scanner.report)
      expect(rust_cyclonedx.build_components_object[0..2]).to match_array(
        [
          {
            "type": "library",
          "group": "",
            "name": "autocfg",
            "version": "0.1.7",
            "purl": "pkg:cargo/autocfg@0.1.7"
          },
          {
            "type": "library",
          "group": "",
            "name": "bitflags",
            "version": "1.2.1",
            "purl": "pkg:cargo/bitflags@1.2.1"
          },
          {
            "type": "library",
          "group": "",
            "name": "cloudabi",
            "version": "0.0.3",
            "purl": "pkg:cargo/cloudabi@0.0.3"
          }
        ]
      )
    end

    it 'should calculate and report all the dependencies in the manifest if Cargo.lock is absent' do
      repo = Salus::Repo.new('spec/fixtures/report_rust_crates/manifest_only')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
      # Cargo tree will create a lock file if not already present
      # We will stub the lock file generate to keep our specs from needing to
      # hit the internet and pulldown the dependency graph
      allow(scanner).to receive(:run_shell).with(/cargo tree/, chdir: nil) do
        existing_lock = 'spec/fixtures/report_rust_crates/lock_only/Cargo.lock'
        mock_lock = File.join(repo.path_to_repo, 'Cargo.lock')
        FileUtils.cp existing_lock, mock_lock
      end

      scanner.run

      rust_cyclonedx = Cyclonedx::ReportRustCrates.new(scanner.report)
      expected = [
        {
          "type": "library",
          "group": "",
          "name": "autocfg",
          "version": "0.1.7",
          "purl": "pkg:cargo/autocfg@0.1.7"
        },
        {
          "type": "library",
          "group": "",
            "name": "bitflags",
            "version": "1.2.1",
            "purl": "pkg:cargo/bitflags@1.2.1"
        },
        {
          "type": "library",
          "group": "",
            "name": "cloudabi",
            "version": "0.0.3",
            "purl": "pkg:cargo/cloudabi@0.0.3"
        }
      ]
      expect(rust_cyclonedx.build_components_object).to include(*expected)
    end

    it 'should prefer the Cargo.lock over the manifest when both available' do
      repo = Salus::Repo.new('spec/fixtures/report_rust_crates/manifest_and_lock')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})

      scanner.run

      rust_cyclonedx = Cyclonedx::ReportRustCrates.new(scanner.report)
      expect(rust_cyclonedx.build_components_object[0..2]).to match_array(
        [
          {
            "type": "library",
          "group": "",
            "name": "autocfg",
            "version": "0.1.7",
            "purl": "pkg:cargo/autocfg@0.1.7"
          },
          {
            "type": "library",
          "group": "",
            "name": "bitflags",
            "version": "1.2.1",
            "purl": "pkg:cargo/bitflags@1.2.1"
          },
          {
            "type": "library",
          "group": "",
            "name": "cloudabi",
            "version": "0.0.3",
            "purl": "pkg:cargo/cloudabi@0.0.3"
          }
        ]
      )
    end
  end
end
