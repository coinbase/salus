require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportRustCrates do
  describe '#run' do
    let(:expected_packages) do
      [{ type: "cargo",
           name: "autocfg",
           reference: "registry+https://github.com/rust-lang/crates.io-index",
           version: "0.1.7",
           dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "bitflags",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "1.2.1",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "cloudabi",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.0.3",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
        name: "foo",
        reference: nil,
        version: "0.1.0",
        dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "fuchsia-cprng",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.1",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "libc",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.2.77",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.6.5",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_chacha",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.1",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_core",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.3.1",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_core",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.4.2",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_hc",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.0",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_isaac",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.1",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_jitter",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.4",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_os",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.3",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_pcg",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.2",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rand_xorshift",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.1.1",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "rdrand",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.4.0",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "winapi",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.3.9",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "winapi-i686-pc-windows-gnu",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.4.0",
         dependency_file: "Cargo.lock" },
       { type: "cargo",
         name: "winapi-x86_64-pc-windows-gnu",
         reference: "registry+https://github.com/rust-lang/crates.io-index",
         version: "0.4.0",
         dependency_file: "Cargo.lock" }]
    end

    it 'should throw an error in the absence of Create.toml' do
      repo = Salus::Repo.new('spec/fixtures/blank_repository')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})

      expect { scanner.run }.to raise_error(
        Salus::Scanners::Base::InvalidScannerInvocationError,
        'Cannot report on crates without a manifest or lock file'
      )
    end

    it 'should calculate and report all the dependencies in the manifest if lock is absent' do
      repo = Salus::Repo.new('spec/fixtures/report_rust_crates/manifest_only')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})

      # We will stub the lock file generate to keep our specs from needing to
      # hit the internet and pulldown the dependency graph
      allow(scanner).to receive(:run_shell).with(/cargo tree/, chdir: nil) do
        existing_lock = 'spec/fixtures/report_rust_crates/lock_only/Cargo.lock'
        mock_lock = File.join(repo.path_to_repo, 'Cargo.lock')
        FileUtils.cp existing_lock, mock_lock
      end

      scanner.run

      info = scanner.report.to_h.fetch(:info)
      expect(info[:dependencies]).to match_array(expected_packages)
    end

    it 'should raise an error when unable to generate the .lock file' do
      repo = Salus::Repo.new('spec/fixtures/report_rust_crates/manifest_only')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})

      # Mock with an empty stub to prevent the .lock file from being generated
      expect(scanner).to receive(:run_shell).with(/cargo tree/, chdir: nil)

      msg = 'Rust .lock file missing.Check write premissions and Cargo version is at least 1.44'
      expect { scanner.run }.to raise_error(Salus::Scanners::ReportRustCrates::MissingRustLock,
                                            msg)
    end

    it 'should report all deps in lock' do
      repo = Salus::Repo.new('spec/fixtures/report_rust_crates/lock_only')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
      scanner.run
      info = scanner.report.to_h.fetch(:info)
      expect(info[:dependencies]).to match_array(expected_packages)
    end

    it 'should prefer the lock over the manifest' do
      repo = Salus::Repo.new('spec/fixtures/report_rust_crates/manifest_and_lock')
      scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
      scanner.run
      info = scanner.report.to_h.fetch(:info)
      expect(info[:dependencies]).to match_array(expected_packages)
    end
  end

  describe '#should_run?' do
    context 'no manifest or lock present' do
      it 'should return false' do
        repo = Salus::Repo.new('spec/fixtures/blank_repository')
        expect(repo.cargo_present?).to eq(false)
        expect(repo.cargo_lock_present?).to eq(false)
        scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'manifest is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/report_rust_crates/manifest_only')
        expect(repo.cargo_present?).to eq(true)
        expect(repo.cargo_lock_present?).to eq(false)
        scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end

    context 'lock is present' do
      it 'should return true' do
        repo = Salus::Repo.new('spec/fixtures/report_rust_crates/lock_only')
        expect(repo.cargo_lock_present?).to eq(true)
        scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
        expect(scanner.should_run?).to eq(true)
      end
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::ReportRustCrates.new(repository: repo, config: {})
        expect(scanner.version).to eq('')
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::ReportRustCrates.supported_languages
        expect(langs).to eq(['rust'])
      end
    end
  end
end
