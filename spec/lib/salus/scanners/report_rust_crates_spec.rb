require_relative '../../../spec_helper.rb'

describe Salus::Scanners::ReportRustCrates do
  describe '#run' do
    
    let (:expected_packages) do
      [{ type:"cargo_lock",
           name:"autocfg",
           reference:"registry+https://github.com/rust-lang/crates.io-index",
           version_tag:"0.1.7",
           dependency_file:"Cargo.lock" },
         { type:"cargo_lock",
           name:"bitflags",
           reference:"registry+https://github.com/rust-lang/crates.io-index",
           version_tag:"1.2.1",
           dependency_file:"Cargo.lock"},
         { type:"cargo_lock",
           name:"cloudabi",
           reference:"registry+https://github.com/rust-lang/crates.io-index",
           version_tag:"0.0.3",
           dependency_file:"Cargo.lock"},
         {type:"cargo_lock",
          name:"foo",
          reference:nil,
          version_tag:"0.1.0",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"fuchsia-cprng",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.1",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"libc",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.2.77",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.6.5",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_chacha",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.1",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_core",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.3.1",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_core",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.4.2",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_hc",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.0",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_isaac",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.1",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_jitter",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.4",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_os",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.3",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_pcg",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.2",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rand_xorshift",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.1.1",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"rdrand",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.4.0",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"winapi",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.3.9",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"winapi-i686-pc-windows-gnu",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.4.0",
          dependency_file:"Cargo.lock"},
        {type:"cargo_lock",
          name:"winapi-x86_64-pc-windows-gnu",
          reference:"registry+https://github.com/rust-lang/crates.io-index",
          version_tag:"0.4.0",
          dependency_file:"Cargo.lock"}
        ]
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
      scanner.run

      info = scanner.report.to_h.fetch(:info)

      # Our manifest only has one top level dependency.  When we analyze we will
      # walk the graph and we'll get back 10 or so dependencies
      dependency = info[:dependencies].first
      
      # Check that we have the expected fields
      expect(dependency.keys).to match_array([:name, :type, :reference, :version_tag, :dependency_file])
      # And check that our single dependency should have fanned out into multiple
      expect(info[:dependencies].size).to be > 1
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
end
