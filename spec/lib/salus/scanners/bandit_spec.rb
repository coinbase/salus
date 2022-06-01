require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Bandit do
  let(:py_dir) { 'spec/fixtures/python' }

  describe '#should_run?' do
    let(:scanner) { Salus::Scanners::Bandit.new(repository: repo, config: {}) }

    context 'no requirements.txt nor setup.cfg' do
      let(:repo) { Salus::Repo.new("#{py_dir}/non_python_project") }

      it 'should return false' do
        expect(repo.requirements_txt_present?).to eq(false)
        expect(repo.setup_cfg_present?).to eq(false)
        expect(scanner.should_run?).to eq(false)
        expect(repo.py_files_present?).to eq(false)
      end
    end

    context 'requirements.txt present but no setup.cfg' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_no_setup_cfg") }

      it 'should return true' do
        expect(repo.requirements_txt_present?).to eq(true)
        expect(repo.setup_cfg_present?).to eq(false)
        py_file = 'spec/fixtures/python/python_project_no_setup_cfg/main.py'
        expect(repo.py_files_present?).to eq([py_file])
        expect(scanner.should_run?).to eq(true)
      end
    end

    context 'setup.cfg present but no requirements.txt' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_no_req_txt") }

      it 'should return true' do
        expect(repo.requirements_txt_present?).to eq(false)
        expect(repo.setup_cfg_present?).to eq(true)
        py_file = 'spec/fixtures/python/python_project_no_req_txt/main.py'
        expect(repo.py_files_present?).to eq([py_file])
        expect(scanner.should_run?).to eq(true)
      end
    end

    context 'py files present but not requirements.txt/setup.cfg' do
      let(:repo) { Salus::Repo.new("#{py_dir}/py_files_only") }

      it 'should return true' do
        expect(repo.requirements_txt_present?).to eq(false)
        expect(repo.setup_cfg_present?).to eq(false)
        py_file1 = 'spec/fixtures/python/py_files_only/subdir/p1.py'
        py_file2 = 'spec/fixtures/python/py_files_only/subdir/p2.py'
        py_files = repo.py_files_present?
        expect(py_files.size).to eq(2)
        expect(py_files).to include(py_file1)
        expect(py_files).to include(py_file2)
        expect(scanner.should_run?).to eq(false)
      end
    end
  end

  describe '#run' do
    before { scanner.run }
    let(:scanner) { Salus::Scanners::Bandit.new(repository: repo, config: {}) }

    context 'non-bandit project' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_empty_code") }

      it 'should record 0 line of code scanned if no code' do
        expect(scanner.should_run?).to eq(true)
        expect(scanner.report.passed?).to eq(false)
        errs = scanner.report.to_h.fetch(:errors)
        expect(errs.size).to eq(1)
        expect(errs[0][:message]).to eq('0 lines of code were scanned')
      end
    end

    context 'python project with insecure code' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_with_insecure_code_practices") }

      it 'should record failure and record the STDOUT from bandit' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        msg = 'Consider possible security implications associated with cPickle module.'
        expect(logs).to include(msg)
      end
    end

    context 'python project with insecure code in a nested folder' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_with_insecure_code_practices_r") }

      it 'should record failure and record the STDOUT from bandit' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        logs = scanner.report.to_h.fetch(:logs)
        expect(info[:stdout]).not_to be_nil
        expect(info[:stdout]).not_to be_empty
        msg = 'Consider possible security implications associated with cPickle module.'
        expect(logs).to include(msg)
      end
    end

    context 'python project with no known vulnerabilities' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_no_vulns") }

      it 'should report a passing scan' do
        expect(scanner.report.passed?).to eq(true)
      end
    end

    context 'python project with unknown skip' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_with_bandit_errors") }

      it 'should report a failing scan' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:stderr]).to include("ERROR\tUnknown test found in profile: B9999999")
      end
    end
  end

  describe '#config_options' do
    context 'when using aggregate' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns2") }

      it 'and aggregate by filename' do
        config_file = "#{py_dir}/salus_configs/aggregate_file.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        result_filenames = logs['results'].map { |r| r['filename'] }

        sorted_files = %w[./main.py ./main2.py ./main2.py ./main2.py
                          ./main2.py ./main2.py ./main2.py]
        expect(result_filenames).to eq(sorted_files)
      end

      it 'and aggregate by vuln' do
        # aggregate by vuln
        config_file = "#{py_dir}/salus_configs/aggregate_vuln.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        result_vulns = logs['results'].map { |r| r['test_id'] }

        expect(result_vulns).to eq(%w[B403 B403 B301 B301 B301 B105 B105])
      end
    end

    context "when using configfile" do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns") }

      it 'if no configfile baseline - results include test_id B301' do
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        results_b301 = logs['results'].select { |r| r['test_id'] == 'B301' }

        expect(results_b301).not_to be_empty
      end

      it 'and configfile says skip test_id B301' do
        # spec/fixtures/python/python_project_vulns
        config_file = "#{py_dir}/salus_configs/config_file.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        results_b301 = logs['results'].select { |r| r['test_id'] == 'B301' }

        expect(results_b301).to be_empty
      end
    end

    context 'when listing exceptions' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns") }

      before(:each) do
        allow(Date).to receive(:today).and_return Date.new(2021, 12, 31)
      end

      it 'should allow exception entries' do
        config_file = "#{py_dir}/salus_configs/exceptions.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end

      it 'should support expirations' do
        config_file = "#{py_dir}/salus_configs/expired-exceptions.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        ids = logs['results'].map { |r| r["test_id"] }.uniq.sort
        expect(ids).to eq(%w[B301 B403])
      end
    end

    context 'when using profile' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns2") }

      it 'if no profile baseline - results test names include multiple items' do
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_names = logs['results'].map { |r| r['test_name'] }.uniq

        expect(test_names).to eq(%w[hardcoded_password_string blacklist])
      end

      it 'and profile says include only one test name' do
        # profile_op.yaml points to yaml file that specifies BadPassword profile
        # BadPassword includes only hardcoded_password_string
        config_file = "#{py_dir}/salus_configs/profile_op.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_names = logs['results'].map { |r| r['test_name'] }.uniq

        expect(test_names).to eq(%w[hardcoded_password_string])
      end
    end

    context 'when using tests' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns2") }

      it 'and tests only B301' do
        # yaml says tests B301
        config_file = "#{py_dir}/salus_configs/test1.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_ids = logs['results'].map { |r| r['test_id'] }.uniq

        expect(test_ids).to eq(%w[B301])
      end

      it 'and test B105 and B301' do
        config_file = "#{py_dir}/salus_configs/test2.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_ids = logs['results'].map { |r| r['test_id'] }.uniq
        expect(test_ids).to eq(%w[B105 B301])
      end

      it 'and test B105, B301, B403' do
        config_file = "#{py_dir}/salus_configs/test3.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_ids = logs['results'].map { |r| r['test_id'] }.uniq
        expect(test_ids).to eq(%w[B105 B403 B301])
      end
    end

    context 'when using skip' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns") }

      it 'and skip B301' do
        config_file = "#{py_dir}/salus_configs/skip1.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        result_ids = logs['results'].map { |r| r['test_id'] }.uniq

        expect(result_ids).to eq(['B403'])
      end

      it 'and skip B301, B403' do
        config_file = "#{py_dir}/salus_configs/skip2.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end
    end

    context 'when using baseline file' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns2") }

      it 'if no baseline, then results include two files' do
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        filenames = logs['results'].map { |r| r['filename'] }.uniq

        expect(filenames).to eq(%w[./main.py ./main2.py])
      end

      it 'and using main.py as baseline' do
        config_file = "#{py_dir}/salus_configs/baseline.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        filenames = logs['results'].map { |r| r['filename'] }.uniq

        expect(filenames).to eq(%w[./main.py])
      end
    end

    context 'when using ini file' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns2") }

      it 'ini file option should work' do
        # ini_file.yaml points to file that specifies exclude main2.py
        config_file = "#{py_dir}/salus_configs/ini_file.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']

        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        expect(logs['results'].size).to eq(1)
        expect(logs['results'][0]['filename']).to eq('./main.py')
      end
    end

    context 'when using ignore nosec' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns3") }

      it 'if ignore nosec is false then report passes' do
        # repo has a nosec comment
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end

      it 'and ignore nosec' do
        # yaml specifies ignore-nosec
        config_file = "#{py_dir}/salus_configs/ignore_nosec.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)
      end
    end

    context 'when using exclude path' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns2") }

      it 'if not using exclude path baseline' do
        # repo contains main.py and main2.py
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run
        logs = JSON.parse(scanner.report.to_h[:logs])

        expect(scanner.report.passed?).to eq(false)

        files_scanned = logs['results'].map { |r| r['filename'] }.uniq
        expect(files_scanned).to eq(['./main.py', './main2.py'])
      end

      it 'and exclude main.py, then only main2.py will be scanned' do
        config_file = "#{py_dir}/salus_configs/exclude1.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        logs = JSON.parse(scanner.report.to_h[:logs])

        expect(scanner.report.passed?).to eq(false)

        files_scanned = logs['results'].map { |r| r['filename'] }.uniq
        expect(files_scanned).to eq(['./main2.py'])
      end

      it 'and exclude both main.py and main2.py' do
        # exclude both files, there will be 0 line of code
        config_file = "#{py_dir}/salus_configs/exclude2.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        errs = scanner.report.to_h.fetch(:errors)
        expect(errs.size).to eq(1)
        expect(errs[0][:message]).to eq('0 lines of code were scanned')
      end
    end

    context 'when using confidence' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns2") }

      it 'and confidence level is MEDIUM' do
        # confidence level = MEDIUM
        config_file = "#{py_dir}/salus_configs/confidence.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        confidence_lst = logs['results'].map { |r| r['issue_confidence'] }.uniq
        expect(confidence_lst).to eq(%w[MEDIUM HIGH])
      end

      it 'and confidence level is HIGH' do
        # confidence level = HIGH
        config_file = "#{py_dir}/salus_configs/confidence2.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        confidence_lst = logs['results'].map { |r| r['issue_confidence'] }.uniq
        expect(confidence_lst).to eq(['HIGH'])
      end
    end

    context 'using severity level' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns") }

      it 'and severity level is LOW' do
        config_file = "#{py_dir}/salus_configs/level.yaml" # severity = LOW
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        sevs = logs['results'].map { |r| r['issue_severity'] }
        expect(sevs).to eq(%w[LOW LOW MEDIUM MEDIUM MEDIUM])
      end

      it 'and severity level is MEDIUM' do
        config_file = "#{py_dir}/salus_configs/level2.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        sevs = logs['results'].map { |r| r['issue_severity'] }
        expect(sevs).to eq(%w[MEDIUM MEDIUM MEDIUM])
      end

      it 'and severity level is HIGH'	do
        config_file = "#{py_dir}/salus_configs/level3.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run

        expect(scanner.report.passed?).to eq(true)
      end
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new(py_dir)
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return python' do
        langs = Salus::Scanners::Bandit.supported_languages
        expect(langs).to eq(['python'])
      end
    end
  end
end
