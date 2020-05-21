require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Bandit do
  let(:py_dir) { 'spec/fixtures/python' }

  describe '#should_run?' do
    context 'no requirements.txt nor setup.cfg' do
      it 'should return false' do
        repo = Salus::Repo.new("#{py_dir}/non_python_project")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})

        expect(repo.requirements_txt_present?).to eq(false)
        expect(repo.setup_cfg_present?).to eq(false)
        expect(scanner.should_run?).to eq(false)
      end
    end

    context 'requirements.txt present but no setup.cfg' do
      it 'should return true' do
        repo = Salus::Repo.new("#{py_dir}/python_project_no_setup_cfg")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})

        expect(repo.requirements_txt_present?).to eq(true)
        expect(repo.setup_cfg_present?).to eq(false)
        expect(scanner.should_run?).to eq(true)
      end
    end

    context 'setup.cfg present but no requirements.txt' do
      it 'should return true' do
        repo = Salus::Repo.new("#{py_dir}/python_project_no_req_txt")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})

        expect(repo.requirements_txt_present?).to eq(false)
        expect(repo.setup_cfg_present?).to eq(true)
        expect(scanner.should_run?).to eq(true)
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

    context 'different config options' do
      let(:repo) { Salus::Repo.new("#{py_dir}/python_project_vulns") }

      it 'aggregate option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns2")

        # aggregate by file
        config_file = "#{py_dir}/salus_configs/aggregate_file.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        results = logs['results']

        # results ordered by filename
        expect(results.size).to eq(7)
        expect(results[0]['filename']).to eq('./main.py')
        results[1..-1].each { |r| expect(r['filename']).to eq('./main2.py') }

        # aggregate by vuln
        config_file = "#{py_dir}/salus_configs/aggregate_vuln.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        results = logs['results']

        # results ordered by vulns (test ids)
        expect(results.size).to eq(7)
        expect(results[0]['test_id']).to eq('B403')
        expect(results[1]['test_id']).to eq('B403')
        expect(results[2]['test_id']).to eq('B301')
        expect(results[3]['test_id']).to eq('B301')
        expect(results[4]['test_id']).to eq('B301')
        expect(results[5]['test_id']).to eq('B105')
        expect(results[6]['test_id']).to eq('B105')
      end

      it 'config file option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        results_b301 = logs['results'].select { |r| r['test_id'] == 'B301' }
        expect(results_b301).not_to be_empty

        # config_file.yaml points to file that says skip test_id B301
        config_file = "#{py_dir}/salus_configs/config_file.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        results_b301 = logs['results'].select { |r| r['test_id'] == 'B301' }
        expect(results_b301).to be_empty
      end

      it 'profile option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns2")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_names = logs['results'].map { |r| r['test_name'] }.uniq
        expect(test_names).to eq(%w[hardcoded_password_string blacklist])

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

      it 'tests option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns2")

        # tests B301
        config_file = "#{py_dir}/salus_configs/test1.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_ids = logs['results'].map { |r| r['test_id'] }.uniq
        expect(test_ids).to eq(%w[B301])

        # tests B301, B105
        config_file = "#{py_dir}/salus_configs/test2.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_ids = logs['results'].map { |r| r['test_id'] }.uniq
        expect(test_ids).to eq(%w[B105 B301])

        # tests B105, B301, B403
        config_file = "#{py_dir}/salus_configs/test3.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        test_ids = logs['results'].map { |r| r['test_id'] }.uniq
        expect(test_ids).to eq(%w[B105 B403 B301])
      end

      it 'skips option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns")

        # skips B301
        config_file = "#{py_dir}/salus_configs/skip1.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        expect(logs['results'].size).to eq(2)
        logs['results'].each { |r| expect(r['test_id']).not_to eq('B301') }

        # skips B301, B403
        config_file = "#{py_dir}/salus_configs/skip2.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end

      it 'baseline file option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns2")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        filenames = logs['results'].map { |r| r['filename'] }.uniq
        expect(filenames).to eq(%w[./main.py ./main2.py])

        # use main.py as baseline
        config_file = "#{py_dir}/salus_configs/baseline.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        filenames = logs['results'].map { |r| r['filename'] }.uniq
        expect(filenames).to eq(%w[./main.py])
      end

      it 'ini file option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns2")

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

      it 'nosec option should work' do
        # repo has a nosec comment
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns3")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run
        expect(scanner.report.passed?).to eq(true)

        # yaml specifies ignore-nosec
        config_file = "#{py_dir}/salus_configs/ignore_nosec.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        results = logs['results']

        expect(results.size).to eq(1)
        expect(results[0]['test_id']).to eq('B105')
      end

      it 'exclude path option should work' do
        # repo contains main.py and main2.py
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns2")
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: {})
        scanner.run
        logs = JSON.parse(scanner.report.to_h[:logs])

        expect(scanner.report.passed?).to eq(false)
        files_scanned = logs['results'].map { |r| r['filename'] }.uniq
        expect(files_scanned).to eq(['./main.py', './main2.py'])

        # exclude main.py, only main2.py will be scanned
        config_file = "#{py_dir}/salus_configs/exclude1.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        logs = JSON.parse(scanner.report.to_h[:logs])

        expect(scanner.report.passed?).to eq(false)
        files_scanned = logs['results'].map { |r| r['filename'] }.uniq
        expect(files_scanned).to eq(['./main2.py'])

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

      it 'confidence option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns2")

        # confidence level = MEDIUM
        config_file = "#{py_dir}/salus_configs/confidence.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        total_info = logs['metrics']['_totals']

        expect(total_info['CONFIDENCE.HIGH']).to eq(5)
        expect(total_info['CONFIDENCE.LOW']).to eq(0)
        expect(total_info['CONFIDENCE.MEDIUM']).to eq(2)

        confidence_lst = logs['results'].map { |r| r['issue_confidence'] }.uniq
        expect(confidence_lst).to eq(%w[MEDIUM HIGH])

        configs['confidence'] = 'HIGH'
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        total_info = logs['metrics']['_totals']

        expect(scanner.report.passed?).to eq(false)
        expect(total_info['CONFIDENCE.HIGH']).to eq(5)
        expect(total_info['CONFIDENCE.LOW']).to eq(0)
        expect(total_info['CONFIDENCE.MEDIUM']).to eq(2)

        confidence_lst = logs['results'].map { |r| r['issue_confidence'] }.uniq
        expect(confidence_lst).to eq(['HIGH'])
      end

      it 'severity option should work' do
        repo = Salus::Repo.new("#{py_dir}/python_project_vulns")

        # severity = LOW
        config_file = "#{py_dir}/salus_configs/level.yaml"
        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(false)

        logs = JSON.parse(scanner.report.to_h[:logs])
        sev = logs['metrics']['_totals']

        expect(sev['SEVERITY.HIGH']).to eq(0)
        expect(sev['SEVERITY.LOW']).to eq(2)
        expect(sev['SEVERITY.MEDIUM']).to eq(3)

        low_sev = logs['results'].select { |r| r['issue_severity'] == 'LOW' }
        expect(low_sev.size).to eq(2)
        med_sev = logs['results'].select { |r| r['issue_severity'] == 'MEDIUM' }
        expect(med_sev.size).to eq(3)
        high_sev = logs['results'].select { |r| r['issue_severity'] == 'HIGH' }
        expect(high_sev.size).to eq(0)

        configs['level'] = 'MEDIUM'
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        logs = JSON.parse(scanner.report.to_h[:logs])
        sev = logs['metrics']['_totals']

        expect(scanner.report.passed?).to eq(false)
        expect(sev['SEVERITY.HIGH']).to eq(0)
        expect(sev['SEVERITY.LOW']).to eq(2)
        expect(sev['SEVERITY.MEDIUM']).to eq(3)

        low_sev = logs['results'].select { |r| r['issue_severity'] == 'LOW' }
        expect(low_sev.size).to eq(0)
        med_sev = logs['results'].select { |r| r['issue_severity'] == 'MEDIUM' }
        expect(med_sev.size).to eq(3)
        high_sev = logs['results'].select { |r| r['issue_severity'] == 'HIGH' }
        expect(high_sev.size).to eq(0)

        configs = Salus::Config.new([File.read(config_file)]).scanner_configs['Bandit']
        configs['level'] = 'HIGH'
        scanner = Salus::Scanners::Bandit.new(repository: repo, config: configs)
        scanner.run
        expect(scanner.report.passed?).to eq(true)
      end
    end
  end
end
