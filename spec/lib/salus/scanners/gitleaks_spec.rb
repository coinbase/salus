require_relative '../../../spec_helper.rb'

describe Salus::Scanners::Gitleaks do
  describe '#run' do
    let(:scanner) { Salus::Scanners::Gitleaks.new(repository: repo, config: config) }

    before do
      live_git = File.join(repo.path_to_repo, '.git')
      inactive_git = File.join(repo.path_to_repo, 'dotGit')
      FileUtils.mv(inactive_git, live_git) if Dir.exist?(inactive_git)

      scanner.run
    end

    after do
      live_git = File.join(repo.path_to_repo, '.git')
      inactive_git = File.join(repo.path_to_repo, 'dotGit')
      FileUtils.mv(live_git, inactive_git) if Dir.exist?(live_git)
    end

    context 'empty directory' do
      let(:repo) { Salus::Repo.new('spec/fixtures/blank_repository') }
      let(:config) { { "no-git" => "true" } }

      it 'should report a passing scan' do
        expect(scanner.should_run?).to eq(true)
        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)
        expect(
          scanner.report.to_h.fetch(:errors)
        ).to be_empty
        expect(
          info[:stderr]
        ).to include('No leaks found')
      end
    end

    context 'repo with secrets' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gitleaks/repo_with_secrets') }
      let(:config) { {} }

      it 'should record failure and record the STDERR from gitleaks' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:stderr]).to include('leaks found')
        expect(info[:hits]).to eq([{
                                    msg: "AWS Access Key secret detected",
                                    file: "aws_config",
                                    line: 1,
                                    hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                  }])
      end

      context 'when using a config' do
        let(:config) { { "config-path" => "gitleaks.conf" } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "top secret secret detected",
                                      file: "test",
                                      line: 1,
                                      hit: "secret"
                                    }])
        end
      end

      context 'when using a repo-specific config' do
        let(:config) { { "repo-config-path" => "gitleaks.conf" } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "top secret secret detected",
                                      file: "test",
                                      line: 1,
                                      hit: "secret"
                                    }])
        end
      end

      context 'when looking at a specific commit' do
        let(:config) { { "commit" => "c2b69722557de56a826cc80c251fa5869c7b25fb" } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when looking at list of commits' do
        let(:config) { { "commits" => ["c2b69722557de56a826cc80c251fa5869c7b25fb"] } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when looking at list of commits (file)' do
        let(:config) { { "commits-file" => "commits" } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when looking at a range of commits' do
        let(:config) do
          {
            "commit-from" => ["c2b69722557de56a826cc80c251fa5869c7b25fb"],
            "commit-to" => ["c2b69722557de56a826cc80c251fa5869c7b25fb"]
          }
        end

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when looking at a time range of commits' do
        let(:config) do
          {
            "commit-since" => "2021-01-25T00:00:00-0000",
            "commit-until" => "2021-01-26T00:00:00-0000"
          }
        end

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when looking at files at a specific commit' do
        let(:config) { { "files-at-commit" => "c2b69722557de56a826cc80c251fa5869c7b25fb" } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when looking a number of commits' do
        let(:config) { { "depth" => 3 } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when looking a specific branch' do
        let(:config) { { "branch" => "master" } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                    }])
        end
      end

      context 'when redacting output' do
        let(:config) { { "redact" => "true" } }

        it 'should record failure and record the STDERR from gitleaks' do
          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:stderr]).to include('leaks found')
          expect(info[:hits]).to eq([{
                                      msg: "AWS Access Key secret detected",
                                      file: "aws_config",
                                      line: 1,
                                      hit: "aws_access_key_id='REDACTED'"
                                    }])
        end
      end
    end

    context 'repo with unstaged secrets' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gitleaks/repo_with_unstaged_secrets') }

      let(:config) { { "unstaged" => "true" } }

      it 'should record failure and record the STDERR from gitleaks' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:stderr]).to include('leaks found')
        expect(info[:hits]).to eq([{
                                    msg: "AWS Access Key secret detected",
                                    file: "aws_config",
                                    line: 1,
                                    hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                  }])
      end
    end

    context 'directory with secrets' do
      let(:repo) { Salus::Repo.new('spec/fixtures/gitleaks/dir_with_secrets') }
      let(:config) { { "no-git" => "true" } }

      it 'should record failure and record the STDERR from gitleaks' do
        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)
        expect(info[:stderr]).to include('leaks found')
        expect(info[:hits]).to eq([{
                                    msg: "AWS Access Key secret detected",
                                    file: "aws_config",
                                    line: 1,
                                    hit: "aws_access_key_id='AKIAIO5FODNN7EXAMPLE'"
                                  }])
      end
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("dir")
        scanner = Salus::Scanners::Gitleaks.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end
end
