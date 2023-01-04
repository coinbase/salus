require_relative "../../../spec_helper.rb"

describe Salus::Scanners::Semgrep do
  describe "#run" do
    context "no forbidden semgrep" do
      it "should report matches" do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "forbidden" => false
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:misses]).to be_empty
      end

      context "external config" do
        it "should not allow pattern defined in both salus config and external config" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config.yml",
                "forbidden" => false,
                "pattern" => "$X = 1"
              }
            ]
          }
          scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
          scanner.run

          expect(scanner.report.passed?).to eq(false)
          info = scanner.report.to_h.fetch(:info)
          msg = "cannot be specified in salus.yaml"
          expect(info[:stderr]).to include(msg)
        end

        it "should report matches" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config.yml",
                "forbidden" => false
              }
            ]
          }
          scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
          scanner.run

          expect(scanner.report.passed?).to eq(true)

          info = scanner.report.to_h.fetch(:info)

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: false,
            msg: "3 == 3 is always true\n\trule_id: semgrep-eqeq-test",
            hit: "trivial.py:3:if 3 == 3:"
          )

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: false,
            msg: "user.id == user.id is always true\n\trule_id: semgrep-eqeq-test",
            hit: "examples/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: false,
            msg: "user.id == user.id is always true\n\trule_id: semgrep-eqeq-test",
            hit: "vendor/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:misses]).to be_empty
        end

        it "should report not report findings that have been allowlisted" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config.yml",
                "forbidden" => false
              }
            ],
            "exceptions" => [
              {
                "advisory_id" => "semgrep-eqeq-test",
                "changed_by" => "me",
                "notes" => "..."
              }
            ]
          }
          scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
          scanner.run

          expect(scanner.report.passed?).to eq(true)

          info = scanner.report.to_h.fetch(:info)
          expect(info[:hits]).to be_empty
          expect(info[:misses]).to be_empty
        end

        it "should report forbidden matches" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config.yml",
                "forbidden" => true
              }
            ]
          }
          scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
          scanner.run

          expect(scanner.report.passed?).to eq(false)

          info = scanner.report.to_h.fetch(:info)

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: true,
            required: false,
            msg: "3 == 3 is always true\n\trule_id: semgrep-eqeq-test",
            hit: "trivial.py:3:if 3 == 3:"
          )

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: true,
            required: false,
            msg: "user.id == user.id is always true\n\trule_id: semgrep-eqeq-test",
            hit: "examples/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: true,
            required: false,
            msg: "user.id == user.id is always true\n\trule_id: semgrep-eqeq-test",
            hit: "vendor/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:misses]).to be_empty
        end

        it "should report required matches" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config.yml",
                "required" => true
              }
            ]
          }
          scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
          scanner.run

          expect(scanner.report.passed?).to eq(true)

          info = scanner.report.to_h.fetch(:info)

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: true,
            msg: "3 == 3 is always true\n\trule_id: semgrep-eqeq-test",
            hit: "trivial.py:3:if 3 == 3:"
          )

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: true,
            msg: "user.id == user.id is always true\n\trule_id: semgrep-eqeq-test",
            hit: "examples/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:hits]).to include(
            id: "semgrep-eqeq-test",
            severity: "WARNING",
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: true,
            msg: "user.id == user.id is always true\n\trule_id: semgrep-eqeq-test",
            hit: "vendor/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:misses]).to be_empty
        end

        it "should report required matches" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config-required.yml",
                "required" => true
              }
            ]
          }
          scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
          scanner.run

          expect(scanner.report.passed?).to eq(false)

          failure_messages = scanner.report.to_h.fetch(:logs)
          expect(failure_messages).to include(
            'Required patterns in config "semgrep-config-required.yml" was not found - '
          )

          info = scanner.report.to_h.fetch(:info)
          expect(info[:hits]).to be_empty
          expect(info[:misses].size).to eq(1)
          expect(info[:misses][0]).to eq(
            config: "semgrep-config-required.yml",
            pattern: nil,
            forbidden: false,
            required: true,
            msg: ""
          )
        end

        it "should report matches with pattern-not" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config-pattern-not.yml",
                "forbidden" => false
              }
            ]
          }
          scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
          scanner.run

          expect(scanner.report.passed?).to eq(true)

          info = scanner.report.to_h.fetch(:info)

          expect(info[:hits]).to include(
            id: "unverified-db-query",
            severity: "ERROR",
            config: "semgrep-config-pattern-not.yml",
            pattern: nil,
            forbidden: false,
            required: false,
            msg: "Found unverified db query\n\trule_id: unverified-db-query",
            hit: "pattern-not/test.py:2:db_query(\"SELECT * FROM ...\")"
          )

          expect(info[:misses]).to be_empty
        end
      end

      it "should report matches with a message" do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "forbidden" => false
            }
          ]
        }

        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:misses]).to be_empty
      end
    end

    context "some semgrep hits are forbidden" do
      it "should report matches" do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "forbidden" => true
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:misses]).to be_empty
      end
    end

    context "some semgrep hits are required" do
      it "should pass the scan if a required patterns are found" do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "required" => true
            }
          ]
        }

        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: true,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: true,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: true,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:misses]).to be_empty
      end

      it "should failed the scan if a required pattern is not found" do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$X == 42",
              "language" => "python",
              "message" => "Should be 42",
              "required" => true
            }
          ]
        }

        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        failure_messages = scanner.report.to_h.fetch(:logs)
        expect(failure_messages).to include(
          'Required pattern "$X == 42" was not found - Should be 42'
        )

        info = scanner.report.to_h.fetch(:info)
        expect(info[:hits]).to be_empty
        expect(info[:misses].size).to eq(1)
        expect(info[:misses][0]).to eq(
          config: nil,
          pattern: "$X == 42",
          forbidden: false,
          required: true,
          msg: "Should be 42"
        )
      end
    end

    context 'global exclusions are given' do
      it 'should not search through excluded material' do
        repo = Salus::Repo.new('spec/fixtures/semgrep')
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "forbidden" => true
            }
          ],
          'exclude' => %w[examples]
        }

        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).not_to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )
      end
    end

    context 'global exclusions are given' do
      it 'should not search through excluded material' do
        repo = Salus::Repo.new('spec/fixtures/semgrep')
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "forbidden" => true
            }
          ],
          'exclude' => %w[examples vendor]
        }

        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).not_to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).not_to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )
      end
    end

    context 'local exclusions are given' do
      it 'should not search through excluded material' do
        repo = Salus::Repo.new('spec/fixtures/semgrep')
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "forbidden" => true,
              'exclude' => %w[examples]
            }
          ]
        }

        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).not_to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )
      end
    end

    context 'local exclusions are given' do
      it 'should not search through excluded material' do
        repo = Salus::Repo.new('spec/fixtures/semgrep')
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "forbidden" => true,
              'exclude' => %w[examples vendor]
            }
          ]
        }

        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          severity: "ERROR",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).not_to include(
          id: "11d6bdec931137a1063338f1f80a631f5b1f2fc2",
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )
      end
    end

    context "rule misconfigured" do
      it "should output misconfig reason" do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "config" => "semgrep-misconfig.yml", # 1 rule missing id
              "forbidden" => true
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors.size).to eq(1)
        error = errors[0]
        expect(error[:message]).to eq("Call to semgrep failed")
        expect(error[:stderr]).to include("semgrep-misconfig.yml:2-7 Invalid rule schema "\
                                          "One of these properties is missing: 'id'")
        expect(error[:stderr]).to include("invalid configuration file found")
      end
    end

    context "invalid pattern or settings which causes error" do
      it "should record the STDERR of semgrep" do
        repo = Salus::Repo.new("spec/fixtures/semgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$",
              "language" => "python",
              "forbidden" => false
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors.size).to eq(1)
        expect(errors[0][:status]).to eq(2)
        expect(errors[0][:stderr].downcase).to include("error")
        expect(errors[0][:message]).to eq("Call to semgrep failed")

        info = scanner.report.to_h.fetch(:info)
        expect(info[:misses]).to be_empty
        expect(info[:hits]).to be_empty
      end
    end

    context "unparsable python code causes error" do
      it "should record the STDERR of semgrep" do
        repo = Salus::Repo.new("spec/fixtures/semgrep/invalid")
        config = {
          "matches" => [
            {
              "pattern" => "$X",
              "language" => "python",
              "forbidden" => false,
              "strict" => true
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors.size).to eq(1)
        expect(errors[0][:status]).to eq(3) # semgrep exit code documentation
        expect(errors[0][:stderr]).to match(
          /`print\(\"foo\"` was unexpected \(warn\)\n\t.+?unparsable_py\.py:3-3/
        )
        expect(errors[0][:message]).to eq("Call to semgrep failed")

        info = scanner.report.to_h.fetch(:info)
        expect(info[:misses]).to be_empty
        expect(info[:hits]).to be_empty
      end
    end

    context "unparsable code causes warning" do
      it "should record semgrep warning" do
        base = "spec/fixtures/semgrep/invalid"
        repo = Salus::Repo.new(base)
        config = {
          "matches" => [
            {
              "pattern" => "$X",
              "language" => "js"
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        file = File.expand_path(File.join(base, "unparsable_js.js"))

        warnings = scanner.report.to_h.fetch(:warn)
        expect(warnings[:semgrep_non_fatal]).to eq(
          [
            {
              level: "warn",
              message: "Syntax error at line /home/spec/fixtures/semgrep/invalid/"\
              "unparsable_js.js:3:\n `cosnt` was unexpected",
              spans:
              [
                {
                  end:
                    {
                      "col" => 6,
                      "line" => 3
                    },
                  file: file,
                  start:
                    {
                      "col" => 1,
                      "line" => 3
                    }
                }
              ],
              type: "Syntax error"
            }
          ]
        )
      end

      it "should not record syntax error if show_syntax_errors=false" do
        base = "spec/fixtures/semgrep/invalid"
        repo = Salus::Repo.new(base)
        config = {
          "show_syntax_errors" => false,
          "matches" => [
            {
              "pattern" => "$X",
              "language" => "js"
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        warnings = scanner.report.to_h.fetch(:warn)
        expect(warnings).to be_empty
      end
    end

    context "unparsable javascript code causes error with strict" do
      it "should record the STDERR of semgrep" do
        repo = Salus::Repo.new("spec/fixtures/semgrep/invalid")
        config = {
          "matches" => [
            {
              "pattern" => "$X",
              "language" => "js",
              "forbidden" => false
            }
          ],
          "strict" => true
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors.size).to eq(1)
        expect(errors[0][:status]).to eq(3) # semgrep exit code documentation
        expect(errors[0][:stderr]).to match(
          /\(warn\)\n\t.+?unparsable_js\.js:3-3/
        )
        expect(errors[0][:message]).to eq("Call to semgrep failed")

        info = scanner.report.to_h.fetch(:info)
        expect(info[:misses]).to be_empty
        expect(info[:hits]).to be_empty
      end
    end
  end

  describe "#should_run?" do
    it "should return true" do
      repo = Salus::Repo.new("spec/fixtures/blank_repository")
      scanner = Salus::Scanners::Semgrep.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end

  describe '#build_command_and_message' do
    let(:scanner) { Salus::Scanners::Semgrep.new(repository: Salus::Repo.new(''), config: {}) }

    it 'config for relative path' do
      match = { "config" => "myrules.yaml", "forbidden" => true, "required" => false,
                "strict" => false, "message" => "" }
      cmd = scanner.build_command_and_message(match, false, '/home/repo', nil)[0]
      expected_cmd = ["semgrep", "--json", "--disable-version-check",
                      "--config", "/home/repo/myrules.yaml", "/home/repo"]
      expect(cmd).to eq(expected_cmd)
    end

    it 'config for url' do
      match = { "config" => "https://localhost/rules", "forbidden" => true, "required" => false,
                "strict" => false, "message" => "" }
      cmd = scanner.build_command_and_message(match, false, '/home/repo', nil)[0]
      expected_cmd = ["semgrep", "--json", "--disable-version-check",
                      "--config", "https://localhost/rules", "/home/repo"]
      expect(cmd).to eq(expected_cmd)
    end

    it 'config for absolute path' do
      match = { "config" => "/home/semgrep_rules", "forbidden" => true, "required" => false,
                "strict" => false, "message" => "" }
      cmd = scanner.build_command_and_message(match, false, '/home/repo', nil)[0]
      expected_cmd = ["semgrep", "--json", "--disable-version-check",
                      "--config", "/home/semgrep_rules", "/home/repo"]
      expect(cmd).to eq(expected_cmd)
    end
  end

  describe '#version_valid?' do
    context 'scanner version is valid' do
      it 'should return true' do
        repo = Salus::Repo.new("spec/fixtures/blank_repository")
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: {})
        expect(scanner.version).to be_a_valid_version
      end
    end
  end

  describe '#supported_languages' do
    context 'should return supported languages' do
      it 'should return expected langs' do
        langs = Salus::Scanners::Semgrep.supported_languages
        expect(langs).to eq(['*'])
      end
    end
  end
end
