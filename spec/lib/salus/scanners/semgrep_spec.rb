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
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )
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
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: false,
            msg: "3 == 3 is always true",
            hit: "trivial.py:3:if 3 == 3:"
          )

          expect(info[:hits]).to include(
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: false,
            msg: "user.id == user.id is always true",
            hit: "examples/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:hits]).to include(
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: false,
            msg: "user.id == user.id is always true",
            hit: "vendor/trivial2.py:10:    if user.id == user.id:"
          )
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
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: true,
            required: false,
            msg: "3 == 3 is always true",
            hit: "trivial.py:3:if 3 == 3:"
          )

          expect(info[:hits]).to include(
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: true,
            required: false,
            msg: "user.id == user.id is always true",
            hit: "examples/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:hits]).to include(
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: true,
            required: false,
            msg: "user.id == user.id is always true",
            hit: "vendor/trivial2.py:10:    if user.id == user.id:"
          )
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
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: true,
            msg: "3 == 3 is always true",
            hit: "trivial.py:3:if 3 == 3:"
          )

          expect(info[:hits]).to include(
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: true,
            msg: "user.id == user.id is always true",
            hit: "examples/trivial2.py:10:    if user.id == user.id:"
          )

          expect(info[:hits]).to include(
            config: "semgrep-config.yml",
            pattern: nil,
            forbidden: false,
            required: true,
            msg: "user.id == user.id is always true",
            hit: "vendor/trivial2.py:10:    if user.id == user.id:"
          )
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
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )
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
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )
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
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: true,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: true,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: false,
          required: true,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )
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
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).not_to include(
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
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).not_to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).not_to include(
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
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).not_to include(
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
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3:if 3 == 3:"
        )

        expect(info[:hits]).not_to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "vendor/trivial2.py:10:    if user.id == user.id:"
        )

        expect(info[:hits]).not_to include(
          config: nil,
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "Useless equality test.",
          hit: "examples/trivial2.py:10:    if user.id == user.id:"
        )
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
        expect(errors).to include(
          status: 4, # semgrep exit code documentation
          stderr: "error: invalid pattern\n\nPattern could not be parsed as a Python " \
                  "semgrep pattern (error)\n\tCLI Input:1",
          message: "Call to semgrep failed"
        )
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
        expect(errors).to include(
          status: 3, # semgrep exit code documentation
          stderr: "warn: parse error\n\nCould not parse unparsable_py.py as python (warn)" \
                  "\n\tunparsable_py.py:3",
          message: "Call to semgrep failed"
        )
      end
    end

    context "unparsable code causes warning" do
      it "should record semgrep warning" do
        repo = Salus::Repo.new("spec/fixtures/semgrep/invalid")
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

        warnings = scanner.report.to_h.fetch(:warn)
        expect(warnings[:semgrep_non_fatal]).to eq(
          [
            {
              level: "warn",
              message: "Could not parse unparsable_js.js as js",
              spans:
              [
                {
                  end:
                    {
                      "col" => 18,
                      "line" => 3
                    },
                  file: "unparsable_js.js",
                  start:
                    {
                      "col" => 7,
                      "line" => 3
                    }
                }
              ],
              type: "SourceParseError"
            }
          ]
        )
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
        expect(errors).to include(
          status: 3, # semgrep exit code documentation
          stderr: "warn: parse error\n\nCould not parse unparsable_js.js as js (warn)" \
                  "\n\tunparsable_js.js:3",
          message: "Call to semgrep failed"
        )
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
end
