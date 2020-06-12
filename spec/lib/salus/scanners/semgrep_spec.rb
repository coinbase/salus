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
              "forbidden" => false,
              "exclude_directory" => ['invalid']
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
        it "should report matches" do
          repo = Salus::Repo.new("spec/fixtures/semgrep")
          config = {
            "matches" => [
              {
                "config" => "semgrep-config.yml",
                "forbidden" => false,
                "exclude_directory" => ['invalid']
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
                "forbidden" => true,
                "exclude_directory" => ['invalid']
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
                "required" => true,
                "exclude_directory" => ['invalid']
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
                "required" => true,
                "exclude_directory" => ['invalid']
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
              "forbidden" => false,
              "exclude_directory" => ['invalid']
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
              "forbidden" => true,
              "exclude_directory" => ['invalid']
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
              "required" => true,
              "exclude_directory" => ['invalid']
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
              "required" => true,
              "exclude_directory" => ['invalid']
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
          'exclude_directory' => %w[examples invalid]
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
          'exclude_directory' => %w[examples vendor invalid]
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
              'exclude_directory' => %w[examples invalid]
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
              'exclude_directory' => %w[examples vendor invalid]
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
          stderr: "invalid pattern \"$\": "\
                  "Parse_info.Lexical_error(\"unrecognized symbol: $\", _)",
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
              "forbidden" => false
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors).to include(
          status: 3, # semgrep exit code documentation
          stderr: "semgrep: /home/spec/fixtures/semgrep/"\
          "invalid/unparsable_py.py: ParseError",
          message: "Call to semgrep failed"
        )
      end
    end

    context "unparsable javascript code causes error" do
      it "should record the STDERR of semgrep" do
        repo = Salus::Repo.new("spec/fixtures/semgrep/invalid")
        config = {
          "matches" => [
            {
              "pattern" => "$X",
              "language" => "js",
              "forbidden" => false
            }
          ]
        }
        scanner = Salus::Scanners::Semgrep.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors).to include(
          status: 3, # semgrep exit code documentation
          stderr: "parse error ",
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
