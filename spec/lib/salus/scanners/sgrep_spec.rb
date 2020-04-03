require_relative "../../../spec_helper.rb"

describe Salus::Scanners::Sgrep do
  describe "#run" do
    context "no forbidden sgrep" do
      it "should report matches" do
        repo = Salus::Repo.new("spec/fixtures/sgrep")
        config = { "matches" => [{ "pattern" => "$X == $X", "language" => "python", "forbidden" => false }] }
        scanner = Salus::Scanners::Sgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "trivial.py:3",
        )

        expect(info[:hits]).to include(
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "",
          hit: "trivial2.py:10",
        )
      end

      it "should report matches with a message" do
        repo = Salus::Repo.new("spec/fixtures/sgrep")
        config = {
          "matches" => [
            {
              "pattern" => "$X == $X",
              "language" => "python",
              "message" => "Useless equality test.",
              "forbidden" => false,
            },
          ],
        }

        scanner = Salus::Scanners::Sgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial.py:3",
        )

        expect(info[:hits]).to include(
          pattern: "$X == $X",
          forbidden: false,
          required: false,
          msg: "Useless equality test.",
          hit: "trivial2.py:10",
        )
      end
    end

    context "some sgrep hits are forbidden" do
      it "should report matches" do
        repo = Salus::Repo.new("spec/fixtures/sgrep")
        config = { "matches" => [{ "pattern" => "$X == $X", "language" => "python", "forbidden" => true }] }
        scanner = Salus::Scanners::Sgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "trivial.py:3",
        )

        expect(info[:hits]).to include(
          pattern: "$X == $X",
          forbidden: true,
          required: false,
          msg: "",
          hit: "trivial2.py:10",
        )
      end
    end

    context "some sgrep hits are required" do
      it "should pass the scan if a required patterns are found" do
        repo = Salus::Repo.new("spec/fixtures/sgrep")
        config = {
          "matches" => [
            { "pattern" => "$X == $X", "language" => "python", "required" => true, "message" => "Useless equality test." },
          ],
        }

        scanner = Salus::Scanners::Sgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(true)

        info = scanner.report.to_h.fetch(:info)

        expect(info[:hits]).to include(
          pattern: "$X == $X",
          forbidden: false,
          required: true,
          msg: "Useless equality test.",
          hit: "trivial.py:3",
        )
      end

      it "should failed the scan if a required pattern is not found" do
        repo = Salus::Repo.new("spec/fixtures/sgrep")
        config = {
          "matches" => [
            { "pattern" => "$X == 42", "language" => "python", "required" => true, "message" => "Should be 42" },
          ],
        }

        scanner = Salus::Scanners::Sgrep.new(repository: repo, config: config)
        scanner.run

        expect(scanner.report.passed?).to eq(false)

        failure_messages = scanner.report.to_h.fetch(:logs)
        expect(failure_messages).to include('Required pattern "$X == 42" was not found - Should be 42')
      end
    end

    context "invalid pattern or settings which causes error" do
      it "should record the STDERR of sgrep" do
        repo = Salus::Repo.new("spec/fixtures/sgrep")
        config = { "matches" => [{ "pattern" => "$", "language" => "python", "forbidden" => true }] }
        scanner = Salus::Scanners::Sgrep.new(repository: repo, config: config)
        scanner.run

        errors = scanner.report.to_h.fetch(:errors)
        expect(errors).to include(
          status: 2,
          stderr: "in manual, pattern in rule - can't be parsed for language python: $\n1 invalid patterns found inside rules; aborting\n",
          message: "Call to sgrep failed",
        )
      end
    end
  end

  describe "#should_run?" do
    it "should return true" do
      repo = Salus::Repo.new("spec/fixtures/blank_repository")
      scanner = Salus::Scanners::Sgrep.new(repository: repo, config: {})
      expect(scanner.should_run?).to eq(true)
    end
  end
end
