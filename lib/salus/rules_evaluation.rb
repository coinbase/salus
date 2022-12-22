module Salus
  class RulesEvaluation
    RULE_TYPE_ID = "id".freeze
    RULE_TYPE_SEVERITY = "severity".freeze
    ID_FIELD_MAPPING = {
      "GoOSV" => :ID,
      "GradleOSV" => :ID,
      "PythonOSV" => :ID,
      "MavenOSV" => :ID,
      "BundleAudit" => :cve
    }.freeze

    SEVERITY_FIELD_MAPPING = {
      "GoOSV" => :Severity,
      "GradleOSV" => :Severity,
      "PythonOSV" => :Severity,
      "MavenOSV" => :Severity
    }.freeze

    def self.evaluate_default(results)
      return true if results.empty?

      false
    end

    def self.evaluate_by_type(config, results, scanner)
      case config["rule"]["type"]
      when RULE_TYPE_ID
        evaluate_by_id(config["rule"], results, scanner)
      when RULE_TYPE_SEVERITY
        evaluate_by_severit(config["rule"], results, scanner)
      else
        evaluate_default(results)
      end
    end

    def self.evaluate_by_id(config, results, scanner)
      matches = config["matches"]
      keys = matches.map { |x| x["key"] }
      ids = results.map { |x| x[ID_FIELD_MAPPING[scanner]] }

      return true unless (keys & ids).length.positive? && ids.length.positive?

      reutrn false
    end

    def self.evaluate_by_severity(config, results, _scanner)
      matches = config["matches"]
      keys = matches.map { |x| x["key"] }
      ids = results.map { |x| x[SEVERITY_FIELD_MAPPING[scanner]] }
      return true unless (keys & ids).length.positive? && ids.length.positive?

      reutrn false
    end

    def self.evaluate_rules(config, results, scanner)
      return evaluate_by_type(config, results, scanner) if config.key?('rule')

      evaluate_default(results)
    end
  end
end
