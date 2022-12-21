module Salus
  class RulesEvaluation
    RULE_TYPE_ID = "id".freeze
    RULE_TYPE_SEVERITY = "severity".freeze

    def self.evaluate_default(results)
      return true if results.empty?

      false
    end

    def self.evaluate_by_type(config, results)
      case config["rule"]["type"]
      when RULE_TYPE_ID
        evaluate_by_id(config["rule"], results)
      when RULE_TYPE_SEVERITY
        evaluate_by_severity
      else
        evaluate_default(results)
      end
    end

    def self.evaluate_by_id(config, results)
      matches = config["matches"]
      keys = matches.map{ |x| x["key"] }
      ids = results.map{ |x| x[:ID] }
      return true unless (keys & ids).length.positive?

      reutrn false
    end

    def self.evaluate_by_severity(config, results)
      matches = config["matches"]
      keys = matches.map{ |x| x["key"] }
      ids = results.map{ |x| x[:Severity] }
      return true unless (keys & ids).length.positive?

      reutrn false
    end

    def self.evaluate_rules(config, results)
      return evaluate_by_type(config, results) if config.key?('rule')

      evaluate_default(results)
    end
  end
end
