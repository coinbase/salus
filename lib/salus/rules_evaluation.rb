module Salus
  class RulesEvaluation
    RULE_TYPE_ID = "id".freeze
    RULE_TYPE_SEVERITY = "severity".freeze

    def evaluate_default(results)
      return true if results.empty?

      false
    end

    def evaluate_by_type(config, _results)
      case config.fetch("rule", "key")
      when RULE_TYPE_ID
        evaluate_by_id
      when RULE_TYPE_SEVERITY
        true
      else
        false
      end
    end

    def evaluate_by_id
      true
    end

    def evaluate(config, results)
      return evaluate_by_type(config, results) if config.key?('rule')

      evaluate_default(results)
    end
  end
end
