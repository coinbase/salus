module Salus
    class RulesEvaluation
      RULE_TYPES = {
        'id' => 'id',
        'severity' => 'severity',
      }.freeze
      
    end

    def evaluate(config, results)
      return true
    end
  end
  