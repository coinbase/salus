module Salus
    class RulesEvaluation
      RULE_TYPES = {
        'id' => 'id',
        'severity' => 'severity',
      }.freeze
      
    end

    def evaluate(config, results)
      if results.empty?
        return true
      end
      return false
    end
  end
  