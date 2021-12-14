module Salus
    class DiceCoefficient
        def self.dice(a, b)
            a_bigrams = a.each_char.each_cons(2).to_a
            b_bigrams = b.each_char.each_cons(2).to_a
          
            overlap = (a_bigrams & b_bigrams).size
          
            total = a_bigrams.size + b_bigrams.size
            dice  = overlap * 2.0 / total
            
            dice
        end 
    end 
end 