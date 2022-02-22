module Salus
  class DiceCoefficient
    # source: https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Dice%27s_coefficient
    # Dice co-efficient can be used for measuring the similarity of two strings
    # bigram: A bigram or digram is a sequence of two adjacent elements
    #         from a string of tokens, which are typically letters,
    #         syllables, or words.
    #         For example, bigram of a string ('hello') can be written as the following requence
    #         [["h", "e"], ["e", "l"], ["l", "l"], ["l", "o"]]
    #
    # dice coefficient = bigram overlap * 2 / (bigrams in a + bigrams in b)
    def self.dice(string_a, string_b)
      a_bigrams = string_a.each_char.each_cons(2).to_a
      b_bigrams = string_b.each_char.each_cons(2).to_a

      overlap = (a_bigrams & b_bigrams).size

      total = a_bigrams.size + b_bigrams.size

      overlap * 2.0 / total
    end
  end
end
