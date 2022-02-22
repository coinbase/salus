module Salus
  class GemfileLock
    def initialize(path)
      @path = path
    end

    def add_line_number(cve)
      pattern = case cve[:type]
                when 'UnpatchedGem'
                  cve[:name] + ' (' + cve[:version] + ')'
                when 'InsecureSource'
                  cve[:source]
                end
      if !pattern.nil?
        line_in_gemfile_lock = IO.popen(["grep", "-n", pattern, @path]).read
        line_no = line_in_gemfile_lock.split(':')[0]
        cve[:line_number] = line_no.to_i if line_no.to_s.match(/^\d+$/)
      end
    end
  end
end
