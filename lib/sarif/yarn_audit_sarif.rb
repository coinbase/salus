module Sarif
  class YarnAuditSarif < BaseSarif
    YARN_URI = 'https://classic.yarnpkg.com/en/docs/cli/audit/'.freeze

    def initialize(scan_report)
      super(scan_report)
      @uri = YARN_URI
      begin
        @logs = scan_report.to_h.fetch(:logs).dump.split("\\n\\n")
      rescue KeyError
        @logs = []
      end
    end

    def parse_issue(issue)
      issue = issue.split('\\n')
      index = 0
      h = {}
      issue.each do |item|
        seperator = item.index(':')
        next if !seperator

        key = item[0, seperator].delete("\"")
        h[key] = item[seperator + 1, item.size - 1].strip
        index += 1
      end
      return nil if h.empty?

      {
        id: format('YARN%<number>.4d', number: h['ID'].to_i),
        name: h['Title'],
        level: h['Severity'].upcase,
        details: "Package: #{h['Package']}\nUpgrade to: #{h['Patched in']}\nDependency of:"\
        "#{h['Dependency of']}",
        uri: "Yarn.lock",
        help_url: h['More info']
      }
    end

    def build_invocations
      if @logs.empty? && !@scan_report.passed?
        error = @scan_report.to_h.fetch(:info)[:stderr]
        {
          "executionSuccessful": false,
          "toolExecutionNotifications": [{
            "descriptor": {
              "id": ""
            },
            "level": "error",
            "message": {
              "text": "#{@scan_report.to_h.fetch(:errors).first[:message] || ''}, #{error}"
            }
          }]
        }
      else
        { "executionSuccessful": @scan_report.passed? }
      end
    end
  end
end
