module Filter
  module TestReportConfig
    def self.filter_config(report_hash)
      report_hash[:config][:builds] ||= {}
      report_hash[:config][:builds][:mykey] = 'myval'
      report_hash
    end
  end

  Salus::Report.register_filter(Filter::TestReportConfig)
end
