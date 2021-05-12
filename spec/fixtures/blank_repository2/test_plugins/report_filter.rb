module Filter
  module TestReportFilter
    def self.filter_report_hash(report_hash)
      report_hash[:config][:builds] ||= {}
      report_hash[:config][:builds][:mykey] = 'myval'
      report_hash
    end
  end

  Salus::Report.register_filter(Filter::TestReportFilter)
end
