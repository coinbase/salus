module Cyclonedx
  class ReportRubyGems < Base
    DEFAULT_COMPONENT_TYPE = "library".freeze

    def initialize(scan_report)
      super(scan_report)
    end

    def parse_dependency(dependency)
      {
        "bom-ref": "",
        "type": DEFAULT_COMPONENT_TYPE,
        "group": "", # TODO: add group or domain name of the publisher
        "name": dependency[:name],
        "version": dependency[:version],
        "purl": "pkg:#{dependency[:type]}/#{dependency[:name]}@#{dependency[:version]}",
        "properties": [
          {
            "key": "source",
            "value": dependency[:source]
          },
          {
            "key": "dependency_file",
            "value": dependency[:dependency_file]
          }
        ]
      }
    end
  end
end
