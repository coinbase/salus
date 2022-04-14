require 'json'

module Salus
  class SwiftDependencyParser
    attr_reader :swift_dependencies
    def initialize(path)
      package_resolved_text = File.read(path)
      raise StandardError, 'Unable to read Package.resolved file' unless path.present?

      begin
        resolved_object = JSON.parse(package_resolved_text)
      rescue StandardError
        raise 'Unable to parse Package.resolved JSON'
      end

      @pinned_dependencies = if resolved_object.dig('object', 'pins')
                               resolved_object['object']['pins']
                             else
                               raise 'Package.resolved does not have "object" or "pins" property'
                             end
      @swift_dependencies = []
    end

    def parse
      @pinned_dependencies.each do |pinned_dep|
        if pinned_dep.dig('package') && pinned_dep.dig('state', 'version')
          @swift_dependencies.append({
                                       "package" => pinned_dep['package'],
              "version" => pinned_dep['state']['version'],
              "source" => pinned_dep['repositoryURL']

                                     })
        end
      end
    end
  end
end
