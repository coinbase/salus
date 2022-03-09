require 'json'
require 'nokogiri'

module Salus
  class MavenDependencyParser
    attr_reader :pom_xml_dependencies
    def initialize(path)
      msg = "pom.xml not found!"
      raise StandardError, msg unless File.exist?(path)

      @pom_xml_content = Nokogiri::XML(File.read(path))
      @pom_xml_dependencies = []
    end

    def parse
      if @pom_xml_content.errors.size.positive?
        err_msg = 'Errors:
        '
        @pom_xml_content.errors.each { |err| err_msg += "#{err}\n" }
        raise StandardError, err_msg
      end
      parse_dependencies
    end

    private

    def parse_dependencies
      properties = parse_properties
      @pom_xml_content.css('dependency')&.each do |dependency|
        group_id = dependency.at('groupId')
        artifact_id = dependency.at('artifactId')
        version = dependency.at('version')
        version = properties.dig(version.children.to_s) || version.children.to_s unless version.nil?

        @pom_xml_dependencies.append({
                                       "group_id" => group_id.nil? ? nil : group_id.children.to_s,
                        "artifact_id" => artifact_id.nil? ? nil : artifact_id.children.to_s,
                        "version" => version
                                     })
      end
    end

    def parse_properties
      # Parse contents within each <properties> tag and map it to dependency version
      # ${logback.version} => 1.2.10
      # <dependency>
      #    <groupId>ch.qos.logback</groupId>
      #    <artifactId>logback-classic</artifactId>
      #    <version>${logback.version}</version>
      # </dependency>
      # <properties>
      #   <logback.version>1.2.10</logback.version>
      # </properties>
      properties = {}
      nodes = @pom_xml_content.css('properties')
      nodes.each do |node|
        childrens = node.children
        childrens.each do |children|
          properties["${#{children.name}}"] = children.text
        end
      end
      properties
    end
  end
end
