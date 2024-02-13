module Gradle
  def gradle_dependencies(path)
    msg = "gradle.lockfile not found!"
    raise StandardError, msg unless File.exist?(path)

    dependency_metadata_regex = /(?<group_id>.+):(?<artifact_id>.+):(?<version>.+)=/
    lockfile_content = File.read(path)
    dependencies = []

    lockfile_content.scan(dependency_metadata_regex).each do |dependency_properties|
      if dependency_properties.length < 3
        report_error("Could not parse dependency metadata #{dependency_properties}")
        next
      end
      dependency_hash = {}
      dependency_hash['group_id'] = dependency_properties[0]
      dependency_hash['artifact_id'] = dependency_properties[1]
      dependency_hash['version'] = dependency_properties[2]
      dependencies.append(dependency_hash)
    end

    report_error('Could not parse dependencies of Gradle project') if dependencies.empty?
    dependencies
  end
end
