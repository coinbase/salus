module Gradle
  GRADLE7 = "/opt/gradle/gradle-7.3.3/bin/gradle".freeze
  GRADLE6 = "/opt/gradle/gradle-6.9.2/bin/gradle".freeze

  def gradle_dependencies
    dependency_metadata_regex = /-\s(?<group_id>.+):(?<artifact_id>.+):(?<version>.+)/

    # 'gradle dependencies' command needs to be run in the folder where buid.gradle is present.
    shell_result = run_shell("#{GRADLE7} dependencies")

    shell_result = run_shell("#{GRADLE6} dependencies") if !shell_result.success?
    if !shell_result.success?
      report_error("Gradle Version Not supported. Please Upgrade to gradle version 6 and above")
      return []
    end

    dependencies = []

    shell_result.stdout.scan(dependency_metadata_regex).each do |dependency_properties|
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
