module Gradle
  GRADLE7 = "/opt/gradle/gradle-7.5.1/bin/gradle".freeze
  GRADLE6 = "/opt/gradle/gradle-6.9.2/bin/gradle".freeze
  GET_GRADLE_PROJECTS = "./gradlew projects --info".freeze


  def is_multi_project
    projects = []
    command = "./gradlew "
    projects_shell_result = run_shell(GET_GRADLE_PROJECTS)
    projects_shell_result.stdout.each_line do |line|
      if line.include? '--- Project '
        projects.append(line.split.last.strip.tr(":", "").tr("'", ""))
      end
    end

    projects.each do |proj|
      command += proj + ":dependencies "
    end

    run_shell(command)
  end

  def is_single_project
    shell_result = run_shell("#{GRADLE7} dependencies")
    run_shell("#{GRADLE6} dependencies") if !shell_result.success?
  end



  def gradle_dependencies
    dependency_metadata_regex = /-\s(?<group_id>.+):(?<artifact_id>.+):(?<version>.+)/
    if @config['multi'].to_s == 'true'
      result = is_multi_project
    else
      result = is_single_project
    end

    # 'gradle dependencies' command needs to be run in the folder where buid.gradle is present.
    if !result.success?
      report_error("Gradle Version Not supported. Please Upgrade to gradle version 6 and above")
      return []
    end

    dependencies = []
    result.stdout.scan(dependency_metadata_regex).each do |dependency_properties|
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