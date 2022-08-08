module Salus
  class Versions
    class SemVersion < Gem::Version; end
    def select_upgrade_version(patched_version, _current_version, list_of_versions)
      # check if patched_version is valid - present in list_of_version and is not major
      list_of_versions.each do |version|
        if patched_version.include? ">="
          parsed_patched_version = patched_version.tr(">=", "").tr(">= ", "")
          return version if SemVersion.new(version) >= SemVersion.new(parsed_patched_version)
        end
      end
      nil
    end

    def is_major(patched_version, current_version)
      # return if this is a major upgrade or not
    end

    def select_max_version(versions)
      # return max version from a list of versions
    end
  end
end
