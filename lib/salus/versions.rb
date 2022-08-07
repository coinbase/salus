module Salus
  class Versions
    class SemVersion < Gem::Version; end
    def select_upgrade_version(patched_version, list_of_versions)
      list_of_versions.each do |version|
        if patched_version.include? ">="
          parsed_patched_version = patched_version.tr(">=", "").tr(">= ", "")
          return version if SemVersion.new(version) >= SemVersion.new(parsed_patched_version)
        end
      end
      nil
    end
  end
end
