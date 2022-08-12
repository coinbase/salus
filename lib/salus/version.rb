module Salus
  class Version
    def self.select_upgrade_version(_patched_version_range, _versions_list)
      nil
    end

    def select_max_version(version_a, _version_b)
      version_a
    end
  end
end
