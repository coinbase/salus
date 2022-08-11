require 'salus/version'

module Salus
  class SemanticVersion < Version
    SEMVER_REGEX = /\d+\.\d+\.\d+/.freeze
    SEMVER_RANGE_REGEX =
      /
        (?<operator>(<|>)?(=|~|\^|\*)?)?
        (?<version>(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+))?
      /x.freeze

    def self.select_upgrade_version(patched_version_range, versions_list)
      version_range_details =
        patched_version_range
          .match(SEMVER_RANGE_REGEX)
      major = version_range_details['major'].to_i
      minor = version_range_details['minor'].to_i
      patch = version_range_details['patch'].to_i

      range_operator = version_range_details['operator']

      # We reverse the list to search from the
      # latest versions first to the oldest versions last
      versions_list.reverse.find do |potential_upgrade_version|
        semver_categories = potential_upgrade_version.split('.')
        potential_major = semver_categories[0].to_i
        potential_minor = semver_categories[1].to_i
        potential_patch = semver_categories[2].to_i

        # NOTE: We want to avoid major version bumps
        #       that exceed the minimum non-vulnerable version.
        #       So if the patched range is >=2.2.0, we want to
        #       avoid using 3.0.0 as our upgrade version
        case range_operator
        when '*'
          potential_major == major
        when '>'
          potential_major == major && potential_minor > minor
        when '<'
          potential_major == major && potential_minor < minor
        when '>=', '^'
          potential_major == major && potential_minor >= minor
        when '<='
          potential_major == major && potential_minor <= minor
        when '~'
          potential_major == major && potential_minor == minor && potential_patch >= patch
        when '=', ''
          potential_major == major && potential_minor == minor && potential_patch == patch
        else
          false
        end
      end
    end

    def self.is_semver(version)
      !version.match(SEMVER_REGEX).nil?
    end

    def self.select_max_version(version_a, version_b)
      return nil if !SemanticVersion.is_semver(version_a)
      return nil if !SemanticVersion.is_semver(version_b)

      a_categories = version_a.split('.')
      b_categories = version_b.split('.')

      (0..a_categories.size).each do |i|
        if a_categories[i].to_i > b_categories[i].to_i
          return version_a
        elsif a_categories[i].to_i < b_categories[i].to_i
          return version_b
        else
          next
        end
      end
      # The two versions are equal
      version_a
    end
  end
end
