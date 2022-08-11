require_relative '../../spec_helper.rb'

describe Salus::SemanticVersion do
  describe 'select_upgrade_version' do
    it 'does not exceed the recommended major version' do
      patched_version_range = '>5.0.0'
      available_versions = [
        '1.0.0',
        '5.0.0',
        '5.1.0',
        '9.0.0'
      ]

      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions)
      ).to eq('5.1.0')
    end

    it 'returns nil if no provided versions satisfy the patch range' do
      patched_version_range = '>5.0.0'
      available_versions = [
        '1.0.0',
        '3.9.0',
        '4.9.9'
      ]

      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions)
      ).to eq(nil)
    end

    it 'correctly handles ">" ranges' do
      patched_version_range = '>5.0.0'
      available_versions = [
        '1.0.0',
        '3.9.0',
        '4.9.9',
        '5.4.0',
        '5.9.9'
      ]

      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions)
      ).to eq('5.9.9')
    end

    it 'correctly handles "<" ranges' do
      patched_version_range = '<5.9.9'
      available_versions = [
        '1.0.0',
        '3.9.0',
        '4.9.9',
        '5.4.0',
        '5.9.9'
      ]

      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions)
      ).to eq('5.4.0')
    end

    it 'correctly handles ">=" ranges' do
      patched_version_range = '>=5.0.0'
      available_versions1 = [
        '1.0.0',
        '3.9.0',
        '4.9.9',
        '5.0.0'
      ]

      available_versions2 = [
        '1.0.0',
        '3.9.0',
        '4.9.9',
        '5.0.0',
        '5.9.9'
      ]

      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions1)
      ).to eq('5.0.0')
      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions2)
      ).to eq('5.9.9')
    end

    it 'correctly handles ">=" ranges' do
      patched_version_range = '<=5.9.9'
      available_versions1 = [
        '1.0.0',
        '3.9.0',
        '4.9.9',
        '5.0.0'
      ]
      available_versions2 = [
        '1.0.0',
        '3.9.0',
        '4.9.9',
        '5.0.0',
        '5.9.9'
      ]

      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions1)
      ).to eq('5.0.0')
      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range, available_versions2)
      ).to eq('5.9.9')
    end

    it 'correctly handles exact versions' do
      patched_version_range1 = '=5.0.0'
      patched_version_range2 = '5.0.0'

      available_versions = [
        '5.0.0',
        '5.4.7',
        '5.9.9'
      ]

      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range1, available_versions)
      ).to eq('5.0.0')
      expect(
        Salus::SemanticVersion.select_upgrade_version(patched_version_range2, available_versions)
      ).to eq('5.0.0')
    end
  end

  describe 'select_max_version' do
    it 'gets the max of two semvers via the major version' do
      expect(
        Salus::SemanticVersion.select_max_version('1.0.0', '2.0.0')
      ).to eq('2.0.0')
    end

    it 'gets the max of two semvers via the minor version' do
      expect(
        Salus::SemanticVersion.select_max_version('1.1.0', '1.0.0')
      ).to eq('1.1.0')
    end

    it 'gets the max of two semvers via the patch version' do
      expect(
        Salus::SemanticVersion.select_max_version('1.1.0', '1.1.1')
      ).to eq('1.1.1')
    end

    it 'gets the value of both arguments if they are equal' do
      expect(
        Salus::SemanticVersion.select_max_version('1.1.1', '1.1.1')
      ).to eq('1.1.1')
    end

    it 'returns nil if either argument is not a three-part semantic version' do
      expect(
        Salus::SemanticVersion.select_max_version('foo', '1.1.1')
      ).to eq(nil)

      expect(
        Salus::SemanticVersion.select_max_version('1.1.1', 'foo')
      ).to eq(nil)
    end
  end
end
