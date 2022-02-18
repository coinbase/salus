require_relative '../../spec_helper'
require 'json'

describe Cyclonedx::ReportPythonModules do
  describe "#run" do
    it 'should report all the deps in the unpinned requirements.txt' do
      repo = Salus::Repo.new('spec/fixtures/python/requirements_unpinned')
      scanner = Salus::Scanners::ReportPythonModules.new(repository: repo, config: {})
      scanner.run

      python_cyclonedx = Cyclonedx::ReportPythonModules.new(scanner.report)
      expected = [
        {
          "type": "library",
          "group": "",
          "name": "requests",
          "version": ">=2.5",
          "purl": "pkg:pypi/requests"
        },
        {
          "type": "library",
          "group": "",
            "name": "six",
            "version": ">=1.9",
            "purl": "pkg:pypi/six"
        },
        {
          "type": "library",
          "group": "",
            "name": "pycryptodome",
            "version": ">=3.4.11",
            "purl": "pkg:pypi/pycryptodome"
        }
      ]
      expect(python_cyclonedx.build_components_object).to include(*expected)
    end

    it 'should report all the deps in the pinned requirements.txt' do
      repo = Salus::Repo.new('spec/fixtures/python/requirements_pinned')
      scanner = Salus::Scanners::ReportPythonModules.new(repository: repo, config: {})
      scanner.run

      python_cyclonedx = Cyclonedx::ReportPythonModules.new(scanner.report)
      expected = [
        {
          "type": "library",
          "group": "",
          "name": "amqp",
          "version": "2.2.2",
          "purl": "pkg:pypi/amqp@2.2.2"
        },
        {
          "type": "library",
          "group": "",
          "name": "billiard",
          "version": "3.5.0.3",
          "purl": "pkg:pypi/billiard@3.5.0.3"
        },
        {
          "type": "library",
          "group": "",
          "name": "celery",
          "version": "4.1.0",
          "purl": "pkg:pypi/celery@4.1.0"
        }
      ]
      expect(python_cyclonedx.build_components_object).to include(*expected)
    end

    it 'should report all the deps in the semi-pinned requirements.txt' do
      repo = Salus::Repo.new('spec/fixtures/python/requirements_semi_pinned_vulnerable')
      scanner = Salus::Scanners::ReportPythonModules.new(repository: repo, config: {})
      scanner.run

      python_cyclonedx = Cyclonedx::ReportPythonModules.new(scanner.report)
      expected = [
        {
          "type": "library",
          "group": "",
          "name": "six",
          "version": ">=1.9",
          "purl": "pkg:pypi/six"
        },
        {
          "type": "library",
          "group": "",
          "name": "pycryptodome",
          "version": ">=3.4.11",
          "purl": "pkg:pypi/pycryptodome"
        },
        {
          "type": "library",
          "group": "",
          "name": "celery",
          "version": "4.0.0",
          "purl": "pkg:pypi/celery@4.0.0"
        },
        {
          "type": "library",
          "group": "",
          "name": "Jinja2",
          "version": "2.10",
          "purl": "pkg:pypi/Jinja2@2.10"
        },
        {
          "type": "library",
          "group": "",
          "name": "itsdangerous",
          "version": "0.24",
          "purl": "pkg:pypi/itsdangerous@0.24"
        },
        {
          "type": "library",
          "group": "",
          "name": "idna",
          "version": "2.6",
          "purl": "pkg:pypi/idna@2.6"
        }
      ]
      expect(python_cyclonedx.build_components_object).to include(*expected)
    end
  end
end
