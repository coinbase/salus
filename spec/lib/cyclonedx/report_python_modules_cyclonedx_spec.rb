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
          "bom-ref": "pkg:python_requirement/requests",
          "type": "library",
          "group": "",
          "name": "requests",
          "version": ">=2.5",
          "purl": "pkg:python_requirement/requests",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/six",
            "type": "library",
            "group": "",
            "name": "six",
            "version": ">=1.9",
            "purl": "pkg:python_requirement/six",
            "properties": [
              {
                "key": "source",
                "value": ""
              },
              {
                "key": "dependency_file",
                "value": "requirements.txt"
              }
            ]
        },
        {
          "bom-ref": "pkg:python_requirement/pycryptodome",
            "type": "library",
            "group": "",
            "name": "pycryptodome",
            "version": ">=3.4.11",
            "purl": "pkg:python_requirement/pycryptodome",
            "properties": [
              {
                "key": "source",
                "value": ""
              },
              {
                "key": "dependency_file",
                "value": "requirements.txt"
              }
            ]
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
          "bom-ref": "pkg:python_requirement/amqp",
          "type": "library",
          "group": "",
          "name": "amqp",
          "version": "==2.2.2",
          "purl": "pkg:python_requirement/amqp",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/billiard",
          "type": "library",
          "group": "",
          "name": "billiard",
          "version": "==3.5.0.3",
          "purl": "pkg:python_requirement/billiard",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/celery",
          "type": "library",
          "group": "",
          "name": "celery",
          "version": "==4.1.0",
          "purl": "pkg:python_requirement/celery",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
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
          "bom-ref": "pkg:python_requirement/six",
          "type": "library",
          "group": "",
          "name": "six",
          "version": ">=1.9",
          "purl": "pkg:python_requirement/six",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/pycryptodome",
          "type": "library",
          "group": "",
          "name": "pycryptodome",
          "version": ">=3.4.11",
          "purl": "pkg:python_requirement/pycryptodome",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/celery",
          "type": "library",
          "group": "",
          "name": "celery",
          "version": "==4.0.0",
          "purl": "pkg:python_requirement/celery",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/Jinja2",
          "type": "library",
          "group": "",
          "name": "Jinja2",
          "version": "==2.10",
          "purl": "pkg:python_requirement/Jinja2",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/itsdangerous",
          "type": "library",
          "group": "",
          "name": "itsdangerous",
          "version": "==0.24",
          "purl": "pkg:python_requirement/itsdangerous",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        },
        {
          "bom-ref": "pkg:python_requirement/idna",
          "type": "library",
          "group": "",
          "name": "idna",
          "version": "==2.6",
          "purl": "pkg:python_requirement/idna",
          "properties": [
            {
              "key": "source",
              "value": ""
            },
            {
              "key": "dependency_file",
              "value": "requirements.txt"
            }
          ]
        }
      ]
      expect(python_cyclonedx.build_components_object).to include(*expected)
    end
  end
end
