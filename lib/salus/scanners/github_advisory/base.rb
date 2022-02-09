require 'salus/scanners/base'
require 'json'

module Salus::Scanners::GithubAdvisory
  class Base < Salus::Scanners::Base
    class ApiTooManyRequestsError < StandardError; end

    MAX_RETRIES_FOR_GITHUB_API = 2
    GITHUB_API_URL = "https://api.github.com/graphql".freeze
    GITHUB_API_MAX_PAGES = 100
    GITHUB_API_PAGE_SIZE = 100

    def github_query
      @github_query ||= if @repository.go_sum_present? || @repository.go_mod_present?
                          GO_ADVISORY_QUERY
                        elsif @repository.requirements_txt_present?
                          PIP_ADVISORY_QUERY
                        elsif @repository.pom_xml_present?
                          MAVEN_ADVISORY_QUERY
                        elsif @repository.gemfile_present? || @repository.gemfile_lock_present?
                          RUBYGEMS_ADVISORY_QUERY
                        end
    end

    def github_advisories
      @github_advisories ||= fetch_advisories
    end

    def should_run?
      ENV['GITHUB_ADVISORY_API_KEY'] && run_github_advisory_scan?
    end

    def run_github_advisory_scan?
      raise NoMethodError
    end

    def run
      raise NoMethodError
    end

    def name
      self.class.name.sub('Salus::Scanners::GithubAdvisory::', '')
    end

    def fetch_advisories
      # Handle paginating over Github API
      all_vulnerabilities_found = []
      variables = { "first" => GITHUB_API_PAGE_SIZE }
      GITHUB_API_MAX_PAGES.times do
        response = send_request(github_query, variables)
        vulnerabilities_per_page = response.dig("data", "securityVulnerabilities", "nodes")
        all_vulnerabilities_found += vulnerabilities_per_page
        unless response.dig("data", "securityVulnerabilities", "pageInfo", "hasNextPage") == true
          break
        end

        variables['after'] = response.dig("data", "securityVulnerabilities",
                                          "pageInfo", "endCursor")
      end
      all_vulnerabilities_found
    rescue StandardError => e
      report_error("Github Adviory failed: #{e}")
    rescue ApiTooManyRequestsError
      if retries < MAX_RETRIES_FOR_GITHUB_API
        retries += 1
        max_sleep_seconds = Float(2**retries)
        sleep rand(0..max_sleep_seconds)
        retry
      else
        msg = "Too many requests for github api after " \
        "#{retries} retries"
        report_error("Github Adviory failed: #{msg}")
      end
    end

    def github_api(adapter = :net_http)
      # Hold connection adapter
      @github_api ||= begin
        Faraday.new do |conn_builder|
          conn_builder.adapter adapter
          conn_builder.headers = {
            "Content-Type" => "application/json",
            "Authorization" => "token " + ENV['GITHUB_ADVISORY_API_KEY']
          }
        end
      end
    end

    def format_vulns(vulns)
      str = ""
      vulns.each do |vul|
        vul.each do |k, v|
          str += "#{k}: #{v}\n"
        end
        str += "\n"
      end
      str
    end

    def send_request(query_name, query_variables = {})
      query_body = JSON.generate(query: query_name, variables: query_variables)

      faraday_response = github_api.post do |req|
        req.url GITHUB_API_URL
        req.body = query_body
        req.options.timeout = 10
      end
      if faraday_response.status == 429
        raise(ApiTooManyRequestsError, faraday_response.body)
      elsif faraday_response.status != 200
        raise(StandardError, faraday_response.body)
      else
        body_obj = JSON.parse faraday_response.body
      end

      body_obj
    end

    GO_ADVISORY_QUERY = <<-GO_QUERY.freeze
        query($first: Int, $after: String) {
        securityVulnerabilities(first: $first, after: $after, ecosystem:GO) {
            pageInfo {
            endCursor
            hasNextPage
            hasPreviousPage
            startCursor
            }
            nodes {
            package {
                name
                ecosystem
            }
            vulnerableVersionRange
            firstPatchedVersion {
                identifier
            }
            advisory {
                identifiers {
                type
                value
                }
                summary
                description
                severity
                cvss {
                score
                vectorString
                }
                references {
                url
                }
                publishedAt
                withdrawnAt
            }
            }
        }
        }
    GO_QUERY
    PIP_ADVISORY_QUERY = <<-PIP_QUERY.freeze
        query($first: Int, $after: String) {
        securityVulnerabilities(first: $first, after: $after, ecosystem:PIP) {
            pageInfo {
            endCursor
            hasNextPage
            hasPreviousPage
            startCursor
            }
            nodes {
            package {
                name
                ecosystem
            }
            vulnerableVersionRange
            firstPatchedVersion {
                identifier
            }
            advisory {
                identifiers {
                type
                value
                }
                summary
                description
                severity
                cvss {
                score
                vectorString
                }
                references {
                url
                }
                publishedAt
                withdrawnAt
            }
            }
        }
        }
    PIP_QUERY
    MAVEN_ADVISORY_QUERY = <<-MAVEN_QUERY.freeze
        query($first: Int, $after: String) {
        securityVulnerabilities(first: $first, after: $after, ecosystem:MAVEN) {
            pageInfo {
            endCursor
            hasNextPage
            hasPreviousPage
            startCursor
            }
            nodes {
            package {
                name
                ecosystem
            }
            vulnerableVersionRange
            firstPatchedVersion {
                identifier
            }
            advisory {
                identifiers {
                type
                value
                }
                summary
                description
                severity
                cvss {
                score
                vectorString
                }
                references {
                url
                }
                publishedAt
                withdrawnAt
            }
            }
        }
        }
    MAVEN_QUERY
    RUBYGEMS_ADVISORY_QUERY = <<-RUBYGEMS_QUERY.freeze
        query($first: Int, $after: String) {
        securityVulnerabilities(first: $first, after: $after, ecosystem:RUBYGEMS) {
            pageInfo {
            endCursor
            hasNextPage
            hasPreviousPage
            startCursor
            }
            nodes {
            package {
                name
                ecosystem
            }
            vulnerableVersionRange
            firstPatchedVersion {
                identifier
            }
            advisory {
                identifiers {
                type
                value
                }
                summary
                description
                severity
                cvss {
                score
                vectorString
                }
                references {
                url
                }
                publishedAt
                withdrawnAt
            }
            }
        }
        }
    RUBYGEMS_QUERY
  end
end
