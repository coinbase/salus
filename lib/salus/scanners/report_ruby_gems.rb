require 'salus/scanners/base'



# Report the use of any Ruby gems.

module Salus::Scanners
  class ReportRubyGems < Base
    def run
      begin
        report_ruby_license() # spec to test if method is called
      rescue StandardError => e
        bugsnag_notify("error from running license finder: #{e.message}") #update error message to a better one
      end 
      
      if @repository.gemfile_lock_present?
        record_dependencies_from_gemfile_lock
      elsif @repository.gemfile_present?
        record_dependencies_from_gemfile
      else
        raise InvalidScannerInvocationError,
              'Cannot report on Ruby gems without a Gemfile or Gemfile.lock'
      end
    end

    def should_run?
      #wrap report ruby licenses
      @repository.gemfile_present? || @repository.gemfile_lock_present?
    end

    def self.supported_languages
      ['ruby']
    end

    private

    def record_dependencies_from_gemfile_lock
      lockfile = Bundler::LockfileParser.new(@repository.gemfile_lock)

      # lockfile.bundler_version isn't a string, so stringify it first
      report_info(:ruby_version, lockfile.ruby_version)
      report_info(:bundler_version, lockfile.bundler_version.to_s)

      lockfile.specs.each do |gem|
        record_ruby_gem(
          name: gem.name,
          version: gem.version.to_s,
          source: gem.source.to_s,
          dependency_file: 'Gemfile.lock'
        )
      end
    end

    def record_dependencies_from_gemfile
      ruby_project = Bundler::Definition.build("#{@repository.path_to_repo}/Gemfile", nil, nil)

      # Record ruby version if present in Gemfile.
      if ruby_project.ruby_version
        ruby_version = ruby_project.ruby_version.versions.first
        report_info(:ruby_version, ruby_version)
      end

      # Record ruby gems.
      ruby_project.dependencies.each do |gem|
        record_ruby_gem(
          name: gem.name,

          # For a Gemfile, the best estimation of the version is the requirement.
          version: gem.requirement.to_s,

          # Gem uses the given source, otherwise Bundler has a default.
          source: gem.source.nil? ? Bundler.rubygems.sources.first.uri.to_s : gem.source.to_s,

          dependency_file: 'Gemfile',

        )
      end
    end

    # Returns an array of license info
    def find_licenses 
      output = run_license_finder()
      license_finder_parsed = output.split('approval:').last
      # puts "this is licences-finder : #{license_finder_parsed}"
      license_finder_hsh = JSON.parse(license_finder_parsed) 
      license_finder_hsh["dependencies"]
    end
    
    # Runs license_finder shell command
    def run_license_finder() 
      license_info = ""
      Dir.chdir(@repository.path_to_repo) do
        shell_return = `license_finder --format json`
        license_info = shell_return
      end
      return license_info
    end

    # Captures license information of a given repository
    def report_ruby_license
      license_arr = find_licenses()
      @opt_hsh = {}
      license_arr.each do |dep|
        puts dep["licenses"].inspect
        @opt_hsh[[dep["name"],dep["version"]].to_s] = to_spdx(dep["licenses"])
        puts "this is dep: #{@opt_hsh[[dep["name"],dep["version"]].to_s]}"
      end
    end
    
    # Dice coefficient = bigram overlap * 2 / (bigrams in a + bigrams in b)
    def dice_coefficient(a, b)
      a_bigrams = a.each_char.each_cons(2).to_a
      b_bigrams = b.each_char.each_cons(2).to_a
    
      overlap = (a_bigrams & b_bigrams).size
    
      total = a_bigrams.size + b_bigrams.size
      dice  = overlap * 2.0 / total
      
      dice
    end

    # Converts each license in an array of licenses to spdx formatted licenses
    def to_spdx(licenses_arr)
      licenses_arr.map{ |license| match_license(license)}
    end 

    # Compares reported license with spdx licenses and returns closest match 
    def match_license(license)
      spdx_schema = File.read("lib/cyclonedx/schema/spdx.schema.json") 
      spdx_hsh = JSON.parse(spdx_schema)
      spdx_licenses = spdx_hsh["enum"] #array of permitted SPDX formatted licenses
      @matching_hsh = {}
      spdx_licenses.each do |spdx_license|
        coefficient  = dice_coefficient(license, spdx_license)
        @matching_hsh[spdx_license] = coefficient
      end 
      puts"this is the match: #{largest_hash_key(@matching_hsh).inspect} done"
      largest_hash_key(@matching_hsh)
    end 


    def largest_hash_key(hash)
      hash.max_by{|k,v| v}[0]
    end


    def record_ruby_gem(name:, version:, source:, dependency_file:)
      dep_hsh = report_dependency(
        dependency_file,
        type: 'gem',
        name: name,
        version: version,
        source: source,
        licenses: @opt_hsh[[name,version].to_s]
      )

     
  end
end
end

