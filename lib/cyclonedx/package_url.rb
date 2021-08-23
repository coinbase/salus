module Cyclonedx
  class PackageUrl
    def initialize(type:, namespace:, version:)
      @type = type
      @namespace = namespace
      @version = version
    end

    # TODO: Add support for qualifiers and subpaths
    # https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst#how-to-build-purl-string-from-its-components
    def to_string
      # Start with type and a colon
      purl = "pkg:#{@type}/"

      # Add the required namespace
      if @namespace.present?
        # Remove leading and trailing /
        namespace = @namespace.delete_prefix("/").delete_suffix("/")

        ns = namespace.split("/").map { |s| CGI.escape(s) }
        purl += ns.join("/")
      end

      # If a version is provided, add it after the @ symbol
      purl += "@#{CGI.escape(@version)}" if @version.present?

      purl
    end
  end
end
