require 'date'
require 'active_model'

module Salus
  class ConfigException
  	DATE_FORMAT = "%Y-%m-%d"
    include ActiveModel::Validations

    attr_accessor :advisory_id, :changed_by, :notes, :expiration

    # allow blank to mirror our old logic validates_presense_of would be nice
    validates :advisory_id, :changed_by, :notes, length: { minimum: 0, allow_nil: false }

# Old logic:
#  if !exception.is_a?(Hash) || exception.keys.sort != %w[advisory_id changed_by notes]

    def initialize(exception_hash = nil)
      return unless exception_hash.is_a?(Hash)

      exception_hash.each do |k,v|
      	puts "v is nil" if v.nil?
        instance_variable_set("@#{k}", v) unless v.nil?
      end
    end

    def active?
      return false unless valid?
      return true unless expiration.present?
 	    today = Date.today()
	    expire = Date.strptime(expiration, DATE_FORMAT)
      return expire >= today
    end
  end
end