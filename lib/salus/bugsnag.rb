require 'bugsnag'
require 'English'

# If present, configure Bugsnag globally to capture all errors
# including both handled and unhandled execptions
if ENV['BUGSNAG_API_KEY']
  Bugsnag.configure do |config|
    config.endpoint = ENV.fetch('BUGSNAG_ENDPOINT', 'notify.bugsnag.com')
    config.api_key = ENV['BUGSNAG_API_KEY']
    config.release_stage = 'production'
  end

  # Hook at_exit to send off the fatal exception if it occurred
  at_exit { Bugsnag.notify($ERROR_INFO) if $ERROR_INFO }
end

module Salus
  module SalusBugsnag
    def bugsnag_notify(msg)
      Bugsnag.notify(msg) if ENV['BUGSNAG_API_KEY']
    end
  end
end
