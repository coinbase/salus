module Salus
  module Bugsnag
    def bugsnag_notify(msg)
      Bugsnag.notify(msg) if ENV['BUGSNAG_API_KEY']
    end
  end    
end

if ENV['BUGSNAG_API_KEY']
  include Salus::Bugsnag

  Bugsnag.configure do |config|
    config.endpoint = ENV.fetch('BUGSNAG_ENDPOINT', 'notify.bugsnag.com')
    config.api_key = ENV['BUGSNAG_API_KEY']
  end
  
  # Hook at_exit to send off the fatal exception if it occurred
  at_exit { bugsnag_notify($ERROR_INFO) if $ERROR_INFO }
end

