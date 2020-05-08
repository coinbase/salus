module Salus
  module SalusBugsnag
    def bugsnag_notify(msg)
      Bugsnag.notify(msg) if ENV['BUGSNAG_API_KEY']
    end
  end
end
