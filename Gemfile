source 'https://rubygems.org'

ruby '2.7.0'

gem 'activesupport', '~> 6.0.3'
gem 'brakeman', '= 4.9.1'
gem 'bugsnag', '~> 6.13.1'
# TODO: Lock `bundler` until:
#  https://github.com/rubysec/bundler-audit/issues/235 and
#  https://github.com/bundler/bundler/issues/7511 are resolved.
gem 'bundler', '= 2.0.2'
gem 'bundler-audit', '~> 0.6.1'
gem 'faraday', '~> 0.9'
gem 'github-linguist', '~> 6.0.1'
gem 'safe_yaml', '~> 1.0'
gem 'thor', '~> 0.20.3'
gem 'toml', '~> 0.1.2'

group :test, :development do
  gem 'pry', '~> 0.10'
  gem 'pry-byebug', '~> 3.4'
end

group :test do
  gem 'rspec', '~> 3.4'
  gem 'rspec_junit_formatter'
  gem 'rubocop', '~> 0.92', require: false
  gem 'simplecov', '~> 0.15.1'
  gem 'webmock', '~> 3.0'
end
