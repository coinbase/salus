source 'https://rubygems.org'

ruby '2.7.2'

gem 'activesupport', '~> 6.1.3'
gem 'bugsnag', '~> 6.19.0'
gem 'bundler', '= 2.2.19'
gem 'faraday', '~> 1.3'
gem 'github-linguist', '~> 7.13.0'
gem 'parser', '~> 3.0.0'
gem 'rgl', '~> 0.5.7'
gem 'safe_yaml', '~> 1.0'
gem 'thor', '~> 1.1.0'
gem 'toml', '~> 0.2.0'

group :scanners do
  gem 'brakeman', '4.10.0'
  gem 'bundler-audit', '~> 0.8.0'
end

group :test, :development do
  gem 'pry', '~> 0.10'
  gem 'pry-byebug', '~> 3.4'
end

group :test do
  gem 'rspec', '~> 3.10'
  gem 'rspec_junit_formatter'
  gem 'rubocop', '~> 0.93', require: false
  gem 'simplecov', '~> 0.21.2'
  gem 'webmock', '~> 3.12'
end

gem "json-schema", "~> 2.8"
