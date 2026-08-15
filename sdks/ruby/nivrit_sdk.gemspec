Gem::Specification.new do |s|
  s.name        = 'nivrit_sdk'
  s.version     = '1.0.1'
  s.summary     = 'Nivrit secrets SDK for Ruby'
  s.authors     = ['Nivrit Contributors']
  s.files       = Dir['lib/**/*.rb'] + Dir['vendor/*']
  s.license     = 'AGPL-3.0-only'
  s.required_ruby_version = '>= 3.0'

  # Set by build-gems.sh to produce a fat per-platform gem (binary in vendor/).
  # Unset -> a pure-Ruby gem that falls back to NIVRIT_CRYPTO_HELPER / dev build.
  plat = ENV['NIVRIT_GEM_PLATFORM']
  s.platform = plat unless plat.nil? || plat.empty?
end
