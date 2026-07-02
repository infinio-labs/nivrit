require 'json'
require 'net/http'
require 'securerandom'
require 'base64'
require_relative '../lib/nivrit_sdk'

API_URL = ENV.fetch('NIVRIT_API_URL', 'http://localhost:4000')
EMAIL = "sdk-ruby-#{Time.now.to_i * 1000}@example.com"
PASSWORD = 'Correct-Horse-Battery-Staple!'

def api_request(method, path, body = nil, token = nil)
  uri = URI.parse("#{API_URL}#{path}")
  req = Net::HTTP.const_get(method.capitalize).new(uri)
  req['Content-Type'] = 'application/json'
  req['Authorization'] = "Bearer #{token}" if token
  req.body = body.to_json if body
  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
  raise "API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)
  JSON.parse(res.body) if res.body && !res.body.empty?
end

crypto = NivritSdk::HelperCrypto.new
keypair = crypto.generate_keypair(PASSWORD)

reg = api_request('post', '/auth/register', {
  'email' => EMAIL,
  'password' => PASSWORD,
  'name' => 'Ruby SDK Test',
  'public_key' => keypair['public_key'],
  'encrypted_private_key' => keypair['encrypted_private_key'],
  'private_key_nonce' => keypair['private_key_nonce'],
  'private_key_algorithm' => keypair['private_key_algorithm']
})
puts "registered #{reg['user']['email']}"

pat = api_request('post', '/auth/pat', { 'name' => 'ruby-sdk-test' }, reg['token'])
puts 'created PAT'

session = NivritSdk::NivritSession.new(API_URL, pat['token'], crypto)
session.authenticate(PASSWORD)
puts "session user #{session.user['email']}"

org = session.client.create_org({
  'name' => 'Ruby SDK Org',
  'slug' => "ruby-sdk-org-#{Time.now.to_i}"
})
puts "created org #{org['name']}"

project_key = Base64.strict_encode64(SecureRandom.bytes(32))
encapsulated = crypto.encapsulate_project_key(project_key, session.user['public_key'])
encrypted_project_key = Base64.strict_encode64(encapsulated.to_json)

project = session.client.create_project({
  'org_id' => org['id'],
  'name' => 'Ruby SDK Project',
  'slug' => "ruby-sdk-project-#{Time.now.to_i}",
  'encrypted_project_key' => encrypted_project_key,
  'project_key_nonce' => Base64.strict_encode64(SecureRandom.bytes(12)),
  'project_key_algorithm' => 'hybrid_x25519_ml_kem_768_aes256gcm_v1'
})
puts "created project #{project['name']}"

env = session.client.create_environment(project['id'], { 'name' => 'Dev', 'slug' => 'dev' })
puts "created environment #{env['name']}"

encrypted = crypto.encrypt_value('hello-ruby-sdk', project_key)
session.client.create_secret(project['id'], {
  'environment_id' => env['id'],
  'key' => 'GREETING',
  'encrypted_value' => encrypted['ciphertext'],
  'nonce' => encrypted['nonce'],
  'algorithm' => 'aes256gcm-v1'
})
puts 'created secret'

secrets = session.list_secrets(project['id'], env['id'])
raise "unexpected secrets: #{secrets.inspect}" unless secrets.length == 1 && secrets.first['value'] == 'hello-ruby-sdk'
puts "decrypted secret: #{secrets.first['value']}"

api_request('delete', "/auth/pats/#{pat['id']}", nil, reg['token'])
puts 'revoked PAT'
puts 'Ruby SDK smoke test passed'
