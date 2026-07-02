require 'json'
require 'open3'
require 'pathname'

module NivritSdk
  class HelperCrypto
    def initialize(helper_path = nil)
      @helper_path = helper_path || find_helper
    end

    def hybrid_suite_id
      call('op' => 'hybrid_suite_id')
    end

    def generate_keypair(password)
      call('op' => 'generate_keypair', 'password' => password)
    end

    def decrypt_private_key(encrypted_private_key, nonce, password)
      call(
        'op' => 'decrypt_private_key',
        'encrypted_private_key' => encrypted_private_key,
        'nonce' => nonce,
        'password' => password
      )['private_key']
    end

    def decapsulate_project_key(encrypted_project_key, private_key)
      call(
        'op' => 'decapsulate_project_key',
        'encrypted_project_key' => encrypted_project_key,
        'private_key' => private_key
      )['project_key']
    end

    def encrypt_value(plaintext, key)
      call('op' => 'encrypt_value', 'plaintext' => plaintext, 'key' => key)
    end

    def decrypt_value(ciphertext, nonce, key)
      call(
        'op' => 'decrypt_value',
        'ciphertext' => ciphertext,
        'nonce' => nonce,
        'key' => key
      )['plaintext']
    end

    def encapsulate_project_key(project_key, recipient_public_key)
      call(
        'op' => 'encapsulate_project_key',
        'project_key' => project_key,
        'recipient_public_key' => recipient_public_key
      )
    end

    private

    def find_helper
      env = ENV['NIVRIT_CRYPTO_HELPER']
      return env if env && !env.empty?

      exe = Gem.win_platform? ? 'nivrit-crypto-helper.exe' : 'nivrit-crypto-helper'

      # Bundled in the platform gem at sdks/ruby/vendor/ (see build-gems.sh).
      # __dir__ is sdks/ruby/lib/nivrit_sdk, so vendor/ is two levels up.
      bundled = File.expand_path(File.join(__dir__, '..', '..', 'vendor', exe))
      return bundled if File.exist?(bundled)

      # Dev fallback: monorepo cargo build output (repo root is four levels up).
      here = Pathname.new(__dir__).expand_path
      (here / '..' / '..' / '..' / '..' / 'target' / 'release' / exe).to_s
    end

    def call(req)
      out, status = Open3.capture2(@helper_path, stdin_data: req.to_json)
      raise "crypto helper exited #{status.exitstatus}" unless status.success?

      resp = JSON.parse(out.strip)
      raise "crypto helper error: #{resp['error']}" unless resp['ok']

      resp['result']
    end
  end
end
