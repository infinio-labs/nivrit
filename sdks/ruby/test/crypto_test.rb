require 'minitest/autorun'
require 'base64'
require 'json'
require 'securerandom'
require_relative '../lib/nivrit_sdk/crypto'

# Hermetic crypto round-trips through the nivrit-crypto-helper binary; no API
# required. Set NIVRIT_CRYPTO_HELPER or build the helper at target/release.
class CryptoTest < Minitest::Test
  def setup
    @c = NivritSdk::HelperCrypto.new
  end

  def test_hybrid_suite_id
    assert_equal 'hybrid_x25519_ml_kem_768_aes256gcm_v1', @c.hybrid_suite_id
  end

  def test_value_roundtrip
    key = Base64.strict_encode64(SecureRandom.bytes(32))
    enc = @c.encrypt_value('hello-ruby', key)
    assert_equal 'hello-ruby', @c.decrypt_value(enc['ciphertext'], enc['nonce'], key)
  end

  def test_keypair_and_project_key
    pw = 'correct horse battery staple'
    kp = @c.generate_keypair(pw)
    priv = @c.decrypt_private_key(kp['encrypted_private_key'], kp['private_key_nonce'], pw)
    project_key = Base64.strict_encode64(SecureRandom.bytes(32))
    enc = @c.encapsulate_project_key(project_key, kp['public_key'])
    blob = Base64.strict_encode64(JSON.generate(enc))
    assert_equal project_key, @c.decapsulate_project_key(blob, priv)
  end
end
