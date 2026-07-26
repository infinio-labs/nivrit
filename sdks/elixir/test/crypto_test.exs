defmodule Nivrit.CryptoTest do
  use ExUnit.Case

  # Pure crypto round-trips through the nivrit-crypto-helper binary; no API
  # required. Guards the System.cmd stdin path: a broken stdin (the previous
  # `:stdin` option, which System.cmd silently ignored) makes every call raise
  # because the helper reads empty input.
  #
  # Build the helper first (cargo build --locked --release -p nivrit-crypto-helper) or set
  # NIVRIT_CRYPTO_HELPER to its path.

  setup do
    {:ok, crypto: Nivrit.Crypto.new()}
  end

  test "hybrid_suite_id returns the suite id", %{crypto: c} do
    assert Nivrit.Crypto.hybrid_suite_id(c) == "hybrid_x25519_ml_kem_768_aes256gcm_v1"
  end

  test "value encrypt/decrypt round-trip", %{crypto: c} do
    key = Base.encode64(:crypto.strong_rand_bytes(32))
    enc = Nivrit.Crypto.encrypt_value(c, "hello-elixir", key)
    assert Nivrit.Crypto.decrypt_value(c, enc["ciphertext"], enc["nonce"], key) == "hello-elixir"
  end

  test "keypair generate -> private key decrypt round-trip", %{crypto: c} do
    pw = "correct horse battery staple"
    kp = Nivrit.Crypto.generate_keypair(c, pw)
    priv = Nivrit.Crypto.decrypt_private_key(c, kp["encrypted_private_key"], kp["private_key_nonce"], pw)
    assert is_binary(priv) and byte_size(priv) > 0
  end

  test "project key encapsulate -> decapsulate round-trip", %{crypto: c} do
    pw = "another password"
    kp = Nivrit.Crypto.generate_keypair(c, pw)
    priv = Nivrit.Crypto.decrypt_private_key(c, kp["encrypted_private_key"], kp["private_key_nonce"], pw)
    project_key = Base.encode64(:crypto.strong_rand_bytes(32))
    enc = Nivrit.Crypto.encapsulate_project_key(c, project_key, kp["public_key"])
    blob = Base.encode64(Jason.encode!(enc))
    assert Nivrit.Crypto.decapsulate_project_key(c, blob, priv) == project_key
  end
end
