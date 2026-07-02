defmodule Nivrit.SmokeTest do
  use ExUnit.Case

  @api_url System.get_env("NIVRIT_API_URL") || "http://localhost:4000"
  @email "sdk-elixir-#{System.os_time(:millisecond)}@example.com"
  @password "Correct-Horse-Battery-Staple!"

  defp api_request(method, path, body \\ nil, token \\ nil) do
    url = @api_url <> path
    headers = [{'Content-Type', 'application/json'}]
    headers = if token, do: [{'Authorization', 'Bearer #{token}'} | headers], else: headers
    json = if body, do: Jason.encode!(body), else: ""
    req = {url, headers, 'application/json', json}
    {:ok, {{_, status, _}, _, resp_body}} = :httpc.request(method, req, [], [])
    body_str = List.to_string(resp_body)
    unless status >= 200 and status < 300 do
      raise "API error #{status}: #{body_str}"
    end
    Jason.decode!(body_str)
  end

  test "full sdk smoke test" do
    crypto = Nivrit.new_crypto()
    keypair = Nivrit.Crypto.generate_keypair(crypto, @password)

    reg = api_request(:post, "/auth/register", %{
      "email" => @email,
      "password" => @password,
      "name" => "Elixir SDK Test",
      "public_key" => keypair["public_key"],
      "encrypted_private_key" => keypair["encrypted_private_key"],
      "private_key_nonce" => keypair["private_key_nonce"],
      "private_key_algorithm" => keypair["private_key_algorithm"]
    })
    IO.puts("registered #{reg["user"]["email"]}")

    pat = api_request(:post, "/auth/pat", %{"name" => "elixir-sdk-test"}, reg["token"])
    IO.puts("created PAT")

    session = Nivrit.new_session(@api_url, pat["token"], crypto)
    session = Nivrit.Session.authenticate(session, @password)
    IO.puts("session user #{session.user["email"]}")

    org = Nivrit.Client.create_org(session.client, %{
      "name" => "Elixir SDK Org",
      "slug" => "elixir-sdk-org-#{System.os_time(:second)}"
    })
    IO.puts("created org #{org["name"]}")

    project_key = Base.encode64(:crypto.strong_rand_bytes(32))
    encapsulated = Nivrit.Crypto.encapsulate_project_key(crypto, project_key, session.user["public_key"])
    encrypted_project_key = Base.encode64(Jason.encode!(encapsulated))

    project = Nivrit.Client.create_project(session.client, %{
      "org_id" => org["id"],
      "name" => "Elixir SDK Project",
      "slug" => "elixir-sdk-project-#{System.os_time(:second)}",
      "encrypted_project_key" => encrypted_project_key,
      "project_key_nonce" => Base.encode64(:crypto.strong_rand_bytes(12)),
      "project_key_algorithm" => "hybrid_x25519_ml_kem_768_aes256gcm_v1"
    })
    IO.puts("created project #{project["name"]}")

    env = Nivrit.Client.create_environment(session.client, project["id"], %{"name" => "Dev", "slug" => "dev"})
    IO.puts("created environment #{env["name"]}")

    encrypted = Nivrit.Crypto.encrypt_value(crypto, "hello-elixir-sdk", project_key)
    Nivrit.Client.create_secret(session.client, project["id"], %{
      "environment_id" => env["id"],
      "key" => "GREETING",
      "encrypted_value" => encrypted["ciphertext"],
      "nonce" => encrypted["nonce"],
      "algorithm" => "aes256gcm-v1"
    })
    IO.puts("created secret")

    secrets = Nivrit.Session.list_secrets(session, project["id"], env["id"])
    assert length(secrets) == 1
    assert hd(secrets)["value"] == "hello-elixir-sdk"
    IO.puts("decrypted secret: #{hd(secrets)["value"]}")

    api_request(:delete, "/auth/pats/#{pat["id"]}", nil, reg["token"])
    IO.puts("revoked PAT")
    IO.puts("Elixir SDK smoke test passed")
  end
end
