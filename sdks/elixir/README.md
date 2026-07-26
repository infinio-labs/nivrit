# Nivrit Elixir SDK

```elixir
defp deps do
  [
    {:nivrit, github: "infinio-labs/nivrit", sparse: "sdks/elixir"}
  ]
end
```

## Usage

```elixir
crypto = Nivrit.new_crypto()
session = Nivrit.new_session("http://localhost:4000", pat_token, crypto)
session = Nivrit.Session.authenticate(session, password)
secrets = Nivrit.Session.list_secrets(session, project_id, environment_id)
```

The SDK expects the `nivrit-crypto-helper` binary on `PATH` or at `NIVRIT_CRYPTO_HELPER`.

## Test

```bash
mix test
```
