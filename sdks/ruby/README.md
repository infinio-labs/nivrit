# Nivrit Ruby SDK

```bash
gem install nivrit_sdk -v 0.1.0
```

## Usage

```ruby
require 'nivrit_sdk'

crypto = NivritSdk::HelperCrypto.new
session = NivritSdk::NivritSession.new('http://localhost:4000', pat_token, crypto)
session.authenticate(password)
secrets = session.list_secrets(project_id, environment_id)
puts secrets.first['value']
```

The SDK expects the `nivrit-crypto-helper` binary on `PATH` or at `NIVRIT_CRYPTO_HELPER`.

## Test

```bash
ruby test/smoke_test.rb
```
