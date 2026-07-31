# Nivrit Go SDK

```bash
go get github.com/infinio-labs/nivrit/sdks/go/nivrit
```

## Usage

```go
import "github.com/infinio-labs/nivrit/sdks/go/nivrit"

crypto := nivrit.NewHelperCrypto("")
session := nivrit.NewSession("http://localhost:4000", patToken, crypto)
if err := session.Authenticate(password); err != nil { ... }

secrets, err := session.ListSecrets(projectID, environmentID)
```

The SDK expects the `nivrit-crypto-helper` binary on `PATH` or at `NIVRIT_CRYPTO_HELPER`.

## Test

```bash
go test -mod=readonly -v -run TestSmoke ./...
```
