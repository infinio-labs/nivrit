# Nivrit .NET SDK

```bash
dotnet add package Nivrit.Sdk
```

## Usage

```csharp
using Nivrit;

var crypto = new HelperCrypto();
var session = new NivritSession("http://localhost:4000", patToken, crypto);
await session.AuthenticateAsync(password);
var secrets = await session.ListSecretsAsync(projectId, environmentId);
```

The SDK expects the `nivrit-crypto-helper` binary on `PATH` or at `NIVRIT_CRYPTO_HELPER`.

## Build package

```bash
cd sdks/dotnet/Nivrit
dotnet restore --locked-mode
dotnet pack -c Release --no-restore
```
