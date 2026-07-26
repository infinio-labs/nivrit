# Nivrit Node.js SDK

```bash
bun add @nivrit/sdk
```

(Works with npm/yarn too — bun is the project's package manager.)

## Usage

```js
const { HelperCrypto, NivritSession } = require('@nivrit/sdk');

const crypto = new HelperCrypto();
const session = await NivritSession.fromPat(
  'http://localhost:4000',
  process.env.NIVRIT_PAT,
  process.env.NIVRIT_PASSWORD,
  crypto
);

const secrets = await session.listSecrets(projectId, environmentId);
console.log(secrets[0].key, secrets[0].value);
```

The SDK expects the `nivrit-crypto-helper` binary on `PATH` or at `NIVRIT_CRYPTO_HELPER`.

## Test

```bash
bun test
```
