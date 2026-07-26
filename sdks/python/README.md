# Nivrit Python SDK

```bash
pip install nivrit-sdk==0.1.0
```

## Usage

```python
import asyncio
from nivrit import HelperCrypto, NivritSession

async def main():
    crypto = HelperCrypto()
    session = await NivritSession.from_pat(
        "http://localhost:4000",
        pat_token,
        password,
        crypto,
    )
    secrets = session.list_secrets(project_id, environment_id)
    print(secrets[0]["key"], secrets[0]["value"])

asyncio.run(main())
```

The SDK expects the `nivrit-crypto-helper` binary on `PATH` or at `NIVRIT_CRYPTO_HELPER`.

## Test

```bash
PYTHONPATH=. python3 tests/test_smoke.py
```
