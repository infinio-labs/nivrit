# Smallest check on helper resolution. Run: PYTHONPATH=. python3 tests/test_find_helper.py
import os
from nivrit.crypto import HelperCrypto

# env override wins
os.environ["NIVRIT_CRYPTO_HELPER"] = "/tmp/fake-helper"
assert HelperCrypto()._find_helper() == "/tmp/fake-helper"
del os.environ["NIVRIT_CRYPTO_HELPER"]

# no env, no bundle, no dev build -> raise with the fix in the message
try:
    HelperCrypto()
except FileNotFoundError as e:
    assert "cargo build" in str(e)
# else: a real build exists on this machine — fine, nothing to assert

print("ok")
