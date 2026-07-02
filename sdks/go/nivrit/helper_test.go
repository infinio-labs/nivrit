package nivrit

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// Regression guard for packaged resolution: with no env override and no dev
// build, a release binary must resolve from the embedded FS alone. Skips in the
// dev tree (bin/ holds only .keep), runs for real in the packaged CI job.
func TestBundledHelperResolves(t *testing.T) {
	os.Unsetenv("NIVRIT_CRYPTO_HELPER")
	p, err := extractHelper()
	if err != nil {
		t.Skip("no embedded helper in this build (dev tree)")
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("extracted helper missing or empty at %s: %v", p, err)
	}
}

// Full hermetic crypto round-trip driven only through the embedded helper (no
// API, no env override) — proves the packaged binary actually works, not just
// that it resolves. Skips in the dev tree.
func TestBundledHelperRoundtrip(t *testing.T) {
	os.Unsetenv("NIVRIT_CRYPTO_HELPER")
	if _, err := extractHelper(); err != nil {
		t.Skip("no embedded helper in this build (dev tree)")
	}
	c := NewHelperCrypto("")

	suite, err := c.HybridSuiteId()
	if err != nil || suite != "hybrid_x25519_ml_kem_768_aes256gcm_v1" {
		t.Fatalf("suite id: %q err=%v", suite, err)
	}
	kp, err := c.GenerateKeypair("pw")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := c.DecryptPrivateKey(kp["encrypted_private_key"], kp["private_key_nonce"], "pw")
	if err != nil {
		t.Fatal(err)
	}
	pk := base64.StdEncoding.EncodeToString(make([]byte, 32))
	enc, err := c.EncapsulateProjectKey(pk, kp["public_key"])
	if err != nil {
		t.Fatal(err)
	}
	encJSON, _ := json.Marshal(enc)
	blob := base64.StdEncoding.EncodeToString(encJSON)
	got, err := c.DecapsulateProjectKey(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != pk {
		t.Fatalf("roundtrip mismatch: %s != %s", got, pk)
	}
}
