package nivrit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// HelperCrypto delegates cryptographic operations to the nivrit-crypto-helper binary.
type HelperCrypto struct {
	HelperPath string
}

func NewHelperCrypto(helperPath string) *HelperCrypto {
	if helperPath == "" {
		helperPath = findHelper()
	}
	return &HelperCrypto{HelperPath: helperPath}
}

func findHelper() string {
	if env := os.Getenv("NIVRIT_CRYPTO_HELPER"); env != "" {
		return env
	}
	// Embedded platform binary (release builds), extracted to the user cache dir.
	if p, err := extractHelper(); err == nil {
		return p
	}
	// Dev fallback: monorepo cargo build output (sdks/go/nivrit -> ../../../target/release).
	return filepath.Join("..", "..", "..", "target", "release", "nivrit-crypto-helper")
}

func (c *HelperCrypto) call(req map[string]any, target any) error {
	input, err := json.Marshal(req)
	if err != nil {
		return err
	}
	cmd := exec.Command(c.HelperPath)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("crypto helper exited %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return fmt.Errorf("crypto helper failed: %w", err)
	}
	var resp struct {
		Ok     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return fmt.Errorf("crypto helper returned invalid JSON: %w", err)
	}
	if !resp.Ok {
		return fmt.Errorf("crypto helper error: %s", resp.Error)
	}
	if target != nil {
		return json.Unmarshal(resp.Result, target)
	}
	return nil
}

func (c *HelperCrypto) HybridSuiteId() (string, error) {
	var result string
	err := c.call(map[string]any{"op": "hybrid_suite_id"}, &result)
	return result, err
}

func (c *HelperCrypto) GenerateKeypair(password string) (map[string]string, error) {
	var result map[string]string
	err := c.call(map[string]any{"op": "generate_keypair", "password": password}, &result)
	return result, err
}

// GenerateRegistrationMaterial returns everything registration needs, computed
// locally: keypair, recovery material, and the auth_hash the server accepts
// in place of the password.
func (c *HelperCrypto) GenerateRegistrationMaterial(password, email string) (map[string]string, error) {
	var result map[string]string
	err := c.call(map[string]any{"op": "generate_registration_material", "password": password, "email": email}, &result)
	return result, err
}

func (c *HelperCrypto) DecryptPrivateKey(encryptedPrivateKey, nonce, password string) (string, error) {
	var result struct {
		PrivateKey string `json:"private_key"`
	}
	err := c.call(map[string]any{
		"op":                    "decrypt_private_key",
		"encrypted_private_key": encryptedPrivateKey,
		"nonce":                 nonce,
		"password":              password,
	}, &result)
	return result.PrivateKey, err
}

func (c *HelperCrypto) DecapsulateProjectKey(encryptedProjectKey, privateKey string) (string, error) {
	var result struct {
		ProjectKey string `json:"project_key"`
	}
	err := c.call(map[string]any{
		"op":                    "decapsulate_project_key",
		"encrypted_project_key": encryptedProjectKey,
		"private_key":           privateKey,
	}, &result)
	return result.ProjectKey, err
}

func (c *HelperCrypto) EncryptValue(plaintext, key string) (map[string]string, error) {
	var result map[string]string
	err := c.call(map[string]any{"op": "encrypt_value", "plaintext": plaintext, "key": key}, &result)
	return result, err
}

func (c *HelperCrypto) DecryptValue(ciphertext, nonce, key string) (string, error) {
	var result struct {
		Plaintext string `json:"plaintext"`
	}
	err := c.call(map[string]any{
		"op":         "decrypt_value",
		"ciphertext": ciphertext,
		"nonce":      nonce,
		"key":        key,
	}, &result)
	return result.Plaintext, err
}

func (c *HelperCrypto) EncapsulateProjectKey(projectKey, recipientPublicKey string) (map[string]any, error) {
	var result map[string]any
	err := c.call(map[string]any{
		"op":                   "encapsulate_project_key",
		"project_key":          projectKey,
		"recipient_public_key": recipientPublicKey,
	}, &result)
	return result, err
}
