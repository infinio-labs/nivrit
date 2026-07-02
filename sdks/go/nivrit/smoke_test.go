package nivrit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

func apiRequest(method, path string, body any, token string) (any, error) {
	url := os.Getenv("NIVRIT_API_URL")
	if url == "" {
		url = "http://localhost:4000"
	}
	var bodyReader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error %d: %v", resp.StatusCode, result)
	}
	return result, nil
}

func TestSmoke(t *testing.T) {
	apiURL := os.Getenv("NIVRIT_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:4000"
	}
	email := fmt.Sprintf("sdk-go-%d@example.com", time.Now().UnixMilli())
	password := "Correct-Horse-Battery-Staple!"

	crypto := NewHelperCrypto("")
	keypair, err := crypto.GenerateKeypair(password)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	reg, err := apiRequest("POST", "/auth/register", map[string]any{
		"email":                   email,
		"password":                password,
		"name":                    "Go SDK Test",
		"public_key":              keypair["public_key"],
		"encrypted_private_key":  keypair["encrypted_private_key"],
		"private_key_nonce":      keypair["private_key_nonce"],
		"private_key_algorithm": keypair["private_key_algorithm"],
	}, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	regMap := reg.(map[string]any)
	user := regMap["user"].(map[string]any)
	t.Logf("registered %s", user["email"])

	patRaw, err := apiRequest("POST", "/auth/pat", map[string]any{"name": "go-sdk-test"}, regMap["token"].(string))
	if err != nil {
		t.Fatalf("create pat: %v", err)
	}
	pat := patRaw.(map[string]any)

	session := NewSession(apiURL, pat["token"].(string), crypto)
	if err := session.Authenticate(password); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	t.Logf("session user %s", session.User["email"])

	orgRaw, err := session.Client.CreateOrg(map[string]any{
		"name": "Go SDK Org",
		"slug": fmt.Sprintf("go-sdk-org-%d", time.Now().Unix()),
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	org := orgRaw
	t.Logf("created org %s", org["name"])

	projectKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	encapsulated, err := crypto.EncapsulateProjectKey(projectKey, session.User["public_key"].(string))
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	encryptedProjectKey, err := EncodeEncapsulatedProjectKey(encapsulated)
	if err != nil {
		t.Fatalf("encode encapsulated: %v", err)
	}
	projectRaw, err := session.Client.CreateProject(map[string]any{
		"org_id":                 org["id"],
		"name":                   "Go SDK Project",
		"slug":                   fmt.Sprintf("go-sdk-project-%d", time.Now().Unix()),
		"encrypted_project_key": encryptedProjectKey,
		"project_key_nonce":      base64.StdEncoding.EncodeToString(make([]byte, 12)),
		"project_key_algorithm": "hybrid_x25519_ml_kem_768_aes256gcm_v1",
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	project := projectRaw
	t.Logf("created project %s", project["name"])

	envRaw, err := session.Client.CreateEnvironment(project["id"].(string), map[string]any{
		"name": "Dev",
		"slug": "dev",
	})
	if err != nil {
		t.Fatalf("create environment: %v", err)
	}
	env := envRaw
	t.Logf("created environment %s", env["name"])

	encrypted, err := crypto.EncryptValue("hello-go-sdk", projectKey)
	if err != nil {
		t.Fatalf("encrypt value: %v", err)
	}
	_, err = session.Client.CreateSecret(project["id"].(string), map[string]any{
		"environment_id": env["id"],
		"key":            "GREETING",
		"encrypted_value": encrypted["ciphertext"],
		"nonce":          encrypted["nonce"],
		"algorithm":      "aes256gcm-v1",
	})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	t.Log("created secret")

	secrets, err := session.ListSecrets(project["id"].(string), env["id"].(string))
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0]["value"] != "hello-go-sdk" {
		t.Fatalf("unexpected value: %v", secrets[0]["value"])
	}
	t.Logf("decrypted secret: %s", secrets[0]["value"])

	if _, err := apiRequest("DELETE", fmt.Sprintf("/auth/pats/%s", pat["id"]), nil, regMap["token"].(string)); err != nil {
		t.Fatalf("revoke pat: %v", err)
	}
	t.Log("Go SDK smoke test passed")
}
