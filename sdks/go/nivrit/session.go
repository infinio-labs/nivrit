package nivrit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// NivritSession holds authentication state and decrypted keys.
type NivritSession struct {
	BaseURL    string
	Client     *NivritClient
	Crypto     *HelperCrypto
	User       map[string]any
	PrivateKey string
	// project_id -> {version -> decapsulated key}. A project that's never
	// been rotated has exactly one entry (ADR 0008).
	projectKeys map[string]map[int]string
}

func NewSession(baseURL, token string, crypto *HelperCrypto) *NivritSession {
	return &NivritSession{
		BaseURL:     baseURL,
		Client:      NewClient(baseURL, token),
		Crypto:      crypto,
		projectKeys: make(map[string]map[int]string),
	}
}

func (s *NivritSession) Authenticate(password string) error {
	user, err := s.Client.GetMe()
	if err != nil {
		return err
	}
	s.User = user
	privateKey, err := s.Crypto.DecryptPrivateKey(
		user["encrypted_private_key"].(string),
		user["private_key_nonce"].(string),
		password,
	)
	if err != nil {
		return err
	}
	s.PrivateKey = privateKey
	return nil
}

func (s *NivritSession) ListProjects(orgID string) ([]map[string]any, error) {
	projectsRaw, err := s.Client.ListOrgProjects(orgID)
	if err != nil {
		return nil, err
	}
	membershipsRaw, err := s.Client.ListMyProjects()
	if err != nil {
		return nil, err
	}
	memberships := make(map[string]map[string]any)
	for _, m := range membershipsRaw {
		mm := m.(map[string]any)
		memberships[mm["project_id"].(string)] = mm
	}
	var result []map[string]any
	for _, p := range projectsRaw {
		pm := p.(map[string]any)
		pm["membership"] = memberships[pm["id"].(string)]
		result = append(result, pm)
	}
	return result, nil
}

// LoadProjectKeys fetches every project-key version this account has been
// granted, decapsulates and caches them, oldest first (ADR 0008). Idempotent
// per project per process -- call again after a rotation you triggered
// yourself (or one that granted you a new version) to pick it up without a
// fresh login.
func (s *NivritSession) LoadProjectKeys(projectID string) (map[int]string, error) {
	entries, err := s.Client.ListKeyVersions(projectID)
	if err != nil {
		return nil, err
	}
	versions := make(map[int]string)
	for _, e := range entries {
		entry := e.(map[string]any)
		encryptedProjectKey, _ := entry["encrypted_project_key"].(string)
		if encryptedProjectKey == "" {
			continue
		}
		key, err := s.Crypto.DecapsulateProjectKey(encryptedProjectKey, s.PrivateKey)
		if err != nil {
			return nil, err
		}
		version := int(entry["version"].(float64))
		versions[version] = key
	}
	s.projectKeys[projectID] = versions
	return versions, nil
}

// GetProjectKey returns the key for a specific project-key version, loading
// the cache first if needed.
func (s *NivritSession) GetProjectKey(projectID string, version int) (string, error) {
	versions, ok := s.projectKeys[projectID]
	if !ok {
		var err error
		versions, err = s.LoadProjectKeys(projectID)
		if err != nil {
			return "", err
		}
	}
	key, ok := versions[version]
	if !ok {
		return "", fmt.Errorf(
			"no cached key for project %s version %d; call LoadProjectKeys() again to pick up any versions granted since",
			projectID, version,
		)
	}
	return key, nil
}

// GetCurrentProjectKey returns the key for the current (highest) project-key
// version, loading the cache first if needed.
func (s *NivritSession) GetCurrentProjectKey(projectID string) (string, error) {
	version, err := s.CurrentProjectKeyVersion(projectID)
	if err != nil {
		return "", err
	}
	return s.GetProjectKey(projectID, version)
}

// CurrentProjectKeyVersion returns the version new secret writes should use
// -- for building a CreateSecret request's project_key_version field.
func (s *NivritSession) CurrentProjectKeyVersion(projectID string) (int, error) {
	versions, ok := s.projectKeys[projectID]
	if !ok {
		var err error
		versions, err = s.LoadProjectKeys(projectID)
		if err != nil {
			return 0, err
		}
	}
	if len(versions) == 0 {
		return 0, fmt.Errorf("no cached key versions for project %s", projectID)
	}
	max := 0
	for v := range versions {
		if v > max {
			max = v
		}
	}
	return max, nil
}

func (s *NivritSession) ListSecrets(projectID, environmentID string) ([]map[string]any, error) {
	secretsRaw, err := s.Client.ListSecrets(projectID, environmentID)
	if err != nil {
		return nil, err
	}
	var result []map[string]any
	for _, sec := range secretsRaw {
		sm := sec.(map[string]any)
		projectKey, err := s.GetProjectKey(projectID, secretProjectKeyVersion(sm))
		if err != nil {
			return nil, err
		}
		plaintext, err := s.Crypto.DecryptValue(
			sm["encrypted_value"].(string),
			sm["nonce"].(string),
			projectKey,
		)
		if err != nil {
			return nil, err
		}
		sm["value"] = plaintext
		result = append(result, sm)
	}
	return result, nil
}

func (s *NivritSession) GetSecret(projectID, environmentID, key string) (map[string]any, error) {
	secret, err := s.Client.GetSecret(projectID, environmentID, key)
	if err != nil {
		return nil, err
	}
	projectKey, err := s.GetProjectKey(projectID, secretProjectKeyVersion(secret))
	if err != nil {
		return nil, err
	}
	plaintext, err := s.Crypto.DecryptValue(
		secret["encrypted_value"].(string),
		secret["nonce"].(string),
		projectKey,
	)
	if err != nil {
		return nil, err
	}
	secret["value"] = plaintext
	return secret, nil
}

// secretProjectKeyVersion resolves the project-key version a secret was
// encrypted under. Absent or zero (a secret written before ADR 0008 added
// the field) defaults to version 1.
func secretProjectKeyVersion(secret map[string]any) int {
	raw, ok := secret["project_key_version"]
	if !ok || raw == nil {
		return 1
	}
	v := int(raw.(float64))
	if v == 0 {
		return 1
	}
	return v
}

// InviteMember invites a user to a project by email, encapsulating the
// project's current key version to their public key. Grants whichever
// version is current, not a hardcoded version 1, so an invite after a
// rotation doesn't hand out a superseded key (ADR 0008).
func (s *NivritSession) InviteMember(projectID, email, role string) error {
	projectKey, err := s.GetCurrentProjectKey(projectID)
	if err != nil {
		return err
	}
	recipientRaw, err := s.Client.GetPublicKey(email, projectID)
	if err != nil {
		return err
	}
	encapsulated, err := s.Crypto.EncapsulateProjectKey(projectKey, recipientRaw["public_key"].(string))
	if err != nil {
		return err
	}
	_, err = s.Client.InviteMember(projectID, map[string]any{
		"email":                 email,
		"role":                  role,
		"encrypted_project_key": encapsulated,
	})
	return err
}

// RotateProjectKey mints a new project-key version and grants it to exactly
// the project's current members (ADR 0008). No existing secret is touched. A
// removed member simply never receives this grant, so they're locked out of
// everything created from this point forward.
func (s *NivritSession) RotateProjectKey(projectID string) (version int, grantedTo int, err error) {
	// Proves we hold a valid key for this project before bothering to mint
	// the next version; the actual replacement key is generated fresh below.
	if _, err = s.GetCurrentProjectKey(projectID); err != nil {
		return 0, 0, err
	}

	membersRaw, err := s.Client.ListMembers(projectID)
	if err != nil {
		return 0, 0, err
	}

	newKeyBytes := make([]byte, 32)
	if _, err = rand.Read(newKeyBytes); err != nil {
		return 0, 0, err
	}
	newKey := base64.StdEncoding.EncodeToString(newKeyBytes)

	grants := make([]map[string]any, 0, len(membersRaw))
	for _, m := range membersRaw {
		member := m.(map[string]any)
		encapsulated, err := s.Crypto.EncapsulateProjectKey(newKey, member["public_key"].(string))
		if err != nil {
			return 0, 0, err
		}
		encoded, err := EncodeEncapsulatedProjectKey(encapsulated)
		if err != nil {
			return 0, 0, err
		}
		suite, _ := encapsulated["suite"].(string)
		grants = append(grants, map[string]any{
			"user_id":               member["user_id"],
			"encrypted_project_key": encoded,
			"project_key_nonce":     "",
			"project_key_algorithm": suite,
		})
	}

	result, err := s.Client.RotateKey(projectID, map[string]any{"grants": grants})
	if err != nil {
		return 0, 0, err
	}
	newVersion := int(result["version"].(float64))

	versions, ok := s.projectKeys[projectID]
	if !ok {
		versions = make(map[int]string)
	}
	versions[newVersion] = newKey
	s.projectKeys[projectID] = versions

	return newVersion, len(grants), nil
}

// EncodeEncapsulatedProjectKey serializes the helper's encapsulation output for the API.
func EncodeEncapsulatedProjectKey(enc map[string]any) (string, error) {
	data, err := json.Marshal(enc)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
