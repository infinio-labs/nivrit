package nivrit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// NivritSession holds authentication state and decrypted keys.
type NivritSession struct {
	BaseURL     string
	Client      *NivritClient
	Crypto      *HelperCrypto
	User        map[string]any
	PrivateKey  string
	projectKeys map[string]string
}

func NewSession(baseURL, token string, crypto *HelperCrypto) *NivritSession {
	return &NivritSession{
		BaseURL:     baseURL,
		Client:      NewClient(baseURL, token),
		Crypto:      crypto,
		projectKeys: make(map[string]string),
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

func (s *NivritSession) GetProjectKey(membership map[string]any) (string, error) {
	if membership == nil {
		return "", fmt.Errorf("no membership for project")
	}
	pid := membership["project_id"].(string)
	if cached, ok := s.projectKeys[pid]; ok {
		return cached, nil
	}
	key, err := s.Crypto.DecapsulateProjectKey(
		membership["encrypted_project_key"].(string),
		s.PrivateKey,
	)
	if err != nil {
		return "", err
	}
	s.projectKeys[pid] = key
	return key, nil
}

func (s *NivritSession) ListSecrets(projectID, environmentID string) ([]map[string]any, error) {
	secretsRaw, err := s.Client.ListSecrets(projectID, environmentID)
	if err != nil {
		return nil, err
	}
	memberships, err := s.Client.ListMyProjects()
	if err != nil {
		return nil, err
	}
	var membership map[string]any
	for _, m := range memberships {
		mm := m.(map[string]any)
		if mm["project_id"].(string) == projectID {
			membership = mm
			break
		}
	}
	projectKey, err := s.GetProjectKey(membership)
	if err != nil {
		return nil, err
	}
	var result []map[string]any
	for _, sec := range secretsRaw {
		sm := sec.(map[string]any)
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
	memberships, err := s.Client.ListMyProjects()
	if err != nil {
		return nil, err
	}
	var membership map[string]any
	for _, m := range memberships {
		mm := m.(map[string]any)
		if mm["project_id"].(string) == projectID {
			membership = mm
			break
		}
	}
	projectKey, err := s.GetProjectKey(membership)
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

// EncodeEncapsulatedProjectKey serializes the helper's encapsulation output for the API.
func EncodeEncapsulatedProjectKey(enc map[string]any) (string, error) {
	data, err := json.Marshal(enc)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
