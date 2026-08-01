package nivrit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// NivritClient is a thin HTTP client for the Nivrit API.
type NivritClient struct {
	BaseURL string
	Token   string
	client  *http.Client
}

func NewClient(baseURL, token string) *NivritClient {
	return &NivritClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		client:  &http.Client{Timeout: 0},
	}
}

func (c *NivritClient) request(method, path string, body any) (any, error) {
	u := c.BaseURL + path
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, u, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Nivrit API error %d: %s", resp.StatusCode, string(respBody))
	}
	if len(respBody) == 0 {
		return nil, nil
	}
	var result any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *NivritClient) GetMe() (map[string]any, error) {
	r, err := c.request("GET", "/users/me", nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) ListOrgs() ([]any, error) {
	r, err := c.request("GET", "/users/me/orgs", nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) ListMyProjects() ([]any, error) {
	r, err := c.request("GET", "/users/me/projects", nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) ListOrgProjects(orgID string) ([]any, error) {
	r, err := c.request("GET", "/orgs/"+url.PathEscape(orgID)+"/projects", nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) ListEnvironments(projectID string) ([]any, error) {
	r, err := c.request("GET", "/projects/"+url.PathEscape(projectID)+"/environments", nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) ListSecrets(projectID, environmentID string) ([]any, error) {
	path := fmt.Sprintf("/projects/%s/secrets?environment_id=%s", url.PathEscape(projectID), url.QueryEscape(environmentID))
	r, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) GetSecret(projectID, environmentID, key string) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/secrets/%s?environment_id=%s", url.PathEscape(projectID), url.PathEscape(key), url.QueryEscape(environmentID))
	r, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) ListSecretVersions(projectID, environmentID, key string) ([]any, error) {
	path := fmt.Sprintf("/projects/%s/secrets/%s/versions?environment_id=%s", url.PathEscape(projectID), url.PathEscape(key), url.QueryEscape(environmentID))
	r, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) RestoreSecret(projectID, environmentID, key string, version int) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/secrets/%s/restore", url.PathEscape(projectID), url.PathEscape(key))
	r, err := c.request("POST", path, map[string]any{"environment_id": environmentID, "version": version})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) ListFolders(projectID, environmentID string) ([]any, error) {
	path := fmt.Sprintf("/projects/%s/folders?environment_id=%s", url.PathEscape(projectID), url.QueryEscape(environmentID))
	r, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) CreateFolder(projectID, environmentID, name, folderPath string) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/folders", url.PathEscape(projectID))
	r, err := c.request("POST", path, map[string]any{"environment_id": environmentID, "name": name, "path": folderPath})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) DeleteFolder(projectID, folderID string) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/folders/%s", url.PathEscape(projectID), url.PathEscape(folderID))
	r, err := c.request("DELETE", path, nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) ListImports(projectID, environmentID string) ([]any, error) {
	path := fmt.Sprintf("/projects/%s/imports?environment_id=%s", url.PathEscape(projectID), url.QueryEscape(environmentID))
	r, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) CreateImport(projectID, environmentID, sourceEnvironmentID string, position int) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/imports", url.PathEscape(projectID))
	r, err := c.request("POST", path, map[string]any{"environment_id": environmentID, "source_environment_id": sourceEnvironmentID, "position": position})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) DeleteImport(projectID, importID string) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/imports/%s", url.PathEscape(projectID), url.PathEscape(importID))
	r, err := c.request("DELETE", path, nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) ListTags(projectID string) ([]any, error) {
	r, err := c.request("GET", "/projects/"+url.PathEscape(projectID)+"/tags", nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) CreateTag(projectID, name, color string) (map[string]any, error) {
	r, err := c.request("POST", "/projects/"+url.PathEscape(projectID)+"/tags", map[string]any{"name": name, "color": color})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) DeleteTag(projectID, tagID string) (map[string]any, error) {
	r, err := c.request("DELETE", "/projects/"+url.PathEscape(projectID)+"/tags/"+url.PathEscape(tagID), nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) ListSecretTags(projectID, environmentID, key string) ([]any, error) {
	path := fmt.Sprintf("/projects/%s/secrets/%s/tags?environment_id=%s", url.PathEscape(projectID), url.PathEscape(key), url.QueryEscape(environmentID))
	r, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) TagSecret(projectID, environmentID, key, tagID string) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/secrets/%s/tags", url.PathEscape(projectID), url.PathEscape(key))
	r, err := c.request("POST", path, map[string]any{"environment_id": environmentID, "tag_id": tagID})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) UntagSecret(projectID, environmentID, key, tagID string) (map[string]any, error) {
	path := fmt.Sprintf("/projects/%s/secrets/%s/tags/%s?environment_id=%s", url.PathEscape(projectID), url.PathEscape(key), url.PathEscape(tagID), url.QueryEscape(environmentID))
	r, err := c.request("DELETE", path, nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) CreateOrg(body any) (map[string]any, error) {
	r, err := c.request("POST", "/orgs", body)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) CreateProject(body any) (map[string]any, error) {
	r, err := c.request("POST", "/projects", body)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) CreateEnvironment(projectID string, body any) (map[string]any, error) {
	r, err := c.request("POST", "/projects/"+url.PathEscape(projectID)+"/environments", body)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) CreateSecret(projectID string, body any) (map[string]any, error) {
	r, err := c.request("POST", "/projects/"+url.PathEscape(projectID)+"/secrets", body)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

func (c *NivritClient) CreatePAT(body any) (map[string]any, error) {
	r, err := c.request("POST", "/auth/pat", body)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// GetPublicKey looks up a user's public key by email, to encapsulate a
// project key to them (invite, or a rotation grant). Requires Member+ on
// projectID.
func (c *NivritClient) GetPublicKey(email, projectID string) (map[string]any, error) {
	path := fmt.Sprintf("/users/public-key?email=%s&project_id=%s", url.QueryEscape(email), url.QueryEscape(projectID))
	r, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// Versioned project keys (ADR 0008)

// ListMembers returns the current members of a project and the public key a
// rotation grant should be encapsulated to.
func (c *NivritClient) ListMembers(projectID string) ([]any, error) {
	r, err := c.request("GET", "/projects/"+url.PathEscape(projectID)+"/members", nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

func (c *NivritClient) InviteMember(projectID string, body any) (map[string]any, error) {
	r, err := c.request("POST", "/projects/"+url.PathEscape(projectID)+"/members", body)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// ListKeyVersions returns every project-key version the caller has been
// granted, oldest first -- what's needed to decrypt the project's full
// secret history, not just what's current.
func (c *NivritClient) ListKeyVersions(projectID string) ([]any, error) {
	r, err := c.request("GET", "/projects/"+url.PathEscape(projectID)+"/key-versions", nil)
	if err != nil {
		return nil, err
	}
	return r.([]any), nil
}

// RotateKey mints the next project-key version, granted to exactly the
// supplied roster. The server independently verifies the roster matches
// current membership.
func (c *NivritClient) RotateKey(projectID string, body any) (map[string]any, error) {
	r, err := c.request("POST", "/projects/"+url.PathEscape(projectID)+"/rotate-key", body)
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}
