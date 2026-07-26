defmodule Nivrit.Client do
  @moduledoc "HTTP client for the Nivrit API."

  defstruct [:base_url, :token]

  def new(base_url, token) do
    %__MODULE__{base_url: String.trim_trailing(base_url, "/"), token: token}
  end

  def request(%__MODULE__{} = client, method, path, body \\ nil) do
    url = client.base_url <> path

    headers = [
      {~c"Authorization", ~c"Bearer #{client.token}"},
      {~c"Content-Type", ~c"application/json"}
    ]

    json = if body, do: Jason.encode!(body), else: ""
    method_atom = String.to_atom(String.downcase(to_string(method)))
    req = {url, headers, ~c"application/json", json}
    {:ok, {{_, status, _}, _resp_headers, resp_body}} = :httpc.request(method_atom, req, [], [])
    body_str = List.to_string(resp_body)

    unless status >= 200 and status < 300 do
      raise "Nivrit API error #{status}: #{body_str}"
    end

    if body_str == "", do: nil, else: Jason.decode!(body_str)
  end

  def get_me(client), do: request(client, :get, "/users/me")
  def list_orgs(client), do: request(client, :get, "/users/me/orgs")
  def list_my_projects(client), do: request(client, :get, "/users/me/projects")

  def list_org_projects(client, org_id),
    do: request(client, :get, "/orgs/#{URI.encode_www_form(org_id)}/projects")

  def list_environments(client, project_id),
    do: request(client, :get, "/projects/#{URI.encode_www_form(project_id)}/environments")

  def list_secrets(client, project_id, environment_id) do
    request(
      client,
      :get,
      "/projects/#{URI.encode_www_form(project_id)}/secrets?environment_id=#{URI.encode_www_form(environment_id)}"
    )
  end

  def get_secret(client, project_id, environment_id, key) do
    request(
      client,
      :get,
      "/projects/#{URI.encode_www_form(project_id)}/secrets/#{URI.encode_www_form(key)}?environment_id=#{URI.encode_www_form(environment_id)}"
    )
  end

  def list_secret_versions(client, project_id, environment_id, key) do
    request(
      client,
      :get,
      "/projects/#{URI.encode_www_form(project_id)}/secrets/#{URI.encode_www_form(key)}/versions?environment_id=#{URI.encode_www_form(environment_id)}"
    )
  end

  def restore_secret(client, project_id, environment_id, key, version) do
    request(
      client,
      :post,
      "/projects/#{URI.encode_www_form(project_id)}/secrets/#{URI.encode_www_form(key)}/restore",
      %{
        "environment_id" => environment_id,
        "version" => version
      }
    )
  end

  def list_folders(client, project_id, environment_id) do
    request(
      client,
      :get,
      "/projects/#{URI.encode_www_form(project_id)}/folders?environment_id=#{URI.encode_www_form(environment_id)}"
    )
  end

  def create_folder(client, project_id, environment_id, name, path) do
    request(client, :post, "/projects/#{URI.encode_www_form(project_id)}/folders", %{
      "environment_id" => environment_id,
      "name" => name,
      "path" => path
    })
  end

  def delete_folder(client, project_id, folder_id) do
    request(
      client,
      :delete,
      "/projects/#{URI.encode_www_form(project_id)}/folders/#{URI.encode_www_form(folder_id)}"
    )
  end

  def list_imports(client, project_id, environment_id) do
    request(
      client,
      :get,
      "/projects/#{URI.encode_www_form(project_id)}/imports?environment_id=#{URI.encode_www_form(environment_id)}"
    )
  end

  def create_import(client, project_id, environment_id, source_environment_id, position \\ 0) do
    request(client, :post, "/projects/#{URI.encode_www_form(project_id)}/imports", %{
      "environment_id" => environment_id,
      "source_environment_id" => source_environment_id,
      "position" => position
    })
  end

  def delete_import(client, project_id, import_id) do
    request(
      client,
      :delete,
      "/projects/#{URI.encode_www_form(project_id)}/imports/#{URI.encode_www_form(import_id)}"
    )
  end

  def list_tags(client, project_id) do
    request(client, :get, "/projects/#{URI.encode_www_form(project_id)}/tags")
  end

  def create_tag(client, project_id, name, color \\ "#888888") do
    request(client, :post, "/projects/#{URI.encode_www_form(project_id)}/tags", %{
      "name" => name,
      "color" => color
    })
  end

  def delete_tag(client, project_id, tag_id) do
    request(
      client,
      :delete,
      "/projects/#{URI.encode_www_form(project_id)}/tags/#{URI.encode_www_form(tag_id)}"
    )
  end

  def list_secret_tags(client, project_id, environment_id, key) do
    request(
      client,
      :get,
      "/projects/#{URI.encode_www_form(project_id)}/secrets/#{URI.encode_www_form(key)}/tags?environment_id=#{URI.encode_www_form(environment_id)}"
    )
  end

  def tag_secret(client, project_id, environment_id, key, tag_id) do
    request(
      client,
      :post,
      "/projects/#{URI.encode_www_form(project_id)}/secrets/#{URI.encode_www_form(key)}/tags",
      %{
        "environment_id" => environment_id,
        "tag_id" => tag_id
      }
    )
  end

  def untag_secret(client, project_id, environment_id, key, tag_id) do
    request(
      client,
      :delete,
      "/projects/#{URI.encode_www_form(project_id)}/secrets/#{URI.encode_www_form(key)}/tags/#{URI.encode_www_form(tag_id)}?environment_id=#{URI.encode_www_form(environment_id)}"
    )
  end

  def create_org(client, body), do: request(client, :post, "/orgs", body)
  def create_project(client, body), do: request(client, :post, "/projects", body)

  def create_environment(client, project_id, body),
    do: request(client, :post, "/projects/#{URI.encode_www_form(project_id)}/environments", body)

  def create_secret(client, project_id, body),
    do: request(client, :post, "/projects/#{URI.encode_www_form(project_id)}/secrets", body)

  def create_pat(client, body), do: request(client, :post, "/auth/pat", body)
end
