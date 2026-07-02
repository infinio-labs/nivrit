defmodule Nivrit.Session do
  @moduledoc "Authenticated session with cached decrypted project keys."

  defstruct [:client, :crypto, :user, :private_key, project_keys: %{}]

  def new(base_url, token, crypto) do
    %__MODULE__{client: Nivrit.Client.new(base_url, token), crypto: crypto}
  end

  def authenticate(%__MODULE__{} = session, password) do
    user = Nivrit.Client.get_me(session.client)

    private_key =
      Nivrit.Crypto.decrypt_private_key(
        session.crypto,
        user["encrypted_private_key"],
        user["private_key_nonce"],
        password
      )

    %{session | user: user, private_key: private_key}
  end

  def list_projects(%__MODULE__{} = session, org_id) do
    projects = Nivrit.Client.list_org_projects(session.client, org_id)
    memberships = Nivrit.Client.list_my_projects(session.client) |> Map.new(&{&1["project_id"], &1})
    Enum.map(projects, &Map.put(&1, "membership", memberships[&1["id"]]))
  end

  def get_project_key(%__MODULE__{} = session, membership) do
    pid = membership["project_id"]

    case session.project_keys[pid] do
      nil ->
        key =
          Nivrit.Crypto.decapsulate_project_key(
            session.crypto,
            membership["encrypted_project_key"],
            session.private_key
          )

        %{session | project_keys: Map.put(session.project_keys, pid, key)}
        key

      key ->
        key
    end
  end

  def list_secrets(%__MODULE__{} = session, project_id, environment_id) do
    secrets = Nivrit.Client.list_secrets(session.client, project_id, environment_id)
    membership = Enum.find(Nivrit.Client.list_my_projects(session.client), &(&1["project_id"] == project_id))
    project_key = get_project_key(session, membership)

    Enum.map(secrets, fn s ->
      value = Nivrit.Crypto.decrypt_value(session.crypto, s["encrypted_value"], s["nonce"], project_key)
      Map.put(s, "value", value)
    end)
  end
end
