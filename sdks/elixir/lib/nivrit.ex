defmodule Nivrit do
  @moduledoc "Nivrit secrets SDK for Elixir."

  defdelegate new_client(base_url, token), to: Nivrit.Client, as: :new
  defdelegate new_crypto(helper_path \\ nil), to: Nivrit.Crypto, as: :new
  defdelegate new_session(base_url, token, crypto), to: Nivrit.Session, as: :new
end
