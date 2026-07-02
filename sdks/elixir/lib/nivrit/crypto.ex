defmodule Nivrit.Crypto do
  @moduledoc "Delegates cryptographic operations to the nivrit-crypto-helper binary."

  defstruct [:helper_path]

  def new(helper_path \\ nil) do
    %__MODULE__{helper_path: helper_path || find_helper()}
  end

  def hybrid_suite_id(%__MODULE__{helper_path: path}), do: call(path, %{"op" => "hybrid_suite_id"})

  def generate_keypair(%__MODULE__{helper_path: path}, password) do
    call(path, %{"op" => "generate_keypair", "password" => password})
  end

  def decrypt_private_key(%__MODULE__{helper_path: path}, encrypted_private_key, nonce, password) do
    call(path, %{
      "op" => "decrypt_private_key",
      "encrypted_private_key" => encrypted_private_key,
      "nonce" => nonce,
      "password" => password
    })["private_key"]
  end

  def decapsulate_project_key(%__MODULE__{helper_path: path}, encrypted_project_key, private_key) do
    call(path, %{
      "op" => "decapsulate_project_key",
      "encrypted_project_key" => encrypted_project_key,
      "private_key" => private_key
    })["project_key"]
  end

  def encrypt_value(%__MODULE__{helper_path: path}, plaintext, key) do
    call(path, %{"op" => "encrypt_value", "plaintext" => plaintext, "key" => key})
  end

  def decrypt_value(%__MODULE__{helper_path: path}, ciphertext, nonce, key) do
    call(path, %{"op" => "decrypt_value", "ciphertext" => ciphertext, "nonce" => nonce, "key" => key})[
      "plaintext"
    ]
  end

  def encapsulate_project_key(%__MODULE__{helper_path: path}, project_key, recipient_public_key) do
    call(path, %{
      "op" => "encapsulate_project_key",
      "project_key" => project_key,
      "recipient_public_key" => recipient_public_key
    })
  end

  defp find_helper do
    case System.get_env("NIVRIT_CRYPTO_HELPER") do
      nil ->
        bundled = bundled_helper()

        if bundled && File.exists?(bundled) do
          bundled
        else
          # Dev fallback: __DIR__ is sdks/elixir/lib/nivrit, repo root four levels up.
          Path.join([__DIR__, "..", "..", "..", "..", "target", "release", "nivrit-crypto-helper"])
          |> Path.expand()
        end

      path ->
        path
    end
  end

  # Helper bundled in priv/native/<os>_<arch>/ by build-priv.sh and shipped in
  # the Hex package. nil if the app isn't built as a release (no priv dir).
  defp bundled_helper do
    case :code.priv_dir(:nivrit) do
      {:error, _} ->
        nil

      dir ->
        {os, arch} = target()
        exe = if os == "windows", do: "nivrit-crypto-helper.exe", else: "nivrit-crypto-helper"
        Path.join([to_string(dir), "native", "#{os}_#{arch}", exe])
    end
  end

  defp target do
    os =
      case :os.type() do
        {:win32, _} -> "windows"
        {:unix, :darwin} -> "darwin"
        _ -> "linux"
      end

    arch_str = to_string(:erlang.system_info(:system_architecture))
    arch = if String.contains?(arch_str, ["aarch64", "arm64"]), do: "arm64", else: "x86_64"
    {os, arch}
  end

  defp call(path, req) do
    out = run_helper(path, Jason.encode!(req))
    resp = Jason.decode!(out)

    unless resp["ok"] do
      raise "crypto helper error: #{resp["error"]}"
    end

    resp["result"]
  end

  # System.cmd/3 has no :stdin option (the previous code silently dropped the
  # request, so the helper read empty stdin and every call failed). Feed the
  # request via a temp file and shell redirection instead. The helper path and
  # temp-file path are passed as positional args ($0/$1), so request data is
  # never interpolated into the shell command (no injection) nor placed in argv
  # (no leak via the process list).
  #
  # ponytail: the request transits a 0600 temp file on disk for the duration of
  # the call. If on-disk exposure of secret material is unacceptable, switch to a
  # Port-based stdin pipe (needs the helper to read length-prefixed input so it
  # doesn't block waiting for EOF).
  defp run_helper(path, input) do
    tmp = Path.join(System.tmp_dir!(), "nivrit-crypto-#{System.unique_integer([:positive])}.json")
    File.write!(tmp, input)
    File.chmod!(tmp, 0o600)

    try do
      case System.cmd("sh", ["-c", ~s|exec "$0" < "$1"|, path, tmp]) do
        {out, 0} -> out
        {out, code} -> raise "crypto helper exited #{code}: #{out}"
      end
    after
      File.rm(tmp)
    end
  end
end
