defmodule Nivrit.MixProject do
  use Mix.Project

  def project do
    [
      app: :nivrit,
      version: "1.0.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      description: "Nivrit SDK — post-quantum, end-to-end-encrypted secrets manager.",
      package: package(),
      deps: deps()
    ]
  end

  defp package do
    [
      licenses: ["AGPL-3.0-only"],
      links: %{"GitHub" => "https://github.com/infinio-labs/nivrit"}
    ]
  end

  def application do
    [extra_applications: [:inets, :ssl, :crypto]]
  end

  defp deps do
    [
      {:jason, "== 1.4.5"}
    ]
  end
end
