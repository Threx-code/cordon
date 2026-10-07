defmodule Edge.MixProject do
  use Mix.Project

  def project, do: [app: :edge, version: "0.2.0", elixir: ">= 1.14.0", deps: deps()]

  defp deps do
    [
      {:acme_billing, "~> 3.0", organization: "acme", repo: "hexpm:acme"},
      {:local_helpers, path: "../helpers"},
      {:nerves_runtime, "~> 0.13", targets: [:rpi4, :rpi5]},
      {:recon, "~> 2.5", only: :prod},
      # {:commented_out, "~> 1.0"},
      {:telemetry, "~> 1.3"}
    ]
  end
end
