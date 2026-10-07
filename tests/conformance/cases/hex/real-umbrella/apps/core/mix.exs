defmodule Core.MixProject do
  use Mix.Project

  def project do
    [
      app: :core,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.15",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:decimal, "~> 2.1", optional: true},
      {:telemetry, "~> 1.3"},
      {:nimble_options, github: "dashbitco/nimble_options", tag: "v1.1.1"},
      {:mox, "~> 1.2", only: :test}
    ]
  end
end
