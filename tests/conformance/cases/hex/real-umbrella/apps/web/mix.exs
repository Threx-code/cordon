defmodule Web.MixProject do
  use Mix.Project

  def project do
    [
      app: :web,
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
      {:core, in_umbrella: true},
      {:plug, "~> 1.16"},
      {:mime, "~> 2.0", override: true}
    ]
  end
end
