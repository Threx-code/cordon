defmodule Demo.MixProject do
  use Mix.Project

  @version "0.3.0"
  @phoenix_version "~> 1.7.14"
  @ecto "~> 3.11"
  @ecto "~> 3.12"

  def project do
    [
      app: :demo,
      version: @version,
      elixir: "~> 1.15",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:phoenix, @phoenix_version},
      {:ecto_sql, @ecto},
      {:jason, "~> 1.4"}
    ]
  end
end
