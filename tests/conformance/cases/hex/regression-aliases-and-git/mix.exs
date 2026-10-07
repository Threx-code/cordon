defmodule Regression.MixProject do
  use Mix.Project

  def project do
    [app: :regression, version: "0.1.0", deps: deps()]
  end

  defp deps do
    [
      {:my_jason, "~> 1.2", hex: :jason},
      {:gettext, git: "https://github.com/elixir-gettext/gettext.git", ref: "0b6f6e3a2c8d1f5e4b7a9c0d2e1f3a4b5c6d7e8f"}
    ]
  end
end
