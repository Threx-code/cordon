defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [
      app: :demo,
      version: "0.1.0",
      docs: &docs/0,
      test_load_filters: [~r/.*_tests\.exs/, ~w(a b)a, ~S"""
      raw
      """],
      test_ignore_filters: [&String.starts_with?(&1, "test/fixtures/")],
      test_coverage: [ignore_modules: [Demo, ~r/Ignore/]],
      aliases: [setup: fn _ -> Mix.shell().info("do: end") end],
      deps: deps()
    ]
  end

  defp docs, do: []

  defp deps do
    [{:jason, "~> 1.4"}]
  end
end
