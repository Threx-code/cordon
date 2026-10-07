#!/bin/sh
# Regenerates the real-world Hex conformance cases.
#
#   real-umbrella   an Elixir umbrella resolved by `mix deps.get`: two apps, an in-umbrella
#                   dependency, dev- and test-only dependencies, an optional dependency, a git
#                   dependency, an override, `runtime: false` and an Elixir requirement.
#                   `mix deps` is the authoritative inventory.
#   real-rebar      an Erlang project resolved by rebar3: Hex and git dependencies, a test
#                   profile, a minimum OTP and pre/post hooks. `rebar3 tree` is authoritative.
#
# Dependencies are fetched, never compiled. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" elixir:1.17 sh /conformance/generate/hex.sh
set -eu
CASES=/conformance/cases/hex
export MIX_ENV=dev HEX_HTTP_TIMEOUT=120
mix local.hex --force >/dev/null && mix local.rebar --force >/dev/null

# --- Elixir umbrella -------------------------------------------------------------------------
rm -rf /tmp/u && mkdir -p /tmp/u/apps/core/lib /tmp/u/apps/web/lib /tmp/u/config && cd /tmp/u
cat > mix.exs <<'EOF'
defmodule Conformance.Umbrella.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.1.0",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Dependencies listed here are available to the umbrella root only.
  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
EOF
cat > config/config.exs <<'EOF'
import Config
EOF
cat > apps/core/mix.exs <<'EOF'
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
EOF
cat > apps/web/mix.exs <<'EOF'
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
EOF
mix deps.get >/dev/null
mix deps > /tmp/mix-deps.txt 2>&1 || true

# --- Erlang / rebar3 -------------------------------------------------------------------------
rm -rf /tmp/e && mkdir -p /tmp/e/src && cd /tmp/e
cat > rebar.config <<'EOF'
{minimum_otp_vsn, "25"}.

{deps, [
    {cowboy, "2.12.0"},
    jsx,
    {recon, {git, "https://github.com/ferd/recon.git", {tag, "2.5.6"}}}
]}.

{profiles, [
    {test, [{deps, [meck]}]}
]}.

{pre_hooks, [{compile, "echo generating"}]}.
{post_hooks, [{compile, "echo compiled"}]}.
EOF
cat > src/conformance.app.src <<'EOF'
{application, conformance, [{vsn, "0.1.0"}, {applications, [kernel, stdlib, cowboy, jsx]}]}.
EOF
rebar3 get-deps >/dev/null
rebar3 tree > /tmp/rebar-tree.txt 2>&1

# --- Copy the cases and the authoritative inventories ---------------------------------------
for c in real-umbrella real-rebar; do
  if [ -d "$CASES/$c" ]; then find "$CASES/$c" -mindepth 1 ! -name expect.yaml -exec rm -rf {} + 2>/dev/null || true; fi
  mkdir -p "$CASES/$c"
done
cd /tmp/u && mkdir -p "$CASES/real-umbrella/apps/core" "$CASES/real-umbrella/apps/web" "$CASES/real-umbrella/config"
cp mix.exs mix.lock "$CASES/real-umbrella/" && cp config/config.exs "$CASES/real-umbrella/config/"
cp apps/core/mix.exs "$CASES/real-umbrella/apps/core/" && cp apps/web/mix.exs "$CASES/real-umbrella/apps/web/"
cd /tmp/e && cp rebar.config rebar.lock "$CASES/real-rebar/"

json() {  # tool, optional extra members; one "name@version" per line on stdin
  printf '{\n "tool": "%s",\n "packages": [\n' "$1"
  sort -u | sed 's/.*/  "&"/' | sed '$!s/$/,/'
  printf ' ]%s\n}\n' "${2:-}"
}
MIX_IGNORE=',
 "ignore": {
  "mox": "test-only: locked, but `mix deps` lists only the current (dev) environment",
  "nimble_ownership": "required only by mox, so test-only as well",
  "nimble_options": "a git dependency: `mix deps` prints its abbreviated commit, the record the full one"
 }'
# `mix deps`: "* jason (Hex package) (mix)" then "  locked at 1.4.4 (jason) 79a3791". A git
# dependency is locked at its commit; an in-umbrella app is never locked.
# (The version is read first: `elixir` started on the receiving end of the pipe would read the
# pipe as its standard input and swallow the list.)
MIX_VERSION=$(elixir -e 'IO.write(System.version())' </dev/null)
awk '/^\* /{n=$2} /^  locked at /{if(n){print n"@"$3; n=""}}' /tmp/mix-deps.txt \
  | json "mix deps (Mix $MIX_VERSION)" "$MIX_IGNORE" > "$CASES/real-umbrella/authoritative.json"
# `rebar3 tree`: "├─ cowboy─2.12.0 (hex package)"
sed -n 's/.*[─] \([a-z_0-9]*\)─\([^ ]*\) (\(hex package\|git repo\)).*/\1@\2/p' /tmp/rebar-tree.txt \
  | json "rebar3 tree" > "$CASES/real-rebar/authoritative.json"
cat "$CASES/real-umbrella/authoritative.json" "$CASES/real-rebar/authoritative.json"
head -3 /tmp/u/mix.lock
head -8 /tmp/e/rebar.lock
echo done
