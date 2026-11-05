"""Names known to exist in the hex ecosystem, curated: each can only clear a false typosquat
accusation, never create one (see `intel/registries/real.py`)."""

from __future__ import annotations

from typing import Final

#: Written into this module, as the floor under whatever `data/` happens to hold.
#:
#: The shipped files are generated from the registries and are the bulk of the
#: allowlist. These are not redundant with them: an sdist built without the data
#: directory, a source checkout before the first refresh, and the two ecosystems no
#: registry ranks all fall back here, and falling back to nothing would mean
#: falling back to the forty-name list this module was written to replace.
#: Hex (Elixir and Erlang). Curated: hex.pm publishes download counts but
#: no ranked export `scripts/refresh/refresh_package_intel.py` can read, so this is the
#: allowlist until one exists.
NAMES: Final = frozenset(
    {
        "absinthe",
        "absinthe_plug",
        "amqp",
        "argon2_elixir",
        "axon",
        "bamboo",
        "bandit",
        "bcrypt_elixir",
        "benchee",
        "broadway",
        "bypass",
        "cachex",
        "castore",
        "certifi",
        "comeonin",
        "con_cache",
        "cowboy",
        "credo",
        "csv",
        "dataloader",
        "decimal",
        "dialyxir",
        "distillery",
        "earmark",
        "ecto",
        "ecto_sql",
        "elixir_uuid",
        "ex_doc",
        "ex_machina",
        "excoveralls",
        "exla",
        "explorer",
        "exq",
        "faker",
        "finch",
        "floki",
        "flow",
        "gen_stage",
        "gettext",
        "guardian",
        "hackney",
        "horde",
        "httpoison",
        "jason",
        "joken",
        "jose",
        "kino",
        "libcluster",
        "makeup",
        "makeup_elixir",
        "mime",
        "mint",
        "mongodb_driver",
        "mox",
        "myxql",
        "nimble_csv",
        "nimble_options",
        "nimble_parsec",
        "nimble_pool",
        "nx",
        "oban",
        "observer_cli",
        "pbkdf2_elixir",
        "phoenix",
        "phoenix_ecto",
        "phoenix_html",
        "phoenix_live_dashboard",
        "phoenix_live_view",
        "phoenix_pubsub",
        "plug",
        "plug_cowboy",
        "plug_crypto",
        "poison",
        "postgrex",
        "quantum",
        "ranch",
        "recon",
        "redix",
        "req",
        "scholar",
        "sobelow",
        "stream_data",
        "sweet_xml",
        "swoosh",
        "telemetry",
        "telemetry_metrics",
        "telemetry_poller",
        "tesla",
        "thousand_island",
        "timex",
        "tzdata",
        "uuid",
    }
)


__all__ = ["NAMES"]
