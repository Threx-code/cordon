# Cordon benchmark

Measured inside Docker by `bench/run.py`. Losses are listed, not hidden.

## Malware blocked (higher is better)

| tool | inputs | blocked | passed | no answer | rate |
|---|---|---|---|---|---|
| cordon | 995 | 949 | 46 | 0 | 95.4% |
| guarddog | 995 | 835 | 160 | 0 | 83.9% |

## Benign packages blocked (lower is better)

| tool | inputs | blocked | passed | no answer | rate |
|---|---|---|---|---|---|
| cordon | 2001 | 32 | 1968 | 1 | 1.6% |
| guarddog | 2001 | 335 | 1658 | 8 | 16.8% |

## Agent and MCP attack-shape suite

Score (cases handled correctly): {'cordon': '17/17', 'trivy': '3/17', 'guarddog': '3/17'}

| case | kind | cordon | trivy | guarddog |
|---|---|---|---|---|
| agent-auto-approve | malicious | yes | **no** | **no** |
| agent-ci-comment-and-control | malicious | yes | **no** | **no** |
| agent-copilot-hidden | malicious | yes | **no** | **no** |
| agent-hook-fetch-exec | malicious | yes | **no** | **no** |
| agent-rules-hidden-text | malicious | yes | **no** | **no** |
| agent-rules-injection | malicious | yes | **no** | **no** |
| agent-skill-fetch-exec | malicious | yes | **no** | **no** |
| editor-devcontainer-removed | malicious | yes | **no** | **no** |
| editor-extension-removed | malicious | yes | **no** | **no** |
| mcp-server-poisoned-local | malicious | yes | **no** | **no** |
| mcp-shell-launch | malicious | yes | **no** | **no** |
| mcp-unpinned-remote | malicious | yes | **no** | **no** |
| model-pickle-exec | malicious | yes | **no** | **no** |
| slopsquat-hallucinated | malicious | yes | **no** | **no** |
| agents | benign | yes | yes | yes |
| agents-lookalike | benign | yes | yes | yes |
| formats | benign | yes | yes | yes |

Snyk agent-scan is not run: it inspects an MCP server by starting it, which runs the package under test, and it sends tool descriptions to Snyk's API.

## CVE agreement with OSV-Scanner and Trivy -- Cordon database: bundled (high/critical subset)

Mean agreement: 0.1577

| lockfile | cordon | osv-scanner | trivy | agreement |
|---|---|---|---|---|
| BurntSushi__ripgrep__Cargo | 0 | 0 | 0 | - |
| Kong__insomnia__package-lock | 62 | 149 | 136 | 0.4228 |
| alacritty__alacritty__Cargo | 0 | 4 | 1 | 0.0 |
| astral-sh__ruff__Cargo | 0 | 4 | 1 | 0.0 |
| astral-sh__uv__Cargo | 0 | 7 | 0 | 0.0 |
| babel__babel__yarn | 19 | 53 | 48 | 0.4151 |
| caddyserver__caddy__go | 0 | 1 | 1 | 0.0 |
| calcom__cal.com__yarn | 126 | 389 | 387 | 0.3265 |
| cli__cli__go | 0 | 1 | 1 | 0.0 |
| denoland__deno__Cargo | 1 | 19 | 3 | 0.0526 |
| discourse__discourse__Gemfile | 0 | 0 | 0 | - |
| etcd-io__etcd__go | 0 | 1 | 1 | 0.0 |
| excalidraw__excalidraw__yarn | 102 | 245 | 246 | 0.4122 |
| facebook__react__yarn | 165 | 324 | 324 | 0.5 |
| forem__forem__Gemfile | 19 | 36 | 39 | 0.4615 |
| gohugoio__hugo__go | 0 | 1 | 1 | 0.0 |
| grafana__grafana__yarn | 5 | 46 | 45 | 0.0435 |
| hashicorp__terraform__go | 0 | 1 | 1 | 0.0 |
| helix-editor__helix__Cargo | 0 | 7 | 0 | 0.0 |
| hoppscotch__hoppscotch__pnpm-lock | 38 | 125 | 74 | 0.272 |
| magento__magento2__composer | 19 | 46 | 42 | 0.413 |
| mastodon__mastodon__Gemfile | 1 | 0 | 0 | - |
| mastodon__mastodon__yarn | 2 | 1 | 1 | 0.0 |
| matomo-org__matomo__composer | 0 | 0 | 0 | - |
| microsoft__TypeScript__package-lock | 0 | 3 | 3 | 0.0 |
| microsoft__vscode__package-lock | 5 | 38 | 19 | 0.1053 |
| minio__minio__go | 37 | 79 | 78 | 0.2357 |
| monicahq__monica__composer | 19 | 57 | 57 | 0.3333 |
| mui__material-ui__pnpm-lock | 14 | 81 | 20 | 0.1728 |
| n8n-io__n8n__pnpm-lock | 38 | 141 | 99 | 0.2553 |
| netbox-community__netbox__requirements | 0 | 1 | 0 | 0.0 |
| paperless-ngx__paperless-ngx__uv | 3 | 24 | 18 | 0.0417 |
| prettier__prettier__yarn | 0 | 0 | 0 | - |
| prometheus__prometheus__go | 1 | 4 | 1 | 0.2 |
| pydantic__pydantic__uv | 0 | 4 | 0 | 0.0 |
| pypa__pipenv__Pipfile | 0 | 5 | 0 | 0.0 |
| python-poetry__poetry__poetry | 0 | 7 | 3 | 0.0 |
| rails__rails__Gemfile | 20 | 72 | 79 | 0.2405 |
| rust-lang__rust__Cargo | 0 | 6 | 1 | 0.0 |
| sharkdp__bat__Cargo | 0 | 4 | 0 | 0.0 |
| sharkdp__fd__Cargo | 0 | 2 | 0 | 0.0 |
| strapi__strapi__yarn | 37 | 136 | 131 | 0.2574 |
| supabase__supabase__pnpm-lock | 10 | 30 | 26 | 0.2667 |
| sveltejs__svelte__pnpm-lock | 26 | 43 | 0 | 0.6047 |
| traefik__traefik__go | 1 | 2 | 2 | 0.25 |
| vitejs__vite__pnpm-lock | 11 | 44 | 4 | 0.2955 |
| vuejs__core__pnpm-lock | 15 | 47 | 4 | 0.3617 |
| webpack__webpack__yarn | 1 | 9 | 9 | 0.0 |
| zulip__zulip__uv | 0 | 8 | 0 | 0.0 |

## CVE agreement with OSV-Scanner and Trivy -- Cordon database: full (advisories sync)

Mean agreement: 0.873

| lockfile | cordon | osv-scanner | trivy | agreement |
|---|---|---|---|---|
| BurntSushi__ripgrep__Cargo | 0 | 0 | 0 | - |
| Kong__insomnia__package-lock | 149 | 149 | 136 | 1.0 |
| alacritty__alacritty__Cargo | 7 | 4 | 1 | 1.0 |
| astral-sh__ruff__Cargo | 6 | 4 | 1 | 1.0 |
| astral-sh__uv__Cargo | 10 | 7 | 0 | 1.0 |
| babel__babel__yarn | 46 | 53 | 48 | 0.9057 |
| caddyserver__caddy__go | 2 | 1 | 1 | 0.5 |
| calcom__cal.com__yarn | 339 | 389 | 387 | 0.8638 |
| cli__cli__go | 1 | 1 | 1 | 0.5 |
| denoland__deno__Cargo | 24 | 19 | 3 | 1.0 |
| discourse__discourse__Gemfile | 0 | 0 | 0 | - |
| etcd-io__etcd__go | 2 | 1 | 1 | 0.5 |
| excalidraw__excalidraw__yarn | 223 | 245 | 246 | 0.902 |
| facebook__react__yarn | 315 | 324 | 324 | 0.9599 |
| forem__forem__Gemfile | 39 | 36 | 39 | 0.9231 |
| gohugoio__hugo__go | 1 | 1 | 1 | 0.5 |
| grafana__grafana__yarn | 56 | 46 | 45 | 0.913 |
| hashicorp__terraform__go | 8 | 1 | 1 | 0.5 |
| helix-editor__helix__Cargo | 7 | 7 | 0 | 1.0 |
| hoppscotch__hoppscotch__pnpm-lock | 140 | 125 | 74 | 1.0 |
| magento__magento2__composer | 46 | 46 | 42 | 1.0 |
| mastodon__mastodon__Gemfile | 3 | 0 | 0 | - |
| mastodon__mastodon__yarn | 12 | 1 | 1 | 1.0 |
| matomo-org__matomo__composer | 0 | 0 | 0 | - |
| microsoft__TypeScript__package-lock | 3 | 3 | 3 | 1.0 |
| microsoft__vscode__package-lock | 49 | 38 | 19 | 1.0 |
| minio__minio__go | 102 | 79 | 78 | 0.5032 |
| monicahq__monica__composer | 57 | 57 | 57 | 1.0 |
| mui__material-ui__pnpm-lock | 90 | 81 | 20 | 1.0 |
| n8n-io__n8n__pnpm-lock | 155 | 141 | 99 | 1.0 |
| netbox-community__netbox__requirements | 0 | 1 | 0 | 0.0 |
| paperless-ngx__paperless-ngx__uv | 50 | 24 | 18 | 1.0 |
| prettier__prettier__yarn | 0 | 0 | 0 | - |
| prometheus__prometheus__go | 4 | 4 | 1 | 0.8 |
| pydantic__pydantic__uv | 4 | 4 | 0 | 1.0 |
| pypa__pipenv__Pipfile | 5 | 5 | 0 | 1.0 |
| python-poetry__poetry__poetry | 7 | 7 | 3 | 1.0 |
| rails__rails__Gemfile | 72 | 72 | 79 | 0.9114 |
| rust-lang__rust__Cargo | 10 | 6 | 1 | 1.0 |
| sharkdp__bat__Cargo | 4 | 4 | 0 | 1.0 |
| sharkdp__fd__Cargo | 2 | 2 | 0 | 1.0 |
| strapi__strapi__yarn | 131 | 136 | 131 | 0.8529 |
| supabase__supabase__pnpm-lock | 46 | 30 | 26 | 1.0 |
| sveltejs__svelte__pnpm-lock | 44 | 43 | 0 | 1.0 |
| traefik__traefik__go | 2 | 2 | 2 | 0.5 |
| vitejs__vite__pnpm-lock | 43 | 44 | 4 | 1.0 |
| vuejs__core__pnpm-lock | 45 | 47 | 4 | 1.0 |
| webpack__webpack__yarn | 20 | 9 | 9 | 1.0 |
| zulip__zulip__uv | 7 | 8 | 0 | 0.875 |

