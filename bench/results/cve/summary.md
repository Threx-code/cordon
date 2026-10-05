# Cordon benchmark

Measured inside Docker by `bench/run.py`. Losses are listed, not hidden.

## CVE agreement with OSV-Scanner and Trivy -- Cordon database: full (advisories sync)

Mean agreement: 0.9841

| lockfile | cordon | osv-scanner | trivy | agreement |
|---|---|---|---|---|
| BurntSushi__ripgrep__Cargo | 0 | 0 | 0 | - |
| Kong__insomnia__package-lock | 149 | 149 | 137 | 1.0 |
| PostHog__posthog__pnpm-lock | 310 | 306 | 259 | 1.0 |
| RocketChat__Rocket.Chat__yarn | 108 | 86 | 84 | 0.9767 |
| alacritty__alacritty__Cargo | 6 | 4 | 1 | 1.0 |
| angular__angular__pnpm-lock | 68 | 71 | 20 | 1.0 |
| ansible__awx__requirements | 59 | 56 | 53 | 1.0 |
| apache__superset__base | 0 | error: Scanning dir /data/lockfiles/apache__superset__base
Starting filesystem walk for root: /
End status: 1 dirs visited, 2 i | 0 | - |
| appsmithorg__appsmith__yarn | 72 | 56 | 54 | 1.0 |
| argoproj__argo-cd__go | 7 | 6 | 3 | 1.0 |
| astral-sh__ruff__Cargo | 6 | 4 | 1 | 1.0 |
| astral-sh__uv__Cargo | 10 | 7 | 0 | 1.0 |
| babel__babel__yarn | 48 | 53 | 48 | 0.9434 |
| bitwarden__clients__package-lock | 241 | 235 | 17 | 1.0 |
| caddyserver__caddy__go | 35 | 1 | 1 | 1.0 |
| calcom__cal.com__yarn | 387 | 389 | 388 | 0.9974 |
| chatwoot__chatwoot__Gemfile | 46 | 3 | 4 | 1.0 |
| cli__cli__go | 1 | 1 | 1 | 1.0 |
| denoland__deno__Cargo | 24 | 19 | 3 | 1.0 |
| directus__directus__pnpm-lock | 52 | 38 | 37 | 1.0 |
| discourse__discourse__Gemfile | 78 | 0 | 0 | - |
| discourse__discourse__pnpm-lock | 19 | 19 | 10 | 1.0 |
| documenso__documenso__package-lock | 69 | 58 | 50 | 1.0 |
| etcd-io__etcd__go | 2 | 1 | 1 | 1.0 |
| excalidraw__excalidraw__yarn | 245 | 245 | 246 | 1.0 |
| facebook__react__yarn | 327 | 324 | 324 | 0.9969 |
| forem__forem__Gemfile | 78 | 36 | 39 | 1.0 |
| freeCodeCamp__freeCodeCamp__pnpm-lock | 280 | 279 | 230 | 1.0 |
| getsentry__sentry__pnpm-lock | 8 | 7 | 7 | 1.0 |
| gitlabhq__gitlabhq__Gemfile | 72 | 11 | 20 | 1.0 |
| go-gitea__gitea__go | 11 | 2 | 1 | 1.0 |
| goharbor__harbor__go | 36 | 18 | 15 | 1.0 |
| gohugoio__hugo__go | 1 | 1 | 1 | 1.0 |
| grafana__grafana__go | 17 | 6 | 3 | 1.0 |
| grafana__grafana__yarn | 58 | 46 | 46 | 1.0 |
| hashicorp__terraform__go | 8 | 1 | 1 | 1.0 |
| hashicorp__vault__go | 5 | 1 | 1 | 1.0 |
| helix-editor__helix__Cargo | 7 | 7 | 0 | 1.0 |
| home-assistant__core__requirements_all | 2 | error: {
  "results": [],
  "experimental_config": {
    "licenses": {
      "summary": false,
      "allowlist": null
    }
   | 0 | - |
| hoppscotch__hoppscotch__pnpm-lock | 138 | 125 | 74 | 1.0 |
| immich-app__immich__pnpm-lock | 98 | 98 | 75 | 1.0 |
| jellyfin__jellyfin-web__package-lock | 171 | 162 | 76 | 1.0 |
| jesseduffield__lazygit__go | 48 | 2 | 2 | 1.0 |
| jestjs__jest__yarn | 5 | 6 | 4 | 0.6667 |
| jitsi__jitsi-meet__package-lock | 117 | 118 | 76 | 1.0 |
| kubernetes__kubernetes__go | 4 | 3 | 1 | 1.0 |
| lapce__lapce__Cargo | 66 | 59 | 21 | 1.0 |
| magento__magento2__composer | 46 | 46 | 42 | 1.0 |
| mastodon__mastodon__Gemfile | 3 | 0 | 0 | - |
| mastodon__mastodon__yarn | 12 | 1 | 1 | 1.0 |
| matomo-org__matomo__composer | 0 | 0 | 0 | - |
| mattermost__mattermost__go | 11 | 2 | 1 | 1.0 |
| mattermost__mattermost__package-lock | 90 | 86 | 49 | 0.989 |
| medusajs__medusa__yarn | 114 | 116 | 116 | 1.0 |
| meilisearch__meilisearch__Cargo | 21 | 18 | 0 | 1.0 |
| microsoft__TypeScript__package-lock | 3 | 3 | 3 | 1.0 |
| microsoft__playwright__package-lock | 41 | 42 | 0 | 1.0 |
| microsoft__vscode__package-lock | 48 | 38 | 19 | 1.0 |
| minio__minio__go | 121 | 79 | 78 | 0.9875 |
| mitmproxy__mitmproxy__uv | 41 | 41 | 27 | 1.0 |
| monicahq__monica__composer | 57 | 57 | 57 | 1.0 |
| mui__material-ui__pnpm-lock | 90 | 81 | 20 | 1.0 |
| n8n-io__n8n__pnpm-lock | 155 | 141 | 100 | 1.0 |
| nestjs__nest__package-lock | 91 | 83 | 8 | 1.0 |
| netbox-community__netbox__requirements | 2 | 1 | 0 | 0.0 |
| nextcloud__server__composer | 0 | 0 | 0 | - |
| novuhq__novu__pnpm-lock | 76 | 56 | 38 | 1.0 |
| nushell__nushell__Cargo | 15 | 9 | 2 | 1.0 |
| nuxt__nuxt__pnpm-lock | 28 | 15 | 1 | 1.0 |
| ollama__ollama__go | 75 | 42 | 41 | 1.0 |
| openedx__edx-platform__base | 0 | error: Scanning dir /data/lockfiles/openedx__edx-platform__base
Starting filesystem walk for root: /
End status: 1 dirs visited | 0 | - |
| outline__outline__yarn | 48 | 34 | 34 | 1.0 |
| paperless-ngx__paperless-ngx__uv | 50 | 24 | 24 | 1.0 |
| payloadcms__payload__pnpm-lock | 145 | 142 | 70 | 1.0 |
| prettier__prettier__yarn | 0 | 0 | 0 | - |
| prisma__prisma__pnpm-lock | 158 | 156 | 78 | 1.0 |
| prometheus__prometheus__go | 4 | 4 | 1 | 1.0 |
| pydantic__pydantic__uv | 5 | 4 | 0 | 1.0 |
| pypa__pipenv__Pipfile | 5 | 5 | 0 | 1.0 |
| python-poetry__poetry-core__poetry | 7 | 7 | 0 | 1.0 |
| python-poetry__poetry__poetry | 7 | 7 | 5 | 1.0 |
| rails__rails__Gemfile | 139 | 72 | 79 | 1.0 |
| rclone__rclone__go | 35 | 1 | 1 | 1.0 |
| remix-run__remix__pnpm-lock | 75 | 71 | 21 | 1.0 |
| rust-lang__cargo__Cargo | 9 | 8 | 0 | 1.0 |
| rust-lang__rust__Cargo | 10 | 6 | 1 | 1.0 |
| saleor__saleor__uv | 14 | 11 | 5 | 1.0 |
| sharkdp__bat__Cargo | 4 | 4 | 0 | 1.0 |
| sharkdp__fd__Cargo | 2 | 2 | 0 | 1.0 |
| signalapp__Signal-Desktop__pnpm-lock | 107 | 105 | 11 | 1.0 |
| standardnotes__app__yarn | 473 | 472 | 475 | 1.0 |
| starship__starship__Cargo | 3 | 1 | 0 | 1.0 |
| strapi__strapi__yarn | 132 | 135 | 130 | 0.8667 |
| streamlit__streamlit__uv | 0 | 0 | 0 | - |
| supabase__supabase__pnpm-lock | 46 | 30 | 26 | 1.0 |
| sveltejs__svelte__pnpm-lock | 43 | 43 | 0 | 1.0 |
| syncthing__syncthing__go | 28 | 7 | 5 | 1.0 |
| tokio-rs__axum__Cargo | 4 | 2 | 2 | 1.0 |
| traefik__traefik__go | 35 | 2 | 2 | 1.0 |
| twentyhq__twenty__yarn | 149 | 114 | 103 | 1.0 |
| umami-software__umami__pnpm-lock | 23 | 23 | 10 | 1.0 |
| vercel__next.js__pnpm-lock | 637 | 634 | 114 | 1.0 |
| vitejs__vite__pnpm-lock | 43 | 44 | 4 | 1.0 |
| vuejs__core__pnpm-lock | 45 | 47 | 4 | 1.0 |
| wagtail__bakerydemo__base | 0 | error: Scanning dir /data/lockfiles/wagtail__bakerydemo__base
Starting filesystem walk for root: /
End status: 1 dirs visited,  | 0 | - |
| webpack__webpack__yarn | 20 | 9 | 9 | 1.0 |
| wekan__wekan__package-lock | 2 | 2 | 1 | 1.0 |
| withastro__astro__pnpm-lock | 146 | 145 | 44 | 1.0 |
| zellij-org__zellij__Cargo | 21 | 13 | 3 | 1.0 |
| zulip__zulip__uv | 11 | 8 | 0 | 1.0 |

