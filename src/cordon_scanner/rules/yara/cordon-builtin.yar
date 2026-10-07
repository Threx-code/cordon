// Cordon's built-in YARA pack (`--yara builtin`). Rules by the GuardDog Team, Datadog,
// from github.com/DataDog/guarddog at 1f4a66c064fb2087c224750507f3b65c7633deeb, Apache License 2.0 (upstream/LICENSE),
// unchanged. Chosen by tests/conformance/generate/yara_select.py: see MANIFEST.json.

rule threat_filesystem_autostart
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects suspicious autostart persistence mechanisms"
        identifies = "threat.filesystem.autostart"
        severity = "high"
        mitre_tactics = "persistence"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - bashrc/profile modifications
        $py_bashrc = ".bashrc" nocase
        $py_bash_profile = ".bash_profile" nocase
        // Require quoted-path context so attribute access (self.profile,
        // config.profile) and identifiers (.profile_manager) don't match.
        $py_profile = /['"][^'"]*\.profile['"]/ nocase
        $py_zshrc = ".zshrc" nocase

        // Python - system-wide startup scripts
        $py_rc_local = "/etc/rc.local" nocase
        $py_init_d = "/etc/init.d/" nocase
        $py_profile_d = "/etc/profile.d/" nocase

        // Python - XDG autostart (Linux desktop)
        $py_autostart = ".config/autostart/" nocase

        // Python - LaunchAgent/LaunchDaemon (macOS)
        $py_launch_agents = "LaunchAgents" nocase
        $py_launch_daemons = "LaunchDaemons" nocase
        $py_plist = ".plist" nocase

        // Node.js - shell config file modifications
        $js_bashrc_write = /fs\.(writeFile|appendFile)[^)]*['"].*\.bashrc/ nocase
        $js_profile_write = /fs\.(writeFile|appendFile)[^)]*['"].*\.profile/ nocase
        $js_zshrc_write = /fs\.(writeFile|appendFile)[^)]*['"].*\.zshrc/ nocase

        // Node.js - startup directories
        $js_autostart_path = /['"].*\.config\/autostart/ nocase
        $js_init_path = /['"].*\/etc\/init\.d\// nocase

        // Windows Registry (Node.js on Windows)
        $win_run_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $win_runonce_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $win_startup_folder = "\\Start Menu\\Programs\\Startup" nocase

        // Python - Windows registry manipulation
        $py_winreg = "import winreg" nocase
        $py_reg_setvalue = "winreg.SetValueEx(" nocase

        // Combined patterns (file write + startup location)
        $py_write_mode = /'[wa]\+?'/ nocase
        // Word boundary so urlopen()/fdopen() don't satisfy the open() condition.
        $py_open_write = /\bopen\s*\(/ nocase

    condition:
        // Startup script modification patterns
        (any of ($py_bashrc, $py_bash_profile, $py_profile, $py_zshrc, $py_rc_local) and ($py_write_mode or $py_open_write)) or

        // System-wide startup locations
        any of ($py_init_d, $py_profile_d, $py_autostart) or

        // macOS persistence
        (any of ($py_launch_agents, $py_launch_daemons) and $py_plist) or

        // Node.js file writes to startup locations
        any of ($js_bashrc_write, $js_profile_write, $js_zshrc_write, $js_autostart_path, $js_init_path) or

        // Windows registry persistence
        (any of ($win_run_key, $win_runonce_key, $win_startup_folder) and (any of ($py_winreg, $py_reg_setvalue) or any of ($js_*)))
}

rule threat_filesystem_destruction
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects destructive operations (recursive deletion, wiping)"
        identifies = "threat.filesystem.destruction"
        severity = "high"
        mitre_tactics = "impact"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Recursive/dangerous deletions
        $dangerous_rm = /rm\s+-rf\s+\// nocase
        $dangerous_rmtree_root = /rmtree\s*\(\s*['"]\/[^'"]*['"]/ nocase
        $py_rmtree_home = /rmtree\s*\(\s*['"]~/ nocase
        $py_rmtree_user = /rmtree\s*\(\s*os\.path\.expanduser/ nocase

        // Wiping specific important directories
        $wipe_home = /rm.*['"]\/home[\/'"]/i nocase
        $wipe_users = /rm.*['"]\/Users[\/'"]/i nocase
        $wipe_root = /rm.*['"]\/['"]\s*$/i nocase

        // Disk wiping utilities
        $dd_zero = "dd if=/dev/zero" nocase
        $dd_random = "dd if=/dev/urandom" nocase
        $shred = "shred -" nocase

        // Node.js - recursive deletion of a hardcoded root/absolute path
        $js_rimraf_root = /rimraf\s*\(\s*['"]\/[^'"]*['"]/ nocase

    condition:
        any of them
}

rule threat_filesystem_read
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects access to sensitive files (credentials, configs, keys)"
        identifies = "threat.filesystem.read"
        severity = "high"
        mitre_tactics = "credential-access"
        specificity = "low"
        sophistication = "low"

        max_hits = 5
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.gemspec"
    strings:
        // Password/credential files
        $passwd = "/etc/passwd" nocase
        $shadow = "/etc/shadow" nocase

        // Environment files - require quotes or path context to avoid matching process.env
        $env1 = /['"][^'"]*\.env['"]/ nocase
        $env2 = /['"][^'"]*\.env\.local['"]/ nocase
        $env3 = /['"][^'"]*\.env\.production['"]/ nocase

        // SSH keys
        $ssh1 = ".ssh/id_rsa"
        $ssh2 = ".ssh/id_ed25519"
        $ssh3 = ".ssh/id_ecdsa"

        // Git credentials
        $git1 = ".git/config"
        $git2 = ".git-credentials"
        $git3 = ".gitconfig"
        // A real path like "~/.netrc", not the bare ".netrc" constant HTTP
        // clients define for netrc auth
        $netrc = /['"][^'"]*\/\.netrc['"]/ nocase

        // Cloud credentials
        $aws = ".aws/credentials"
        $gcp = "gcloud/credentials"
        $azure = ".azure/credentials"

        // NPM/package manager tokens
        $npm = ".npmrc"
        $pypi = ".pypirc"

        // Browser/application data
        $chrome = "Google/Chrome/User Data"
        $firefox = ".mozilla/firefox"

    condition:
        any of them
}

rule threat_network_dns_exfil
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects DNS-based data exfiltration: encoding data in DNS queries"
        identifies = "threat.network.outbound"
        severity = "high"
        mitre_tactics = "exfiltration"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python: socket.getaddrinfo with f-string or format (data in subdomain)
        $py_getaddrinfo_f = /socket\.getaddrinfo\s*\(\s*f['"]/ nocase
        $py_getaddrinfo_fmt = /socket\.getaddrinfo\s*\(.*\.format\s*\(/ nocase
        $py_getaddrinfo_concat = /socket\.getaddrinfo\s*\(.*\+.*\+/ nocase

        // Python: socket.gethostbyname with constructed hostname
        $py_gethostbyname_f = /socket\.gethostbyname\s*\(\s*f['"]/ nocase
        $py_gethostbyname_fmt = /socket\.gethostbyname\s*\(.*\.format\s*\(/ nocase

        // General: nslookup/dig commands with variable interpolation
        $cmd_nslookup = /nslookup\s+.*\$/ nocase
        $cmd_dig = /\bdig\s+.*\$/ nocase

    condition:
        any of ($py_getaddrinfo_*, $py_gethostbyname_*) or
        any of ($cmd_*)
}

rule threat_network_exfil_messenger
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects hardcoded messaging platform tokens/webhooks used for data exfiltration"
        identifies = "threat.network.outbound"
        severity = "high"
        mitre_tactics = "exfiltration"
        specificity = "high"
        sophistication = "low"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Telegram bot tokens (format: digits:alphanumeric)
        $telegram_token = /\b\d{8,12}:[A-Za-z0-9_-]{30,40}\b/

        // Telegram bot API URL with token
        $telegram_api = /api\.telegram\.org\/bot\d+:/

        // Telegram sendMessage/sendDocument calls
        $telegram_send = /telegram.*send(Message|Document)/i nocase

        // Discord webhook URLs
        $discord_webhook = /discord(app)?\.com\/api\/webhooks\/\d+\// nocase

        // Discord bot tokens (format: base64-ish string with dots)
        $discord_token = /['"][A-Za-z0-9]{24,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}['"]/

    condition:
        any of ($telegram_token, $telegram_api, $telegram_send) or
        any of ($discord_webhook, $discord_token)
}

rule threat_network_exfil_sysinfo
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects system info collection combined with network exfiltration (hostname/user in HTTP requests)"
        identifies = "threat.network.outbound"
        severity = "high"
        mitre_tactics = "exfiltration"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // System info collection
        $py_hostname = /socket\.gethostname\s*\(\s*\)/ nocase
        // node/uname reveal host identity; system/machine are routine OS branching
        $py_platform = /platform\.(node|uname)\s*\(\s*\)/ nocase
        $py_getuser = /getpass\.getuser\s*\(\s*\)/ nocase
        $py_getlogin = /os\.getlogin\s*\(\s*\)/ nocase
        $py_username = /os\.environ\s*\[\s*['"]USER(NAME)?['"]\s*\]/ nocase
        $py_whoami = /os\.(system|popen)\s*\(\s*['"]whoami/ nocase

        $js_hostname = /os\.hostname\s*\(\s*\)/ nocase
        $js_userinfo = /os\.userInfo\s*\(\s*\)/ nocase

        // Network operations (sending data out)
        $py_requests = /requests\.(get|post|put)\s*\(/ nocase
        $py_urllib = /urllib\.\w+\.(urlopen|urlretrieve)\s*\(/ nocase
        $py_http = /http\.client\.HTTP/ nocase

        $js_fetch = /\bfetch\s*\(/ nocase
        $js_axios = /axios\.(get|post|put)\s*\(/ nocase
        $js_http_request = /https?\.(get|request)\s*\(/ nocase

    condition:
        // System info + network = exfiltration
        (any of ($py_hostname, $py_platform, $py_getuser, $py_getlogin, $py_username, $py_whoami) and any of ($py_requests, $py_urllib, $py_http)) or
        (any of ($js_hostname, $js_userinfo) and any of ($js_fetch, $js_axios, $js_http_request))
}

rule threat_network_exfiltration
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects URLs to suspicious domains often used for exfiltration or C2"
        identifies = "threat.network.outbound"
        severity = "high"
        mitre_tactics = "exfiltration"
        specificity = "medium"
        sophistication = "medium"

        max_hits = 5
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.gemspec,*.rs"
    strings:
        // Webhook/tunneling services
        $webhook1 = "webhook.site" nocase
        $webhook2 = "webhook.cool" nocase
        $webhook3 = "oastify.com" nocase
        $webhook4 = "burpcollaborator.net" nocase
        $webhook5 = "burpcollaborator.me" nocase
        $webhook6 = "pipedream.net" nocase
        $webhook7 = "beeceptor.com" nocase

        // Tunneling services
        $tunnel1 = "ngrok.io" nocase
        $tunnel2 = "ngrok-free.app" nocase
        $tunnel3 = "trycloudflare.com" nocase
        $tunnel4 = "localhost.run" nocase

        // Paste/file sharing services
        $paste1 = "pastebin.com" nocase
        $paste2 = "hastebin.com" nocase
        $paste3 = "ghostbin.site" nocase
        $paste4 = "transfer.sh" nocase
        $paste5 = "filetransfer.io" nocase

        // Communication platforms (when used for exfil)
        $comm1 = "api.telegram.org" nocase
        $comm2 = "discord.com/api/webhooks" nocase

        // Suspicious TLDs; trailing boundary requires the TLD to end the host
        $tld1 = /https?:\/\/[^\s\/]+\.(xyz|tk|ml|ga|cf|gq)([\/:?#"'\s)]|$)/
        $tld2 = /https?:\/\/[^\s\/]+\.(pw|top|club|bid|icu)([\/:?#"'\s)]|$)/
        $tld3 = /https?:\/\/[^\s\/]+\.(zip|stream|link|quest)([\/:?#"'\s)]|$)/

        // Direct IP addresses in URLs, restricted to public addresses. The
        // exclusion of loopback/private ranges (0/8, 10/8, 127/8, 169.254/16,
        // 172.16-31, 192.168/16) is baked into the regex so it applies per
        // match: a private URL elsewhere in the file cannot suppress a real
        // public-IP C2 endpoint. First two octets gate the private ranges;
        // remaining octets are any valid 0-255.
        $ip = /https?:\/\/(([1-9]|1[1-9]|[2-9][0-9]|1[01][0-9]|12[0-6]|12[89]|1[3-5][0-9]|16[0-8]|17[01]|17[3-9]|18[0-9]|19[01]|19[3-9]|2[0-4][0-9]|25[0-5])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|169\.(25[0-3]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]|255)|172\.([0-9]|1[0-5]|3[2-9]|[4-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])|192\.([0-9]|[1-9][0-9]|1[0-5][0-9]|16[0-7]|169|17[0-9]|18[0-9]|19[0-9]|2[0-4][0-9]|25[0-5]))\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/

    condition:
        any of ($webhook*, $tunnel*, $paste*, $comm*, $tld*) or
        $ip
}

rule threat_network_outbound_shady_links
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects URLs to URL shorteners, file sharing, and suspicious services"
        identifies = "threat.network.outbound.shady_links"
        severity = "medium"
        mitre_tactics = "command-and-control"
        specificity = "high"
        sophistication = "low"

        max_hits = 5
        path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.gemspec"
    strings:
        // URL shorteners - complete domains
        $shortener = /(\b|^|[\s"'(])(https??:\/\/)??[a-zA-Z0-9.-]*?(bit\.ly)\b/ nocase

        // Ephemeral/tunnels - complete domains (group 1). workers.dev omitted: it
        // hosts many legitimate assets.
        $ephemeral1 = /(\b|^|[\s"'(])(https??:\/\/)??[a-zA-Z0-9.-]*?(appdomain\.cloud|ngrok\.io|termbin\.com|localhost\.run|webhook\.(site|cool)|oastify\.com|burpcollaborator\.(me|net)|trycloudflare\.com)\b/ nocase

        // Ephemeral/tunnels - complete domains (group 2)
        $ephemeral2 = /(\b|^|[\s"'(])(https??:\/\/)??[a-zA-Z0-9.-]*?(oast\.(pro|live|site|online|fun|me)|ply\.gg|pipedream\.net|dnslog\.cn|webhook-test\.com|typedwebhook\.tools|beeceptor\.com|ngrok-free\.(app|dev))\b/ nocase

        // Exfiltration services - complete domains. discord.com scoped to the
        // webhook API path (not invite links).
        $exfil = /(\b|^|[\s"'(])(https??:\/\/)??[a-zA-Z0-9.-]*?(discord\.com\/api\/webhooks|transfer\.sh|filetransfer\.io|sendspace\.com|backblazeb2\.com|paste\.ee|pastebin\.com|hastebin\.com|ghostbin\.site|api\.telegram\.org|rentry\.co)\b/ nocase

        // Intel/IP lookup services - complete domains
        $intel = /(\b|^|[\s"'(])(https??:\/\/)??[a-zA-Z0-9.-]*?(ipinfo\.io|checkip\.dyndns\.org|ip\.me|jsonip\.com|ipify\.org|ifconfig\.me)\b/ nocase

        // Malware download services - complete domains
        $malware_dl = /(\b|^|[\s"'(])(https??:\/\/)??[a-zA-Z0-9.-]*?(files\.catbox\.moe)\b/ nocase

    condition:
        any of them
}

rule threat_network_reverse_shell
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects reverse shell patterns and remote access tools"
        identifies = "threat.network.outbound"
        severity = "high"
        mitre_tactics = "command-and-control"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.sh,*.rb"

    strings:
        // Bash reverse shells
        $bash_tcp = /bash\s+-i\s+>&\s+\/dev\/tcp\// nocase
        $bash_udp = /bash\s+-i\s+>&\s+\/dev\/udp\// nocase

        // Python reverse shell patterns
        $py_socket_connect = /socket\s*\.\s*socket\s*\(.*\)\s*\.\s*connect\s*\(/ nocase
        $py_pty_spawn = /pty\s*\.\s*spawn\s*\(/ nocase
        $py_subprocess_shell = /subprocess\.(call|Popen|run)\s*\(\s*\[?\s*['"]\/bin\/(ba)?sh/ nocase

        // Netcat reverse shell
        $nc_reverse = /\bnc\s+.*-e\s+\/bin\/(ba)?sh/ nocase
        $ncat_reverse = /\bncat\s+.*-e\s+\/bin\/(ba)?sh/ nocase

        // Python socket + exec/eval (socket-based remote control)
        $py_socket_exec = /socket.*\bexec\s*\(/ nocase
        $py_socket_eval = /socket.*\beval\s*\(/ nocase

        // Common reverse shell function names
        $func_reverse_shell = /def\s+(reverse_shell|rev_shell|connect_back|backdoor)\s*\(/ nocase

    condition:
        any of ($bash_*, $nc_*, $ncat_*) or
        ($py_socket_connect and ($py_pty_spawn or $py_subprocess_shell or $py_socket_exec or $py_socket_eval)) or
        $func_reverse_shell
}

rule threat_npm_dependency_confusion
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects dependency confusion indicators: self-referencing dependencies or DNS exfil in scripts"
        identifies = "threat.npm.http.dependency"
        severity = "high"
        mitre_tactics = "initial-access"
        specificity = "high"
        sophistication = "low"
        max_hits = 1
        path_include = "*/package.json,package.json"

    strings:
        // DNS-based exfiltration in scripts (common dep confusion probe)
        $dns_exfil_nslookup = /nslookup\s+.*\$/ nocase
        $dns_exfil_dig = /\bdig\s+.*\$/ nocase
        $dns_exfil_host = /\bhost\s+.*\$/ nocase
        $dns_exfil_curl = /curl\s+.*\$\{?[A-Z_]+\}?\./ nocase

        // Whoami/hostname exfil via DNS (very common in dep confusion)
        $dns_whoami = /\$\(whoami\)/ nocase
        $dns_hostname = /\$\(hostname\)/ nocase

        // Beacon-style callbacks (common in dep confusion proofs)
        $beacon_curl = /curl\s+https?:\/\/[^\/]*\.(burpcollaborator|oastify|interact|canarytokens|dnslog)/ nocase
        $beacon_wget = /wget\s+https?:\/\/[^\/]*\.(burpcollaborator|oastify|interact|canarytokens|dnslog)/ nocase

    condition:
        any of them
}

rule threat_npm_http_dependency
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects HTTP/HTTPS URL dependencies in package.json (dependency confusion, untrusted sources)"
        identifies = "threat.npm.http.dependency"
        severity = "high"
        mitre_tactics = "initial-access"
        specificity = "low"
        sophistication = "low"
        max_hits = 3
        path_include = "*/package.json,package.json"

    strings:
        // HTTP URL as dependency version (IP address or domain)
        $http_ip = /:\s*"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase
        $http_url = /:\s*"https?:\/\/[^"]+\.(tar\.gz|tgz|zip)"/ nocase
        // Generic HTTP dependency pointing to non-standard hosts
        $http_plain = /:\s*"http:\/\/[^"]+"/
        // Plain-http URLs in flat package metadata fields (homepage, author-as-string, ...)
        $http_meta = /"(web|website|homepage|funding|bugs|email|wiki|blog|docs|documentation|repository|author|maintainers|contributors|logo|image)"\s*:\s*"http:\/\//  nocase
        // Plain-http URL under the nested `url` key of a metadata object, e.g.
        // "author": { "url": "http://..." }. Scoped to metadata objects so a
        // dependency literally named `url` with an http specifier is still reported.
        $http_meta_url = /"(author|repository|bugs|funding|contributors|maintainers)"\s*:\s*[\[{][^}]*"url"\s*:\s*"http:\/\//  nocase

    condition:
        $http_ip or
        $http_url or
        // plain-http values beyond those explained by metadata = dependency URLs
        (#http_plain > #http_meta + #http_meta_url)
}

rule threat_npm_preinstall_script
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects npm preinstall scripts, which are almost exclusively used for malware delivery"
        identifies = "threat.process.hooks"
        severity = "high"
        mitre_tactics = "execution"
        specificity = "high"
        sophistication = "low"

        max_hits = 1
        path_include = "*/package.json"

    strings:
        $preinstall = /"preinstall"[\s]*:[\s]*"[^"]+/ nocase

    condition:
        $preinstall
}

rule threat_process_cryptomining
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects cryptocurrency mining activity"
        identifies = "threat.process.cryptomining"
        severity = "high"
        mitre_tactics = "impact"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.sh,*.rs"

    strings:
        // Mining software
        $miner_xmrig = "xmrig" nocase
        $miner_ethminer = "ethminer" nocase
        $miner_cgminer = "cgminer" nocase
        $miner_bfgminer = "bfgminer" nocase
        $miner_cpuminer = "cpuminer" nocase
        $miner_ccminer = "ccminer" nocase

        // Mining pools
        $pool_monero = /(pool\.)?[a-z0-9-]+\.monero/ nocase
        $pool_supportxmr = "supportxmr.com" nocase
        $pool_minexmr = "minexmr.com" nocase
        $pool_nanopool = "nanopool.org" nocase

        // Mining protocols
        $stratum = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase

        // Monero address (95 chars starting with 4). Word boundaries keep it from
        // matching inside a longer base64 blob.
        $monero_address = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/ nocase

        // Mining-related terms in combination (require more context)
        $mining_hashrate = "hashrate" nocase
        $mining_nonce = "nonce" nocase
        $mining_stratum = "stratum" nocase
        $mining_miner = "miner" nocase

    condition:
        any of ($miner_*) or
        any of ($pool_*) or
        any of ($stratum*) or
        $monero_address or
        3 of ($mining_*)
}

rule threat_process_hooks
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects LOLBAS usage in install hooks (execution and network tools)"
        identifies = "threat.process.hooks"
        severity = "medium"
        mitre_tactics = "execution"
        specificity = "medium"
        sophistication = "low"

        max_hits = 1
        path_include = "*/package.json,*/setup.py"

    strings:
        // npm install hooks (exclude prepare/prepack - build lifecycle, not attack vectors)
        $npm_preinstall = /"preinstall"[\s]*:[\s]*"[^"]+/ nocase
        $npm_install = /"install"[\s]*:[\s]*"[^"]+/ nocase
        $npm_postinstall = /"postinstall"[\s]*:[\s]*"[^"]+/ nocase

        // Python setuptools hooks
        $py_cmdclass_install = /cmdclass\s*=\s*\{[^}]*['"]install['"]\s*:/ nocase
        $py_cmdclass_develop = /cmdclass\s*=\s*\{[^}]*['"]develop['"]\s*:/ nocase
        $py_cmdclass_egg_info = /cmdclass\s*=\s*\{[^}]*['"]egg_info['"]\s*:/ nocase

        // setup.py top-level execution (setup() with imports running code at module level)
        $py_setup = /\bsetup\s*\(/ nocase

        // LOLBAS process execution
        $bash_c = /\bbash\s+-c\b/
        $sh_c = /\bsh\s+-c\b/
        $bash_path = /\/bin\/bash\b/
        $sh_path = /\/bin\/sh\b/
        $bash_script = /\bbash\s+\S+\.(sh|bash)\b/
        $sh_script = /\bsh\s+\S+\.sh\b/
        $python_flag = /\bpython[0-9]?\s+-[cmubE]\b/
        $python_script = /\bpython[0-9]?\s+\S+\.py\b/
        $node_flag = /\bnode\s+-e\b/
        $node_script = /\bnode\s+\S+\.js\b/
        $perl_flag = /\bperl\s+-[eE]\b/
        $ruby_flag = /\bruby\s+-e\b/
        $php_flag = /\bphp\s+-r\b/

        // LOLBAS network tools
        $curl_flag = /\bcurl\s+-[sSfLokOdXH]/ nocase
        $curl_url = /\bcurl\s+['"]?https?:\/\// nocase
        $curl_pipe = /\bcurl\s.*\|/ nocase
        $wget_flag = /\bwget\s+-/ nocase
        $wget_url = /\bwget\s+['"]?https?:\/\// nocase
        $nc_flag = /\bnc\s+-[lvnzwep]/ nocase
        $nc_host = /\bnc\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase
        $netcat_cmd = /\bnetcat\s/ nocase

    condition:
        (any of ($npm_*) or any of ($py_*)) and
        (any of ($bash_*, $sh_*, $python_*, $node_*, $perl_*, $ruby_*, $php_*,
                 $curl_*, $wget_*, $nc_*, $netcat_*))
}

rule threat_process_injection_dll
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects DLL injection and process injection techniques"
        identifies = "threat.process.injection.dll"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "high"

        max_hits = 5
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Windows API injection chain (need 2+ to indicate actual injection)
        $win_writeprocessmemory = "WriteProcessMemory" nocase
        $win_createremotethread = "CreateRemoteThread" nocase
        $win_virtualalloc = "VirtualAllocEx" nocase
        $win_ntcreatethreadex = "NtCreateThreadEx" nocase

        // DLL proxy execution via shell
        $dll_rundll32 = /\brundll32\s+/ nocase
        $dll_regsvr32 = /\bregsvr32\s+/ nocase
        $dll_mshta = /\bmshta\s+/ nocase

        // Python ctypes injection pattern (loading + calling into foreign process)
        $py_ctypes_windll = "ctypes.windll.kernel32" nocase

    condition:
        2 of ($win_*) or
        any of ($dll_rundll32, $dll_regsvr32, $dll_mshta) or
        // ctypes kernel32 only counts when paired with an injection API (alone it
        // serves many benign calls like OpenProcess/LocalFree)
        ($py_ctypes_windll and 1 of ($win_*))
}

rule threat_process_memory
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects memory scraping and credential dumping from process memory"
        identifies = "threat.process.memory"
        severity = "high"
        mitre_tactics = "credential-access"
        specificity = "low"
        sophistication = "high"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - process memory access
        $py_psutil_memory = "psutil.Process(" nocase
        $py_memory_info = ".memory_info()" nocase
        $py_memory_maps = ".memory_maps()" nocase
        $py_proc_mem = "/proc/*/mem" nocase
        $py_proc_maps = "/proc/*/maps" nocase

        // Python - ptrace (Linux debugger interface)
        $py_ptrace_attach = "ptrace.attach(" nocase
        $py_ptrace_peek = "PTRACE_PEEKDATA" nocase

        // Python - Windows memory access
        $py_readprocessmemory = "ReadProcessMemory" nocase
        $py_openprocess = "OpenProcess" nocase

        // Python - credential dumping tools/techniques
        $py_mimikatz = "mimikatz" nocase
        $py_pypykatz = "pypykatz" nocase
        $py_lsass = "lsass" nocase
        $py_secretsdump = "secretsdump" nocase

        // Python - memory dumping
        $py_minidump = "minidump" nocase
        $py_procdump = "procdump" nocase

        // Node.js - process memory access (via native modules)
        $js_ffi = "require('ffi-napi')" nocase
        $js_memoryjs = "memoryjs" nocase
        $js_readprocessmemory = "ReadProcessMemory" nocase
        $js_openprocess = "OpenProcess" nocase

        // Node.js - debugging/profiling APIs
        $js_inspector = "require('inspector')" nocase
        $js_heapdump = "require('heapdump')" nocase
        $js_v8_profiler = "require('v8-profiler')" nocase

        // Memory search patterns
        $search_password = /(search|scan|find).*(password|credential|secret|token)/i nocase
        $extract_memory = /(extract|dump|read).*(memory|heap|process)/i nocase

        // Regex patterns for credentials in memory
        $regex_password = /password\s*[:=]/i nocase
        $regex_token = /token\s*[:=]/i nocase
        $regex_api_key = /api[_-]?key\s*[:=]/i nocase

        // Python - memory scanning libraries
        $py_regex_search = "re.search(" nocase
        $py_regex_findall = "re.findall(" nocase
        $py_bytes_find = ".find(b'" nocase

    condition:
        // Python memory access APIs
        (any of ($py_psutil_memory, $py_memory_info, $py_memory_maps) and
         (any of ($search_password, $extract_memory, $regex_password, $regex_token))) or

        // Low-level memory access. OpenProcess only counts with an actual memory
        // read (alone it is a benign liveness check).
        any of ($py_ptrace_attach, $py_ptrace_peek, $py_readprocessmemory) or
        ($py_openprocess and $py_readprocessmemory) or

        // Python credential dumping tools
        any of ($py_mimikatz, $py_pypykatz, $py_lsass, $py_secretsdump) or

        // Python memory dumping
        (any of ($py_minidump, $py_procdump) and $py_proc_mem) or

        // Node.js native memory access
        (any of ($js_ffi, $js_memoryjs) and
         (any of ($js_readprocessmemory, $js_openprocess))) or

        // Node.js heap/memory profiling + credential search
        (any of ($js_heapdump, $js_v8_profiler, $js_inspector) and
         (any of ($search_password, $extract_memory))) or

        // Memory scanning for credentials
        ((any of ($py_regex_search, $py_regex_findall, $py_bytes_find)) and
         (any of ($regex_password, $regex_token, $regex_api_key)) and
         (any of ($py_memory_info, $py_proc_mem, $py_proc_maps)))
}

rule threat_process_powershell_encoded
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects PowerShell encoded commands, hidden windows, and download cradles"
        identifies = "threat.process.spawn"
        severity = "high"
        mitre_tactics = "execution"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // PowerShell encoded command (base64-encoded PS commands)
        $ps_encoded = /powershell.*-EncodedCommand\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $ps_enc_short = /powershell.*-enc\s+[A-Za-z0-9+\/=]{20,}/ nocase

        // PowerShell hidden window
        $ps_hidden = /powershell.*-WindowStyle\s+Hidden/ nocase

        // PowerShell download cradles
        $ps_iex_iwr = /IEX\s*\(\s*(New-Object\s+Net\.WebClient|Invoke-WebRequest)/ nocase
        $ps_downloadstring = /\(New-Object\s+Net\.WebClient\)\.DownloadString\s*\(/ nocase
        $ps_downloadfile = /\(New-Object\s+Net\.WebClient\)\.DownloadFile\s*\(/ nocase

        // Python calling PowerShell with these patterns
        $py_popen_ps = /Popen\s*\(\s*['"]powershell/ nocase
        $py_system_ps = /os\.(system|popen)\s*\(\s*['"]powershell/ nocase

    condition:
        any of ($ps_encoded, $ps_enc_short) or
        ($ps_hidden and any of ($py_*)) or
        any of ($ps_iex_iwr, $ps_downloadstring, $ps_downloadfile)
}

rule threat_process_spawn_silent
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects fully silent process execution (suppressing all output channels)"
        identifies = "threat.process.spawn.silent"
        severity = "low"
        mitre_tactics = "defense-evasion"
        specificity = "low"
        sophistication = "medium"

        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"

    strings:
        // Python - require BOTH stdout AND stderr suppressed (full silencing)
        $py_stdout_devnull = "stdout=subprocess.DEVNULL" nocase
        $py_stderr_devnull = "stderr=subprocess.DEVNULL" nocase

        // JavaScript/Node.js - detached + stdio ignore (intent to hide)
        $js_detached = /"?detached"?[\s]*:[\s]*true/ nocase
        $js_stdio_ignore = /"?stdio"?[\s]*:[\s]*('|")ignore/ nocase
        $js_stdio_arr_ignore = /"?stdio"?[\s]*:[\s]*\[[\s]*('|")ignore/ nocase
        $js_windowshide = /"?windowsHide"?[\s]*:[\s]*true/ nocase

        // Go - detached/hidden processes
        $go_hidewindow = "syscall.CREATE_NO_WINDOW" nocase

    condition:
        // Python: both stdout AND stderr devnulled
        ($py_stdout_devnull and $py_stderr_devnull) or
        // JS: detached + stdio suppressed or windows hidden
        ($js_detached and (any of ($js_stdio_*, $js_windowshide))) or
        // Go: explicit window hiding
        $go_hidewindow
}

rule threat_runtime_dynamic_loader
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects dynamic code loading: downloading and importing/executing code at runtime"
        identifies = "threat.runtime.obfuscation"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "high"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth"

    strings:
        // Dynamic import mechanisms
        $importlib_import = /importlib\.import_module\s*\(/ nocase
        $importlib_util = /importlib\.util\.spec_from_/ nocase
        $builtins_import = /__import__\s*\(/ nocase

        // getattr for dynamic function resolution
        $getattr_call = /getattr\s*\(\s*\w+\s*,/ nocase

        // Network download via an actual fetch call, not a bare urllib import
        $urllib_dl = /urllib\.\w*request\w*\.(urlopen|urlretrieve)\s*\(/ nocase
        $requests_get = /requests\.get\s*\(/ nocase

        // base64 decode (for obfuscated module names/URLs)
        $b64_decode = /base64\.\w*decode/ nocase
        $b64_b64decode = /b64decode\s*\(/ nocase

        // Execution sink: bare exec(/eval(, not method calls. Required alongside
        // import+download, which co-occur in many benign plugin loaders.
        $exec_sink = /[^.\w]exec\s*\(/ nocase
        $eval_sink = /[^.\w]eval\s*\(/ nocase

    condition:
        // Dynamic import + network download + execution of the payload
        (any of ($importlib_*, $builtins_import) and any of ($urllib_*, $requests_get) and any of ($exec_sink, $eval_sink)) or
        // Dynamic import + getattr + base64 (obfuscated dynamic loading)
        (any of ($importlib_*, $builtins_import) and $getattr_call and any of ($b64_*))
}

rule threat_runtime_enumeration
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects extensive system/network enumeration activities"
        identifies = "threat.runtime.enumeration"
        severity = "medium"
        mitre_tactics = "discovery"
        specificity = "medium"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - process enumeration
        $py_psutil_process = "psutil.process_iter()" nocase
        $py_psutil_pids = "psutil.pids()" nocase
        $py_proc_list = "/proc/" nocase

        // Node.js - process enumeration
        $js_ps_list = "ps-list" nocase
        $js_process_list = "process-list" nocase
        $js_find_process = "find-process" nocase

        // Python - network interface enumeration
        $py_netifaces = "netifaces.interfaces()" nocase
        $py_ifconfig = "ifconfig" nocase
        // Word boundary after "addr" so prose like "IP Address" does not match.
        $py_ip_addr = /\bip\s+addr\b/ nocase

        // Node.js - network enumeration
        $js_os_networkinterfaces = "os.networkInterfaces()" nocase
        $js_network_list = "network-list" nocase

        // Python - user enumeration
        $py_etc_passwd = "/etc/passwd" nocase
        $py_pwd_getpwall = "pwd.getpwall()" nocase

        // Port scanning indicators. Keep "port" and "scan" adjacent so they can't
        // span unrelated identifiers like "afterImportPos = scanner". Match nmap
        // case-sensitively with word boundaries so it can't match "ChainMap".
        $port_scan = /\bport[\s_-]?scan/i nocase
        $nmap = /\bnmap\b/

    condition:
        2 of them
}

rule threat_runtime_keylogging
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects keylogging and input capture patterns"
        identifies = "threat.runtime.keylogging"
        severity = "high"
        mitre_tactics = "credential-access"
        specificity = "low"
        sophistication = "medium"
        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - keylogging libraries
        $py_pynput_keyboard = "from pynput import keyboard" nocase
        $py_pynput_listener = "keyboard.Listener(" nocase
        $py_pynput_on_press = "on_press" nocase
        $py_keyboard_hook = "keyboard.hook(" nocase
        $py_keyboard_on_press = "keyboard.on_press(" nocase

        // Python - PyHook (Windows keylogging)
        $py_pyhook = "import pyHook" nocase
        $py_hookmanager = "pyHook.HookManager()" nocase

        // Python - evdev (Linux input events)
        $py_evdev = "from evdev import" nocase
        $py_inputdevice = "InputDevice(" nocase
        $py_event_kbd = "ecodes.EV_KEY" nocase

        // Node.js - keylogging libraries
        $js_iohook = "require('iohook')" nocase
        $js_iohook_start = "iohook.start()" nocase
        $js_keypress = "require('keypress')" nocase
        $js_node_key_sender = "node-key-sender" nocase
        $js_node_global_key = "node-global-key-listener" nocase

        // Python - X11 input monitoring (Linux)
        $py_xlib = "from Xlib import" nocase
        $py_xlib_display = "display.Display()" nocase
        $py_record_context = "record.create_context(" nocase

        // Suspicious patterns - logging keystrokes (require function-like context)
        $log_keystroke = /log_?key(stroke|press)/i nocase
        $steal_password = /(steal|grab|exfiltrate).*(password|credential|passwd)/i nocase

        // Hook installation patterns
        $hook_keyboard = "hook_keyboard" nocase
        $set_hook = "SetWindowsHookEx" nocase

        // Combination: listener + file write
        $py_file_write = "write(" nocase
        $py_file_append = "append(" nocase
        $js_fs_write = "fs.writeFile(" nocase
        $js_fs_append = "fs.appendFile(" nocase

    condition:
        // Python keylogging libraries. Require an actual capture call, not a bare
        // `import keyboard` (the keyboard lib has legitimate hotkey uses).
        (($py_pynput_keyboard or $py_pynput_listener) and $py_pynput_on_press) or
        (any of ($py_keyboard_hook, $py_keyboard_on_press)) or
        (any of ($py_pyhook, $py_hookmanager)) or
        (any of ($py_evdev, $py_inputdevice) and $py_event_kbd) or
        (any of ($py_xlib, $py_xlib_display) and $py_record_context) or

        // Node.js keylogging libraries
        (any of ($js_iohook, $js_iohook_start)) or
        any of ($js_keypress, $js_node_key_sender, $js_node_global_key) or

        // Suspicious logging patterns
        any of ($log_keystroke, $steal_password) or

        // Hook patterns
        any of ($hook_keyboard, $set_hook) or

        // Combination: keyboard listener + file write (very suspicious)
        ((any of ($py_pynput_keyboard, $py_pynput_listener, $py_keyboard_hook, $py_keyboard_on_press, $js_iohook, $js_keypress)) and
         (any of ($py_file_write, $py_file_append, $js_fs_write, $js_fs_append)))
}

rule threat_runtime_obfuscation_api
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects advanced API call obfuscation using introspection and reflection techniques"
        identifies = "threat.runtime.obfuscation.api"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
    strings:
        // getattr that fetches AND immediately calls a dangerous builtin, e.g.
        // getattr(o, "exec")(...). The trailing call excludes assign-only shims.
        $py_getattr_exec = /\bgetattr\s*\([^,]+,\s*['"](__import__|exec|eval|compile)['"]\s*\)\s*\(/ nocase
        // getattr on __builtins__ whose result is immediately invoked
        $py_builtins_getattr = /\bgetattr\s*\(\s*__builtins__\s*,[^)]*\)\s*\(/ nocase

        // JS reflection where the resolved descriptor .value is then invoked
        $js_get_own_prop_desc = /\bObject\s*\.\s*getOwnPropertyDescriptor\s*\([^)]+,\s*[^)]+\)\s*\.\s*\bvalue\b\s*\(/ nocase
        $js_get_own_prop_names = /\[\s*\bObject\s*\.\s*getOwnPropertyNames\s*\([^)]+\)\s*\.\s*\bfind\s*\(/ nocase
        $js_object_keys_find = /\[\s*\bObject\s*\.\s*\bkeys\s*\([^)]+\)\s*\.\s*\bfind\s*\(/ nocase
        $js_entries_find = /\bObject\s*\.\s*\bentries\s*\([^)]+\)\s*\.\s*\bfind\s*\([^)]+\)\s*\[\s*1\s*\]/ nocase
        $js_entries_filter = /\bObject\s*\.\s*\bentries\s*\([^)]+\)\s*\.\s*\bfilter\s*\([^)]+\)\s*\[\s*0\s*\]\s*\[\s*1\s*\]/ nocase

    condition:
        any of them
}

rule threat_runtime_obfuscation_base64exec
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects base64 decoding followed by code execution"
        identifies = "threat.runtime.obfuscation.base64exec"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.gemspec"

    strings:
        // Python - base64 decode + exec/eval
        $py_b64decode = /\bbase64\s*\.\s*b64decode\s*\(/ nocase
        $py_b64decode_alt = /\bbase64\s*\.\s*decodebytes\s*\(/ nocase
        $py_b64decode_std = /\bbase64\s*\.\s*standard_b64decode\s*\(/ nocase
        // bare exec(/eval( builtins, not method calls like model.eval()
        $py_exec = /[^.\w]exec\s*\(/ nocase
        $py_eval = /[^.\w]eval\s*\(/ nocase

        // JavaScript/Node.js - base64 decode patterns
        $js_atob = /\batob\s*\(/ nocase
        // Buffer.from with explicit base64 encoding (not just any Buffer.from)
        $js_buffer_b64 = /Buffer\s*\.\s*from\s*\([^)]*['"]base64['"]/ nocase
        $js_eval = /\beval\s*\(/ nocase
        $js_function = /\bnew\s+Function\s*\(/ nocase

        // Go - base64 decode + exec
        $go_b64decode = /\bbase64\s*\.\s*StdEncoding\s*\.\s*DecodeString\s*\(/ nocase
        $go_b64decode_alt = /\bbase64\s*\.\s*URLEncoding\s*\.\s*DecodeString\s*\(/ nocase
        $go_exec = /\bexec\s*\.\s*Command\s*\(/ nocase

        // Ruby - base64 decode
        $rb_b64decode = /\bBase64\s*\.\s*decode64\s*\(/ nocase
        $rb_b64decode_strict = /\bBase64\s*\.\s*strict_decode64\s*\(/ nocase
        $rb_b64decode_url = /\bBase64\s*\.\s*urlsafe_decode64\s*\(/ nocase
        $rb_unpack_m = /\.\s*unpack\s*\(\s*['"]m0?['"]/ nocase

        // Ruby - eval methods
        $rb_eval = /\beval\s*\(/ nocase
        $rb_instance_eval = /\binstance_eval\s*\(/ nocase

    condition:
        (any of ($py_b64decode*) and any of ($py_exec, $py_eval)) or
        (($js_atob or $js_buffer_b64) and ($js_eval or $js_function)) or
        (any of ($go_b64decode*) and $go_exec) or
        (any of ($rb_b64decode*, $rb_unpack_m) and any of ($rb_eval, $rb_instance_eval))
}

rule threat_runtime_obfuscation_chr
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects chr-based code obfuscation: exec/eval of chr() sequences"
        identifies = "threat.runtime.obfuscation"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"
        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth"

    strings:
        // exec("".join(map(chr, [...]))) - most common pattern
        $chr_join_exec = /exec\s*\(\s*["']?["']?\s*\.\s*join\s*\(\s*map\s*\(\s*chr\s*,/ nocase
        // eval("".join(map(chr, [...])))
        $chr_join_eval = /eval\s*\(\s*["']?["']?\s*\.\s*join\s*\(\s*map\s*\(\s*chr\s*,/ nocase
        // exec(chr(n)+chr(n)+...) or via list comprehension
        $chr_concat = /exec\s*\(\s*chr\s*\(\d+\)\s*\+/ nocase
        // [chr(n) for n in [...]] pattern
        $chr_listcomp = /\[\s*chr\s*\(\s*\w+\s*\)\s+for\s+\w+\s+in\s+\[/ nocase
        // Hex/octal escape obfuscation in eval: eval("\x65\x76\141...")
        // Matches both actual escape sequences and literal backslash-x in source
        $hex_eval = /eval\s*\(\s*"(\\x[0-9a-fA-F]{2}){5,}/ nocase
        $hex_eval2 = /eval\s*\(\s*'(\\x[0-9a-fA-F]{2}){5,}/ nocase
        $hex_eval3 = /eval\s*\(\s*"(\\[0-7]{3}){5,}/ nocase
        $hex_eval4 = /eval\s*\(\s*'(\\[0-7]{3}){5,}/ nocase

        // Underscore-only variable names used by Python obfuscators
        // 5+ consecutive underscores used as identifiers = obfuscation tool output
        $underscore_vars = /_{5,}\s*=\s*eval\s*\(/ nocase

    condition:
        any of them
}

rule threat_runtime_obfuscation_dynamic_eval
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects JavaScript payloads executed through eval/Function over a self-decoding wrapper or character-code/base64 decoded data"
        identifies = "threat.runtime.obfuscation.dynamic-eval"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
        path_exclude = "dist/*,build/*,vendor/*,node_modules/*"

    strings:
        // eval of a function literal: a packed/self-decoding wrapper invoked
        // immediately. Legitimate code defines and calls functions, it does not
        // eval a function expression.
        $eval_func = /\beval\s*\(\s*function\s*\(/ nocase

        // eval / Function over character-code decoding
        $eval_fcc = /\beval\s*\([^;]{0,160}\bfromCharCode\b/ nocase
        $func_fcc = /\bnew\s+Function\s*\([^;]{0,160}\bfromCharCode\b/ nocase

        // eval / Function directly over base64 decoding
        $eval_atob = /\beval\s*\(\s*atob\s*\(/ nocase
        $func_atob = /\bnew\s+Function\s*\(\s*atob\s*\(/ nocase

        // eval of a decoder applied to a long numeric (char-code) array
        $eval_decoder_arr = /\beval\s*\(\s*[A-Za-z_$][\w$]*\s*\(\s*\[\s*\d{1,3}(\s*,\s*\d{1,3}){19,}/ nocase

    condition:
        any of them
}

rule threat_runtime_obfuscation_general
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects heavy code obfuscation techniques"
        identifies = "threat.runtime.obfuscation.general"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "medium"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Python - 50+ consecutive hex escapes (crypto test vectors are shorter)
        $py_hex_chr = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){49,}/ nocase
        // Python - 50+ consecutive octal escapes
        $py_octal = /\\[0-7]{3}(\\[0-7]{3}){49,}/ nocase

        // JavaScript - JSFuck
        $js_jsfuck = /\[\s*!\s*!\s*\[\s*\]\s*\]/ nocase
        // JavaScript - packer pattern
        $js_packer = /\beval\s*\(\s*\bfunction\s*\([a-z],\s*[a-z],\s*[a-z],\s*[a-z]/ nocase
        // JavaScript - fromCharCode over a long list of numeric literals (10+
        // char codes indicates obfuscation). Requiring numeric arguments avoids
        // false positives on legitimate long expressions such as
        // String.fromCharCode(...someCall(args)) spread over multiple lines.
        $js_fromcharcode = /\bString\s*\.\s*fromCharCode\s*\(\s*(0x[0-9a-fA-F]+|[0-9]+)(\s*,\s*(0x[0-9a-fA-F]+|[0-9]+)){9,}/ nocase

    condition:
        any of them
}

rule threat_runtime_obfuscation_hidden_code
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects a payload hidden by excessive whitespace or require aliased through a global to evade static analysis"
        identifies = "threat.runtime.obfuscation"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "high"
        max_hits = 1
        path_include = "*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // require aliased through a global bracket assignment, used to dodge static
        // require() detection (react-native-aria / Shai-Hulud injected payloads)
        $global_require = /global\s*\[\s*['"][A-Za-z0-9_$]{1,6}['"]\s*\]\s*=\s*require\b/ nocase

        // a long run of spaces pushing a payload far off-screen
        $ws_hidden = /[ ]{400,}\S/

        // execution sinks that, after a whitespace gap, signal the hidden payload
        $eval = /\beval\s*\(/ nocase
        $new_function = /\bnew\s+Function\s*\(/ nocase

    condition:
        $global_require or
        ($ws_hidden and any of ($eval, $new_function))
}

rule threat_runtime_obfuscation_import_exec
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects dynamic import chains used to obfuscate code execution"
        identifies = "threat.runtime.obfuscation"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"
        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth"

    strings:
        // exec(__import__('...')) - dynamic import + exec chain
        $import_exec = /exec\s*\(\s*__import__\s*\(/ nocase
        $import_builtins_exec = /__import__\s*\(\s*['"]builtins['"]\s*\)\s*\.\s*exec\s*\(/ nocase

        // Compressed/encoded exec: exec(zlib.decompress(base64.b64decode(...)))
        $zlib_b64_exec = /exec\s*\(\s*__import__\s*\(\s*['"]zlib['"]\s*\)\s*\.\s*decompress/ nocase
        $zlib_exec = /exec\s*\(\s*zlib\s*\.\s*decompress\s*\(\s*base64/ nocase
        $marshal_exec = /exec\s*\(\s*marshal\s*\.\s*loads\s*\(/ nocase

        // type() constructor abuse for dynamic class/code creation
        $type_exec = /type\s*\(\s*['"]loading['"]\s*\)/ nocase

    condition:
        any of them
}

rule threat_runtime_obfuscation_js_mangling
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects JavaScript variable name mangling (_0x pattern) used by obfuscation tools"
        identifies = "threat.runtime.obfuscation.js.mangling"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"
        max_hits = 1
        path_include = "*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
        path_exclude = "dist/*,build/*,vendor/*,node_modules/*"

    strings:
        // _0x hex variable names (ASCII encoding)
        $hex_var_1 = /_0x[a-f0-9]{4,6}\b/
        $hex_var_2 = /const _0x[a-f0-9]{4,6}\s*=/
        $hex_var_3 = /function _0x[a-f0-9]{4,6}\s*\(/
        $hex_var_4 = /var _0x[a-f0-9]{4,6}\s*=/

        // UTF-16LE encoded _0x patterns (null bytes between ASCII chars)
        $utf16_hex_var = { 5F 00 30 00 78 00 [2-12] 3D 00 }  // _0x...=
        $utf16_function = { 66 00 75 00 6E 00 63 00 74 00 69 00 6F 00 6E 00 20 00 5F 00 30 00 78 00 }  // function _0x

    condition:
        3 of ($hex_var_*) or
        (#utf16_hex_var >= 5) or
        (#utf16_function >= 2)
}

rule threat_runtime_obfuscation_log_suppress
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects log/console suppression combined with obfuscated code, a common malware evasion pattern"
        identifies = "threat.runtime.obfuscation"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"
        max_hits = 1
        path_include = "*.js,*.ts,*.mjs,*.cjs"

    strings:
        // Console/log suppression (overriding with no-op)
        $suppress_log = /console\.log\s*=\s*function\s*\(\s*\)/ nocase
        $suppress_warn = /console\.warn\s*=\s*function\s*\(\s*\)/ nocase
        $suppress_error = /console\.error\s*=\s*function\s*\(\s*\)/ nocase
        $suppress_all = /console\s*=\s*\{/ nocase

        // Obfuscation indicators (present in same file)
        $hex_array = /\[\s*0x[0-9a-f]+\s*,\s*0x[0-9a-f]+\s*,\s*0x[0-9a-f]+/ nocase
        $fromCodePoint = "fromCodePoint" nocase
        $fromCharCode = "fromCharCode" nocase

    condition:
        any of ($suppress_*) and any of ($hex_array, $fromCodePoint, $fromCharCode)
}

rule threat_runtime_obfuscation_pyarmor
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects PyArmor obfuscation, a commercial tool commonly used to hide malicious code in Python packages"
        identifies = "threat.runtime.obfuscation.pyarmor"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "high"
        sophistication = "medium"

        path_include = "*.py,*.pyx,*.pyi,*.pth"
        max_hits = 1

    strings:
        // PyArmor bootstrap function call
        $pyarmor_bootstrap = /__pyarmor__\s*\(/

        // Legacy pytransform imports (PyArmor < 8.0)
        $legacy_import_from = /from\s+pytransform\s+import\s/
        $legacy_import = /import\s+pytransform\b/

        // PyArmor runtime initialization call
        $runtime_call = /pyarmor_runtime\s*\(/

        // Modern pyarmor_runtime package imports (PyArmor >= 8.0)
        $modern_import = /from\s+pyarmor_runtime\w*\s+import\s/

        // Armor enter/exit bytecode markers
        $armor_enter = "__armor_enter__"
        $armor_exit = "__armor_exit__"
        $pyarmor_enter = "__pyarmor_enter__"
        $pyarmor_exit = "__pyarmor_exit__"

        // PyArmor verification functions
        $check_armored = /check_armored\s*\(/
        $assert_armored = /assert_armored\s*\(/

    condition:
        any of them
}
rule threat_runtime_obfuscation_steganography
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects steganography decode followed by code execution"
        identifies = "threat.runtime.obfuscation.steganography"
        severity = "high"
        mitre_tactics = "defense-evasion"
        specificity = "low"
        sophistication = "high"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"
    strings:
        // Python - steganography libraries
        $py_stego_decode = "steganography.decode(" nocase
        $py_lsb_reveal = "lsb.reveal(" nocase
        $py_stegano = "stegano" nocase
        // bare exec(/eval( builtins, not ast.literal_eval()/img.eval() method calls
        $py_exec = /[^.\w]exec\s*\(/ nocase
        $py_eval = /[^.\w]eval\s*\(/ nocase

        // JavaScript/Node.js - steganography
        $js_steggy = "steggy.reveal(" nocase
        $js_stego = "stego.decode(" nocase
        $js_jimp = "Jimp.read(" nocase
        $js_getpixel = "getPixelColor(" nocase
        $js_buffer_concat = "Buffer.concat(" nocase
        $js_eval = "eval(" nocase

        // Image file references in code
        $img_png = /\.(png|jpg|jpeg|gif|bmp)['"]/ nocase

    condition:
        (any of ($py_stego_decode, $py_lsb_reveal, $py_stegano) and $img_png and ($py_exec or $py_eval)) or
        (any of ($js_*) and $img_png and $js_eval)
}

rule threat_runtime_obfuscation_unicode
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects unicode homoglyphs and uncommon characters used for obfuscation"
        identifies = "threat.runtime.obfuscation.unicode"
        severity = "medium"
        mitre_tactics = "defense-evasion"
        specificity = "low"
        sophistication = "medium"

	path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
        max_hits = 1
    strings:
        // Homoglyph obfuscation hides a lookalike char inside an ASCII word
        // (e.g. "pаypal" with a Cyrillic 'а'). Match a Cyrillic/Greek/math letter
        // adjacent to an ASCII letter; pure non-ASCII data (charset/i18n tables)
        // has no such boundary.

        // Cyrillic block (U+0400-U+047F) touching an ASCII letter
        $cyr_after_ascii  = /[a-zA-Z][\xd0\xd1][\x80-\xbf]/
        $cyr_before_ascii = /[\xd0\xd1][\x80-\xbf][a-zA-Z]/

        // Greek block (U+0380-U+03FF) touching an ASCII letter
        $grk_after_ascii  = /[a-zA-Z][\xce\xcf][\x80-\xbf]/
        $grk_before_ascii = /[\xce\xcf][\x80-\xbf][a-zA-Z]/

        // Mathematical Alphanumeric Symbols (U+1D400+) touching an ASCII letter
        $math_after_ascii  = /[a-zA-Z]\xf0\x9d[\x80-\xbf][\x80-\xbf]/
        $math_before_ascii = /\xf0\x9d[\x80-\xbf][\x80-\xbf][a-zA-Z]/

        // Zero-width characters wedged between ASCII letters (invisible splitter)
        $zw_between = /[a-zA-Z]\xe2\x80[\x8b-\x8d][a-zA-Z]/

    condition:
        any of them
}

rule threat_runtime_obfuscation
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects heavy obfuscation techniques commonly used by malware"
        identifies = "threat.runtime.obfuscation"
        severity = "low"
        mitre_tactics = "defense-evasion"
        specificity = "medium"
        sophistication = "low"

	path_include = "*.py,*.pyx,*.pyi,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go"
        max_hits = 1
    strings:
        // Base64 patterns (multiple long strings). Require an opening quote and a
        // long run so quoted SDK identifiers, doc links and long URLs (all well
        // under this length) are not counted as base64 payloads.
        $b64_1 = /['"][A-Za-z0-9+\/]{150,}={0,2}/

        // Hex-encoded strings
        $hex_1 = /\\x[0-9a-fA-F]{2}([\\x][0-9a-fA-F]{2}){20,}/

        // Unicode escape sequences
        $unicode_1 = /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/

        // Obfuscated variable names (obfuscator.io-style hex identifiers).
        // The previous [A-Z]{10,} branch also matched ALLCAPS words (license
        // text, constants like INTERACTIVE) and was a heavy false-positive source.
        $random_vars = /\b[a-zA-Z]_0x[a-f0-9]{4,6}\b/

        // String concatenation obfuscation
        $concat = /['"]\s*\+\s*['"]/

    condition:
        // One long base64 run is routinely a legitimate inline asset (image,
        // SRI integrity hash, embedded cert); require several before treating it
        // as obfuscation.
        (#b64_1 >= 3) or
        (#hex_1 >= 3) or
        (#random_vars >= 10 and #concat >= 20) or
        // \uXXXX runs recur in legitimate Unicode/charset tables, so require a
        // second obfuscation signal alongside them
        (#unicode_1 >= 2 and ($b64_1 or #concat >= 5 or #hex_1 >= 1))
}

rule threat_runtime_system_capture
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects screenshot capture of the user's display"
        identifies = "threat.runtime.screencapture"
        severity = "medium"
        mitre_tactics = "collection"
        specificity = "high"
        sophistication = "low"

        max_hits = 1
        path_include = "*.py,*.pyx,*.pyi,*.pth"

    strings:
        // Python - PIL ImageGrab
        $py_imagegrab = /\bImageGrab\s*\.\s*grab\s*\(/ nocase
        $py_pil_imagegrab = /\bPIL\s*\.\s*ImageGrab\s*\.\s*grab\s*\(/ nocase

        // Python - pyscreenshot library
        $py_pyscreenshot = /\bpyscreenshot\s*\.\s*grab\s*\(/ nocase

        // Python - pyautogui library
        $py_pyautogui = /\bpyautogui\s*\.\s*screenshot\s*\(/ nocase

        // Python - mss library
        $py_mss_grab = /\bmss\s*\.\s*mss\s*\(\s*\)\s*\.\s*grab\s*\(/ nocase
        $py_mss_with = /\bwith\s+\bmss\s*\.\s*mss\s*\(\s*\)\s+\bas\b/ nocase

        // Python - D3DShot (Windows DirectX screenshots)
        $py_d3dshot = /\bd3dshot\s*\.\s*create\s*\([^)]*\)\s*\.\s*screenshot\s*\(/ nocase

    condition:
        any of them
}

rule threat_runtime_self_propagation
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects worm/self-propagating behavior: package code that rewrites its own manifest and programmatically publishes copies to a package registry to spread"
        identifies = "threat.runtime.self-propagation"
        severity = "high"
        mitre_tactics = "lateral-movement"
        specificity = "high"
        sophistication = "low"

        max_hits = 1
        path_include = "*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs"

    strings:
        // Programmatically invoking a registry publish from package code
        // (npm/yarn/pnpm) -- a publish is a developer/CI action, not something
        // a package does to itself at runtime unless it is propagating.
        $publish = /['"`]\s*(npm|yarn|pnpm)\s+publish/ nocase

        // Rewriting its own manifest to clone itself under a new identity.
        $write_manifest = /\b(writeFile(Sync)?|writeJson(Sync)?|outputJson(Sync)?)\s*\(\s*['"`][^'"`]*package(-lock)?\.json/ nocase

        // Process-execution capability used to drive the publish.
        $cp_require = /require\s*\(\s*['"]child_process['"]\s*\)/
        $cp_exec = /\bexec(Sync|File|FileSync)?\s*\(/
        $cp_spawn = /\bspawn(Sync)?\s*\(/

    condition:
        $publish
        and $write_manifest
        and any of ($cp_require, $cp_exec, $cp_spawn)
}

rule threat_runtime_system_info
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects active collection of system information (hostname, platform, architecture, user)"
        identifies = "threat.runtime.system.info"
        severity = "low"
        mitre_tactics = "collection"
        specificity = "low"
        sophistication = "low"

        max_hits = 3
        path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,*.jsx,*.tsx,*.mjs,*.cjs,*.go,*.rb,*.gemspec"
    strings:
        // Python - require platform/socket module prefix for specificity
        $py_platform_system = /\bplatform\.system\s*\(\s*\)/ nocase
        $py_platform_machine = /\bplatform\.machine\s*\(\s*\)/ nocase
        $py_platform_node = /\bplatform\.node\s*\(\s*\)/ nocase
        $py_platform_uname = /\bplatform\.uname\s*\(\s*\)/ nocase
        $py_platform_architecture = /\bplatform\.architecture\s*\(\s*\)/ nocase
        $py_socket_gethostname = /\bsocket\.gethostname\s*\(\s*\)/ nocase
        $py_getpass_getuser = /\bgetpass\.getuser\s*\(\s*\)/ nocase

        // JavaScript - require os module prefix
        $js_os_platform = /\bos\.platform\s*\(\s*\)/ nocase
        $js_os_arch = /\bos\.arch\s*\(\s*\)/ nocase
        $js_os_hostname = /\bos\.hostname\s*\(\s*\)/ nocase
        $js_os_type = /\bos\.type\s*\(\s*\)/ nocase
        $js_os_userinfo = /\bos\.userInfo\s*\(\s*\)/ nocase
        $js_os_release = /\bos\.release\s*\(\s*\)/ nocase
        $js_os_homedir = /\bos\.homedir\s*\(\s*\)/ nocase
        $js_os_tmpdir = /\bos\.tmpdir\s*\(\s*\)/ nocase

        // Go - unique system info function calls
        $go_goos = /\bruntime\.GOOS\b/ nocase
        $go_goarch = /\bruntime\.GOARCH\b/ nocase
        $go_hostname = /\bos\.Hostname\s*\(\s*\)/ nocase

        // Ruby - system info
        $rb_socket_gethostname = /\bSocket\s*\.\s*gethostname\b/ nocase
        $rb_etc_getlogin = /\bEtc\s*\.\s*getlogin\b/ nocase
        $rb_etc_getpwuid = /\bEtc\s*\.\s*getpwuid\s*\(/ nocase

    condition:
        // Require 3+ distinct system info calls to indicate enumeration, not just platform check
        3 of them
}

rule threat_setup_import_aliasing
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects suspicious import aliasing of dangerous functions in setup.py"
        identifies = "threat.setup.import.aliasing"
        severity = "high"
        mitre_tactics = "execution"
        specificity = "high"
        sophistication = "medium"
        max_hits = 3
        path_include = "*/setup.py,setup.py"

    strings:
        // Aliased imports of process execution functions
        $from_os_system = /from\s+os\s+import\s+system\s+as\s/ nocase
        $from_os_popen = /from\s+os\s+import\s+popen\s+as\s/ nocase
        $from_subprocess = /from\s+subprocess\s+import\s+(call|run|Popen|check_output|check_call)\s+as\s/ nocase

        // Aliased imports of code execution
        $from_os_exec = /from\s+os\s+import\s+exec\w*\s+as\s/ nocase
        $from_builtins_exec = /from\s+builtins\s+import\s+exec\s+as\s/ nocase

        // Aliased imports of sys.executable (used to re-invoke Python)
        $from_sys_executable = /from\s+sys\s+import\s+executable\s+as\s/ nocase

        // Aliased imports of temp file creation (dropper pattern)
        $from_tempfile = /from\s+tempfile\s+import\s+NamedTemporaryFile\s+as\s/ nocase

        // Non-aliased but suspicious: importing dangerous functions directly in setup.py
        $from_os_system_direct = /from\s+os\s+import\s+system\b/ nocase
        $from_sys_exec_direct = /from\s+sys\s+import\s+executable\b/ nocase

    condition:
        // Aliased imports are very suspicious in setup.py
        any of ($from_os_system, $from_os_popen, $from_subprocess, $from_os_exec, $from_builtins_exec) or
        // sys.executable + tempfile combo is a classic dropper
        ($from_sys_executable and $from_tempfile) or
        // Aliased sys.executable alone is suspicious
        $from_sys_executable or
        // Direct import of os.system in setup.py combined with tempfile
        ($from_os_system_direct and $from_tempfile) or
        ($from_sys_exec_direct and $from_tempfile)
}

rule threat_setup_network_in_install
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects network operations or hostname/system info collection in setup.py, which is suspicious at install time"
        identifies = "threat.network.outbound"
        severity = "high"
        mitre_tactics = "exfiltration"
        specificity = "high"
        sophistication = "low"
        max_hits = 1
        path_include = "*/setup.py,setup.py"

    strings:
        // Network operations in setup.py
        $net_requests = /requests\.(get|post|put)\s*\(/ nocase
        $net_urllib_open = /urllib\.\w+\.urlopen\s*\(/ nocase
        $net_urllib_retrieve = /urllib\.\w+\.urlretrieve\s*\(/ nocase
        $net_http = /http\.client\.HTTP/ nocase
        $net_socket_connect = /socket\.\w*\.\s*connect\s*\(/ nocase
        $net_socket_create = /socket\.socket\s*\(/ nocase

        // Hostname / system info gathering in setup.py
        $sysinfo_hostname = /socket\.gethostname\s*\(\s*\)/ nocase
        $sysinfo_platform = /platform\.(system|machine|node|uname)\s*\(\s*\)/ nocase
        $sysinfo_getuser = /getpass\.getuser\s*\(\s*\)/ nocase
        $sysinfo_getlogin = /os\.getlogin\s*\(\s*\)/ nocase

        // Base64 decode of URLs (common obfuscation for exfil endpoints)
        $b64_decode = /base64\.\w*decode\s*\(/ nocase

        // Setup indicator
        $setup_call = /\bsetup\s*\(/ nocase
        $from_setuptools = /from\s+setuptools\s+import/ nocase
        $from_distutils = /from\s+distutils/ nocase

    condition:
        any of ($setup_call, $from_setuptools, $from_distutils) and
        (any of ($net_*) or ($b64_decode and any of ($sysinfo_*)))
}

rule threat_setup_suspicious_imports
{
    meta:
        author = "GuardDog Team, Datadog"
        description = "Detects suspicious imports in setup.py: network, system, or crypto libraries that have no place in a build script"
        identifies = "threat.setup.import.aliasing"
        severity = "high"
        mitre_tactics = "execution"
        specificity = "high"
        sophistication = "low"
        max_hits = 1
        path_include = "*/setup.py,setup.py"

    strings:
        // Network libraries (no legitimate reason in setup.py)
        $import_requests = /\bimport\s+requests\b/ nocase
        $import_urllib = /\bimport\s+urllib\b/ nocase
        $from_urllib = /\bfrom\s+urllib/ nocase
        $import_http = /\bimport\s+http\.client\b/ nocase
        $import_socket = /\bimport\s+socket\b/ nocase

        // Code execution / system
        $import_subprocess = /\bimport\s+subprocess\b/ nocase
        $import_ctypes = /\bimport\s+ctypes\b/ nocase
        $import_winreg = /\bimport\s+winreg\b/ nocase

        // Crypto/encoding (used for payload obfuscation)
        $import_base64 = /\bimport\s+base64\b/ nocase
        $import_marshal = /\bimport\s+marshal\b/ nocase
        $import_codecs = /\bimport\s+codecs\b/ nocase

        // Build script indicator
        $setup_call = /\bsetup\s*\(/ nocase

    condition:
        $setup_call and (
            any of ($import_requests, $import_urllib, $from_urllib, $import_http, $import_socket) or
            (any of ($import_subprocess, $import_ctypes, $import_winreg) and
             any of ($import_requests, $import_urllib, $from_urllib, $import_http, $import_socket,
                     $import_base64, $import_marshal, $import_codecs))
        )
}
