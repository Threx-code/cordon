#!/bin/sh
# Regenerates the real-world Ansible conformance case: ansible-galaxy installs a project's
# collections (a version range, an exact pin, one with its own collection dependency, one from
# git) into ./collections and its roles (from Galaxy and from git) into ./roles. The installed
# state -- each collection's MANIFEST.json and each role's .galaxy_install_info, the files a
# project commits so plays run the same everywhere -- is kept, without the content. ansible-galaxy's
# own `collection list` and `role list` are the authoritative inventory. No play is run. Run inside
# Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim sh /conformance/generate/ansible.sh
set -eu
OUT=/conformance/cases/ansible/real-project
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq git >/dev/null 2>&1
pip install --quiet --disable-pip-version-check "ansible-core>=2.17,<2.19" >/dev/null 2>&1
rm -rf /tmp/a && mkdir -p /tmp/a && cd /tmp/a
cat > requirements.yml <<'EOF'
collections:
  - name: community.general
    version: ">=9.0.0,<10.0.0"
  - name: ansible.posix
    version: 1.5.4
  - name: community.docker
    version: 3.13.0
  - name: https://github.com/ansible-collections/community.crypto.git
    type: git
    version: 2.22.0

roles:
  - name: geerlingguy.docker
    version: 7.4.1
  - name: geerlingguy.pip
    src: https://github.com/geerlingguy/ansible-role-pip.git
    scm: git
    version: 3.0.3
EOF
ansible-galaxy collection install -r requirements.yml -p ./collections >/tmp/galaxy.log 2>&1 || { tail -20 /tmp/galaxy.log; exit 1; }
ansible-galaxy role install -r requirements.yml -p ./roles >>/tmp/galaxy.log 2>&1 || { tail -20 /tmp/galaxy.log; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT"
cp requirements.yml "$OUT/"
for manifest in collections/ansible_collections/*/*/MANIFEST.json; do
  mkdir -p "$OUT/$(dirname "$manifest")"
  cp "$manifest" "$OUT/$manifest"
done
for info in roles/*/meta/.galaxy_install_info; do
  mkdir -p "$OUT/$(dirname "$info")"
  cp "$info" "$OUT/$info"
  cp "$(dirname "$info")/main.yml" "$OUT/$(dirname "$info")/main.yml" 2>/dev/null || true
done

ansible-galaxy collection list -p ./collections --format json >/tmp/collections.json 2>>/tmp/galaxy.log
ansible-galaxy role list -p ./roles >/tmp/roles.txt 2>>/tmp/galaxy.log
python3 - "$OUT" <<'PY'
import json, re, sys
found = set()
for path, listed in json.load(open("/tmp/collections.json")).items():
    if path.startswith("/tmp/a/collections"):
        for name, info in listed.items():
            found.add(f"{name}@{info['version']}")
for line in open("/tmp/roles.txt"):
    match = re.match(r"^- ([\w.\-]+), v?([^\s]+)", line.strip())
    if match:
        found.add(f"{match.group(1)}@{match.group(2)}")
json.dump({"tool": "ansible-galaxy collection list and role list", "packages": sorted(found)}, open(f"{sys.argv[1]}/authoritative.json", "w"), indent=1)
print("\n".join(sorted(found)))
PY
echo done
