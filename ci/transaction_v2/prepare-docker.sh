#!/usr/bin/env bash
# Prepare only a fresh, disposable GitHub-hosted VM for Transaction v2.
# Preserve the archive's strict backend preflight. Never infer absent API data.
set -Eeuo pipefail
[[ $EUID == 0 && $GITHUB_ACTIONS == true && $RUNNER_ENVIRONMENT == github-hosted ]] || exit 78
[[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} && -z ${DOCKER_API_VERSION:-} ]] || exit 78
[[ $(docker context show) == default ]]
[[ $(docker context inspect default --format '{{.Endpoints.docker.Host}}') == unix:///var/run/docker.sock ]]
[[ -z $(docker ps -aq) ]] || { echo 'REFUSE: existing containers'; exit 1; }
target='29.1.3'
version="5:$target-1~ubuntu.24.04~noble"
docker version --format 'Initial client={{.Client.Version}} server={{.Server.Version}} API={{.Server.APIVersion}}'
# The release must be obtained from the official authenticated APT repository.
if [[ $(docker version --format '{{.Server.Version}}') != "$target" || $(docker version --format '{{.Client.Version}}') != "$target" ]]; then
  . /etc/os-release
  [[ $ID == ubuntu && $VERSION_CODENAME == noble && $(dpkg --print-architecture) == amd64 ]]
  # Verify official signing key, not a generic unsigned repository or a third-party mirror.
  key=$(mktemp)
  source_dir=$(mktemp -d)
  trap 'rm -f "$key"; rm -rf "$source_dir"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --max-time 60 https://download.docker.com/linux/ubuntu/gpg -o "$key"
  gpg --batch --show-keys --with-colons "$key" | awk -F: '$1=="fpr"{print $10;exit}' | grep -Fxq '9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
  chmod 644 "$key"
  chmod 755 "$source_dir"
  printf 'deb [arch=amd64 signed-by=%s] https://download.docker.com/linux/ubuntu noble stable\n' "$key" > "$source_dir/docker.list"
  opts=(-o "Dir::Etc::sourcelist=$source_dir/docker.list" -o 'Dir::Etc::sourceparts=-' -o 'APT::Get::List-Cleanup=0')
  apt-get "${opts[@]}" update
  # Exact signed version; fail rather than substitute an unreviewed package.
  apt-cache "${opts[@]}" madison docker-ce docker-ce-cli
  DEBIAN_FRONTEND=noninteractive apt-get "${opts[@]}" install -y --no-install-recommends --allow-downgrades "docker-ce=$version" "docker-ce-cli=$version"
  systemctl restart docker
fi
docker version --format 'Target client={{.Client.Version}} server={{.Server.Version}} API={{.Server.APIVersion}}'
[[ $(docker version --format '{{.Server.Version}}') == "$target" && $(docker version --format '{{.Client.Version}}') == "$target" ]]
docker info --format '{{json .}}' | python3 -c 'import json,sys; d=json.load(sys.stdin); f=d.get("FirewallBackend"); print("V2 reported firewall backend:",f); assert isinstance(f,dict) and f.get("Driver")=="iptables", "explicit iptables backend required"'
iptables --version | grep -F nf_tables
iptables-nft -t nat -S DOCKER | grep -Fx -- '-N DOCKER'
echo 'V2 environment PASS: exact target Docker version and explicit backend'
