#!/usr/bin/env bash
# Prepare only a fresh, disposable GitHub-hosted VM for Transaction v2.
# Preserve the archive's strict backend preflight. Never infer absent API data.
set -Eeuo pipefail
[[ $EUID == 0 && $GITHUB_ACTIONS == true && $RUNNER_ENVIRONMENT == github-hosted ]] || exit 78
[[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} && -z ${DOCKER_API_VERSION:-} ]] || exit 78
[[ $(docker context show) == default ]]
[[ $(docker context inspect default --format '{{.Endpoints.docker.Host}}') == unix:///var/run/docker.sock ]]
[[ -z $(docker ps -aq) ]] || { echo 'REFUSE: existing containers'; exit 1; }
docker_start_diagnostics() {
  echo 'Docker startup diagnostic (read-only, redacted categories)' >&2
  timeout 10 systemctl show docker.service containerd.service docker.socket \
    -p Id -p LoadState -p ActiveState -p SubState -p Result \
    -p ExecMainCode -p ExecMainStatus -p NRestarts --no-pager >&2 || true
  timeout 10 dpkg-query -W -f='${Package} ${Version}\n' docker-ce docker-ce-cli containerd.io >&2 || true
  # Do not publish journal messages, which may contain addresses or paths.
  # Journal access is bounded; unknown errors remain explicitly unclassified.
  if ! timeout 10 journalctl -b -u docker.service -u containerd.service -u docker.socket \
      --since '-5 minutes' -n 160 --no-pager -o cat 2>/dev/null | python3 -c '
import re,sys
patterns={
"configuration":r"failed to (load|read|decode|parse).*config|invalid.*(configuration|directive)|specified both as a flag|unknown (flag|option|directive)",
"containerd":r"failed to (connect|dial|start).*containerd|containerd.*(not running|unavailable|deadline exceeded)|failed to start containerd",
"firewall":r"iptables.*(failed|error|permission denied|not found)|failed.*(iptables|nftables|nat chain)|failed to register.*bridge",
"storage":r"error initializing graphdriver|failed to mount overlay|failed to (initialize|load).*snapshotter|storage driver.*(error|failed)|no space left on device|read-only file system",
"socket":r"address already in use|failed to (listen|bind)|no sockets found via socket activation",
"pidfile":r"pid file.*(exists|found)|process with pid.*running",
"permissions":r"permission denied|operation not permitted",
"start_limit":r"start request repeated too quickly|start-limit-hit",
"timeout":r"deadline exceeded|timed out|timeout",
"service_exit":r"main process exited|failed with result|failed to start|error starting daemon"
}
rows=sys.stdin.read().splitlines()
print("journal_lines="+str(len(rows)))
hits={k:sum(bool(re.search(p,line,re.I)) for line in rows) for k,p in patterns.items()}
print("journal_categories="+(",".join(k+":"+str(v) for k,v in hits.items() if v) or "unclassified"))
' >&2; then
    echo 'Docker startup journal classification unavailable' >&2
  fi
  return 0
}
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
  # Signed index/CDN synchronization can transiently fail. Retry the
  # complete authenticated update; never install using a failed update.
  updated=0
  for attempt in 1 2 3; do
    if apt-get "${opts[@]}" -o APT::Update::Error-Mode=any update; then
      updated=1; break
    fi
    echo "Docker signed index update failed attempt=$attempt" >&2
    if ((attempt < 3)); then sleep "$((attempt*5))"; fi
  done
  [[ $updated == 1 ]] || { echo 'Docker signed index unavailable after bounded retry' >&2; exit 100; }
  # Exact signed version; fail rather than substitute an unreviewed package.
  apt-cache "${opts[@]}" madison docker-ce docker-ce-cli
  DEBIAN_FRONTEND=noninteractive apt-get "${opts[@]}" install -y --no-install-recommends --allow-downgrades "docker-ce=$version" "docker-ce-cli=$version"
  # Diagnose the original failure before another action can obscure it.
  # Only public, synthetic hosted-runner metadata; no raw logs/config/env.
  if systemctl restart docker; then
    :
  else
    rc=$?
    echo "Docker preparation restart failed rc=$rc" >&2
    docker_start_diagnostics
    exit "$rc"
  fi
fi
docker version --format 'Target client={{.Client.Version}} server={{.Server.Version}} API={{.Server.APIVersion}}'
[[ $(docker version --format '{{.Server.Version}}') == "$target" && $(docker version --format '{{.Client.Version}}') == "$target" ]]
docker info --format '{{json .}}' | python3 -c 'import json,sys; d=json.load(sys.stdin); f=d.get("FirewallBackend"); print("V2 reported firewall backend:",f); assert isinstance(f,dict) and f.get("Driver")=="iptables", "explicit iptables backend required"'
iptables --version | grep -F nf_tables
iptables-nft -t nat -S DOCKER | grep -Fx -- '-N DOCKER'
echo 'V2 environment PASS: exact target Docker version and explicit backend'
