#!/usr/bin/env bash
# Disposable GitHub-hosted VM ONLY.
set -Eeuo pipefail
umask 077
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID == 0 ]] || { echo 'REFUSE: not GitHub-hosted runner'; exit 78; }
cd "$(dirname "$0")/.."
ROOT=$PWD; WORK=$(mktemp -d); chmod 755 "$WORK"
TABLE=0; VETH=0; NS=0; NET1=''; NET2=''; C1=''; C2='';
cleanup() {
  rc=$?; trap - EXIT; set +e
  bad=0
  for id in "$C1" "$C2"; do [[ -z $id ]] || docker rm -f "$id" >/dev/null || bad=1; done
  for id in "$NET1" "$NET2"; do [[ -z $id ]] || docker network rm "$id" >/dev/null || bad=1; done
  if ((bad == 0)); then ((TABLE == 0)) || nft delete table inet vpn_benchmark || bad=1; else echo 'FAIL: retain firewall; cleanup incomplete'; fi
  ((NS == 0)) || ip netns del vb-client || bad=1
  ((VETH == 0)) || ip link del vb-wan 2>/dev/null || true
  rm -rf -- "$WORK"
  if ((bad)); then exit 1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for cmd in docker nft ip openssl python3 curl git timeout; do command -v "$cmd" >/dev/null; done
nft list table inet vpn_benchmark >/dev/null 2>&1 && { echo 'Existing table'; exit 1; }
for n in vb-sbox vb-mita; do if docker network inspect "$n" >/dev/null 2>&1; then echo 'Existing network'; exit 1; fi; done
for n in vpn-test-singbox vpn-test-mita; do if docker inspect "$n" >/dev/null 2>&1; then echo 'Existing container'; exit 1; fi; done
ip netns add vb-client; NS=1
ip link add vb-wan type veth peer name vb-peer; VETH=1
ip link set vb-peer netns vb-client
ip addr add 198.18.254.1/29 dev vb-wan; ip link set vb-wan up
ip -n vb-client addr add 198.18.254.2/29 dev vb-peer
ip -n vb-client addr add 198.18.254.3/29 dev vb-peer
ip -n vb-client link set lo up; ip -n vb-client link set vb-peer up
SBOX_REF=ghcr.io/sagernet/sing-box@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279
docker pull --platform linux/amd64 "$SBOX_REF"
SBOX=$(docker image inspect "$SBOX_REF" --format '{{.Id}}')
docker image inspect "$SBOX" --format 'sing-box digests={{json .RepoDigests}}'
docker run --rm --network none --entrypoint sing-box "$SBOX" version
git clone --depth 1 --branch v3.39.0 https://github.com/enfein/mieru.git "$WORK/mieru"
MITA_REV=$(git -C "$WORK/mieru" rev-parse HEAD)
echo "Mita revision: $MITA_REV"
[[ $MITA_REV == bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06 ]] || { echo 'FAIL: unexpected Mita source revision'; exit 1; }
docker build -t vb-mita-lab -f "$WORK/mieru/deployments/docker/mita/Dockerfile" "$WORK/mieru"
MITA=$(docker image inspect vb-mita-lab --format '{{.Id}}'); echo "Mita image ID: $MITA"
# Resolve the image's own service account, without running as root.
MITA_IDS=$(docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --read-only --entrypoint /bin/sh "$MITA" -ec 'printf "%s %s\n" "$(id -u mita)" "$(id -g mita)"')
read -r VB_MITA_UID VB_MITA_GID <<< "$MITA_IDS"
[[ $VB_MITA_UID =~ ^[1-9][0-9]*$ && $VB_MITA_GID =~ ^[1-9][0-9]*$ ]] || { echo 'FAIL: invalid Mita service account'; exit 1; }
export VB_MITA_UID VB_MITA_GID
printf 'Mita image service account: UID=%s GID=%s\n' "$VB_MITA_UID" "$VB_MITA_GID"
KEY_OUT=$(docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --entrypoint sing-box "$SBOX" generate reality-keypair)
export VB_KEY=$(printf '%s\n' "$KEY_OUT" | sed -n 's/^PrivateKey:[[:space:]]*//p')
[[ -n $VB_KEY ]]; unset KEY_OUT
export VB_WORK=$WORK
python3 ci/render.py
unset VB_KEY
for file in sing-box-acme.json sing-box-lab.json; do
  docker run --rm --network none --entrypoint sing-box -v "$WORK:/lab:ro" "$SBOX" check -c "/lab/$file" >/dev/null 2>&1 || { echo "FAIL: native sing-box check $file"; exit 1; }
done
nft -c -f "$WORK/firewall.nft"
nft -f "$WORK/firewall.nft"; TABLE=1
NET1=$(docker network create --label vpn-benchmark=ci --driver bridge --subnet 172.30.241.0/28 --opt com.docker.network.bridge.name=br-vb-sbox vb-sbox)
NET2=$(docker network create --label vpn-benchmark=ci --driver bridge --subnet 172.30.242.0/28 --opt com.docker.network.bridge.name=br-vb-mita vb-mita)
for net in "$NET1" "$NET2"; do [[ $(docker network inspect "$net" --format '{{.EnableIPv6}}') == false ]]; done
C1=$(docker create --name vpn-test-singbox --label vpn-benchmark=ci --pull never --restart no --network vb-sbox --ip 172.30.241.2 --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --cpus .75 --memory 384m --memory-swap 384m --pids-limit 128 -p 198.18.254.1:18443:18443/tcp -p 198.18.254.1:18445:18445/tcp --mount type=bind,src="$WORK/sing-box-lab.json",dst=/config.json,readonly --mount type=bind,src="$WORK/cert.pem",dst=/lab/cert.pem,readonly --mount type=bind,src="$WORK/key.pem",dst=/lab/key.pem,readonly --mount type=bind,src="$ROOT/candidate/resolv.conf",dst=/etc/resolv.conf,readonly --entrypoint sing-box "$SBOX" run -c /config.json)
C2=$(docker create --name vpn-test-mita --label vpn-benchmark=ci --pull never --restart no --network vb-mita --ip 172.30.242.2 --user "$VB_MITA_UID:$VB_MITA_GID" --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --tmpfs /var/run/mita:rw,nosuid,nodev,noexec,uid=$VB_MITA_UID,gid=$VB_MITA_GID,mode=0700 --tmpfs /etc/mita:rw,nosuid,nodev,noexec,uid=$VB_MITA_UID,gid=$VB_MITA_GID,mode=0700 --tmpfs /var/lib/mita:rw,nosuid,nodev,noexec,uid=$VB_MITA_UID,gid=$VB_MITA_GID,mode=0700 --cpus .75 --memory 256m --memory-swap 256m --pids-limit 128 -p 198.18.254.1:18444:18444/tcp --mount type=bind,src="$WORK/mita.json",dst=/config.json,readonly --mount type=bind,src="$ROOT/candidate/resolv.conf",dst=/etc/resolv.conf,readonly -e MITA_UDS_PATH=/var/run/mita/mita.sock -e MITA_CONFIG_JSON_FILE=/config.json --entrypoint /usr/local/bin/mita "$MITA" run)
diagnose_container() {
  local id=$1 name=$2
  printf 'Diagnostics for %s\n' "$name"
  docker inspect --format 'status={{.State.Status}} running={{.State.Running}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} user={{.Config.User}}' "$id" || true
  docker logs --tail 200 "$id" 2>&1 | python3 ci/diagnose.py || echo 'Diagnostic classifier unavailable (raw logs withheld)'
}
start_container() {
  local id=$1 name=$2
  if ! docker start "$id" >/dev/null 2>"$WORK/start-error"; then
    echo "FAIL: Docker start $name"
    python3 ci/diagnose.py <"$WORK/start-error"
    diagnose_container "$id" "$name"
    return 1
  fi
}
wait_ready() {
  local id=$1 name=$2; shift 2
  local attempt running port ready
  for attempt in {1..12}; do
    running=$(docker inspect --format '{{.State.Running}}' "$id")
    if [[ $running != true ]]; then
      echo "FAIL: $name exited during startup"
      diagnose_container "$id" "$name"
      return 1
    fi
    ready=1
    if [[ $name == vpn-test-mita ]]; then
      # Mita can have a live daemon but no active proxy.
      if ! timeout 3 docker exec "$id" /usr/local/bin/mita status 2>&1 | grep -Fq 'mita server status is "RUNNING"'; then ready=0; fi
    fi
    for port in "$@"; do
      if ! ip netns exec vb-client python3 ci/probe.py 198.18.254.2 198.18.254.1 "$port" allow >/dev/null 2>&1; then ready=0; fi
    done
    if ((ready)); then
      echo "PASS: $name startup and listener readiness"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: $name readiness timeout"
  diagnose_container "$id" "$name"
  return 1
}
start_container "$C1" vpn-test-singbox
wait_ready "$C1" vpn-test-singbox 18443 18445
start_container "$C2" vpn-test-mita
wait_ready "$C2" vpn-test-mita 18444
for port in 18443 18444 18445; do
  ip netns exec vb-client python3 ci/probe.py 198.18.254.2 198.18.254.1 "$port" allow
  ip netns exec vb-client python3 ci/probe.py 198.18.254.3 198.18.254.1 "$port" deny
done
nft list table inet vpn_benchmark
docker stop "$C1" "$C2" >/dev/null
for port in 18443 18444 18445; do ip netns exec vb-client python3 ci/probe.py 198.18.254.2 198.18.254.1 "$port" deny; done
echo 'PASS: native checks, startup, TCP ingress allow/deny and stopped endpoints. Other acceptance tests remain pending.'
