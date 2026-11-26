#!/usr/bin/env bash
# Disposable GitHub-hosted VM ONLY.
set -Eeuo pipefail
umask 077
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID == 0 ]] || { echo 'REFUSE: not GitHub-hosted runner'; exit 78; }
cd "$(dirname "$0")/.."
ROOT=$PWD; WORK=$(mktemp -d); chmod 755 "$WORK"
TABLE=0; VETH=0; NS=0; NET1=''; NET2=''; C1=''; C2=''; FIXTURE=''; HOST_FIXTURE='';
cleanup() {
  rc=$?; trap - EXIT; set +e
  bad=0
  for id in "$C1" "$C2"; do [[ -z $id ]] || docker rm -f "$id" >/dev/null || bad=1; done
  for id in "$NET1" "$NET2"; do [[ -z $id ]] || docker network rm "$id" >/dev/null || bad=1; done
  if ((bad == 0)); then ((TABLE == 0)) || nft delete table inet vpn_benchmark || bad=1; else echo 'FAIL: retain firewall; cleanup incomplete'; fi
  for pid in "$FIXTURE" "$HOST_FIXTURE"; do
    if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  ((NS == 0)) || ip netns del vb-client || bad=1
  ((VETH == 0)) || ip link del vb-wan 2>/dev/null || true
  rm -rf -- "$WORK"
  if ((bad)); then exit 1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for cmd in docker nft ip openssl python3 curl git timeout tar sha256sum nsenter setpriv sysctl; do command -v "$cmd" >/dev/null; done
nft list table inet vpn_benchmark >/dev/null 2>&1 && { echo 'Existing table'; exit 1; }
for n in vb-sbox vb-mita; do if docker network inspect "$n" >/dev/null 2>&1; then echo 'Existing network'; exit 1; fi; done
for n in vpn-test-singbox vpn-test-mita; do if docker inspect "$n" >/dev/null 2>&1; then echo 'Existing container'; exit 1; fi; done
# Create the transient veth only after downloads, builds and Docker network creation.
# Fixed client releases; fetched by the runner, never by the isolated proxy.
curl -fsSL --max-time 120 https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz -o "$WORK/sbox.tar.gz"
echo "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968  $WORK/sbox.tar.gz" | sha256sum -c -
mkdir "$WORK/sbox-client"
tar -xzf "$WORK/sbox.tar.gz" -C "$WORK/sbox-client"
curl -fsSL --max-time 120 https://github.com/enfein/mieru/releases/download/v3.39.0/mieru_3.39.0_linux_amd64.tar.gz -o "$WORK/mieru.tar.gz"
echo "81f549ffd7be2df6958b1051aad10e58884889d92e691c1e43822c42091d1dfe  $WORK/mieru.tar.gz" | sha256sum -c -
mkdir "$WORK/mieru-client"
tar -xzf "$WORK/mieru.tar.gz" -C "$WORK/mieru-client"
SBOX_CLIENT=$(find "$WORK/sbox-client" -type f -name sing-box -print -quit)
MIERU_CLIENT=$(find "$WORK/mieru-client" -type f -name mieru -print -quit)
[[ -x $SBOX_CLIENT && -x $MIERU_CLIENT ]]
chmod a+rx "$WORK/sbox-client" "$WORK/mieru-client"
find "$WORK/sbox-client" "$WORK/mieru-client" -type d -exec chmod a+rx {} +
export SBOX_CLIENT MIERU_CLIENT
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
export VB_PUB=$(printf '%s\n' "$KEY_OUT" | sed -n 's/^PublicKey:[[:space:]]*//p')
[[ -n $VB_KEY && -n $VB_PUB ]]; unset KEY_OUT
export VB_WORK=$WORK
python3 ci/render.py
unset VB_KEY VB_PUB
for file in sing-box-acme.json sing-box-lab.json; do
  docker run --rm --network none --entrypoint sing-box -v "$WORK:/lab:ro" "$SBOX" check -c "/lab/$file" >/dev/null 2>&1 || { echo "FAIL: native sing-box check $file"; exit 1; }
done
nft -c -f "$WORK/firewall-original.nft"
nft -c -f "$WORK/firewall.nft"
nft -f "$WORK/firewall.nft"; TABLE=1
NET1=$(docker network create --label vpn-benchmark=ci --driver bridge --subnet 172.30.241.0/28 --opt com.docker.network.bridge.name=br-vb-sbox vb-sbox)
NET2=$(docker network create --label vpn-benchmark=ci --driver bridge --subnet 172.30.242.0/28 --opt com.docker.network.bridge.name=br-vb-mita vb-mita)
for net in "$NET1" "$NET2"; do [[ $(docker network inspect "$net" --format '{{.EnableIPv6}}') == false ]]; done
# Use only newly created lab interfaces; never reconfigure an existing interface.
if ip link show vb-wan >/dev/null 2>&1 || ip link show vb-peer >/dev/null 2>&1 || ip netns list | grep -Eq '^vb-client([[:space:]]|$)'; then
  echo 'FAIL: existing lab link or namespace'; exit 1
fi
ip netns add vb-client; NS=1
ip link add vb-wan type veth peer name vb-peer; VETH=1
ip link set vb-peer netns vb-client
ip addr add 198.18.254.1/29 dev vb-wan; ip link set vb-wan up
ip -n vb-client addr add 198.18.254.2/29 dev vb-peer
ip -n vb-client addr add 198.18.254.3/29 dev vb-peer
ip -n vb-client link set lo up; ip -n vb-client link set vb-peer up
[[ -z $(ip -n vb-client route show default) && -z $(ip -n vb-client -6 route show default) ]]
VB_WAN_IFINDEX=$(cat /sys/class/net/vb-wan/ifindex)
lab_addresses() {
  # Assert interface identity and exact local addresses; print only fixed lab metadata.
  [[ $(cat /sys/class/net/vb-wan/ifindex) == "$VB_WAN_IFINDEX" ]] || return 1
  ip -j -4 addr show dev vb-wan | python3 -c 'import json,sys; sys.exit(not any(a.get("local")=="198.18.254.1" and a.get("prefixlen")==29 for i in json.load(sys.stdin) for a in i.get("addr_info",[])))' || return 1
  ip -n vb-client -j -4 addr show dev vb-peer | python3 -c 'import json,sys; a={x.get("local") for i in json.load(sys.stdin) for x in i.get("addr_info",[]) if x.get("prefixlen")==29}; sys.exit(not {"198.18.254.2","198.18.254.3"}<=a)' || return 1
  [[ -z $(ip -n vb-client route show default) && -z $(ip -n vb-client -6 route show default) ]]
}
require_lab_addresses() {
  local phase=$1
  if lab_addresses; then echo "PASS: synthetic interface addresses ($phase)"; return 0; fi
  echo "FAIL: synthetic interface addresses ($phase)"
  return 1
}
require_lab_addresses created
# Extra fixture addresses and processes are installed only after ingress readiness.
C1=$(docker create --name vpn-test-singbox --label vpn-benchmark=ci --pull never --restart no --network vb-sbox --ip 172.30.241.2 --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --cpus .75 --memory 384m --memory-swap 384m --pids-limit 128 -p 198.18.254.1:18443:18443/tcp -p 198.18.254.1:18445:18445/tcp --mount type=bind,src="$WORK/sing-box-lab.json",dst=/config.json,readonly --mount type=bind,src="$WORK/cert.pem",dst=/lab/cert.pem,readonly --mount type=bind,src="$WORK/key.pem",dst=/lab/key.pem,readonly --mount type=bind,src="$WORK/resolv.conf",dst=/etc/resolv.conf,readonly --entrypoint sing-box "$SBOX" run -c /config.json)
C2=$(docker create --name vpn-test-mita --label vpn-benchmark=ci --pull never --restart no --network vb-mita --ip 172.30.242.2 --user "$VB_MITA_UID:$VB_MITA_GID" --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --tmpfs /var/run/mita:rw,nosuid,nodev,noexec,uid=$VB_MITA_UID,gid=$VB_MITA_GID,mode=0700 --tmpfs /etc/mita:rw,nosuid,nodev,noexec,uid=$VB_MITA_UID,gid=$VB_MITA_GID,mode=0700 --tmpfs /var/lib/mita:rw,nosuid,nodev,noexec,uid=$VB_MITA_UID,gid=$VB_MITA_GID,mode=0700 --cpus .75 --memory 256m --memory-swap 256m --pids-limit 128 -p 198.18.254.1:18444:18444/tcp --mount type=bind,src="$WORK/mita.json",dst=/config.json,readonly --mount type=bind,src="$WORK/resolv.conf",dst=/etc/resolv.conf,readonly -e MITA_UDS_PATH=/var/run/mita/mita.sock -e MITA_CONFIG_JSON_FILE=/config.json --entrypoint /usr/local/bin/mita "$MITA" run)
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
    # Recheck the address and failed ports after the daemon error, without raw logs.
    if [[ $name == vpn-test-singbox ]]; then check_bind 18443 18445 || true; else check_bind 18444 || true; fi
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
check_bind() {
  # Do not use IP_FREEBIND, wildcard listeners, or public interfaces.
  # Only the owned synthetic interface and ports are checked.
  require_lab_addresses before-bind || return 1
  python3 - "$@" <<'PY'
import errno, socket, sys
for value in sys.argv[1:]:
    port=int(value)
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("198.18.254.1",port))
        except OSError as exc:
            print("FAIL: synthetic bind",port,"errno",exc.errno,errno.errorcode.get(exc.errno,"UNKNOWN"),flush=True)
            sys.exit(1)
        print("PASS: synthetic bind",port,flush=True)
PY
}
require_lab_addresses containers-created
check_bind 18443 18445
start_container "$C1" vpn-test-singbox
wait_ready "$C1" vpn-test-singbox 18443 18445
require_lab_addresses singbox-ready
check_bind 18444
start_container "$C2" vpn-test-mita
wait_ready "$C2" vpn-test-mita 18444
require_lab_addresses mita-ready
for port in 18443 18444 18445; do
  ip netns exec vb-client python3 ci/probe.py 198.18.254.2 198.18.254.1 "$port" allow
  ip netns exec vb-client python3 ci/probe.py 198.18.254.3 198.18.254.1 "$port" deny
done
if [[ ${VB_FAIL_AFTER_START:-0} == 1 ]]; then
  echo 'FAULT_INJECTED: both containers ready; exiting with code 42'
  exit 42
fi
ip -n vb-client addr add 198.18.254.4/29 dev vb-peer
ip -n vb-client addr add 198.18.254.5/29 dev vb-peer
ip -n vb-client addr add 198.18.254.6/29 dev vb-peer
# IPv6 fixture is local to the isolated veth, not a public service.
sysctl -qw net.ipv6.conf.vb-wan.disable_ipv6=0
ip netns exec vb-client sysctl -qw net.ipv6.conf.vb-peer.disable_ipv6=0
ip -6 addr add fd42:198:18::1/64 dev vb-wan nodad
ip -n vb-client -6 addr add fd42:198:18::4/64 dev vb-peer nodad
[[ -z $(ip -n vb-client route show default) && -z $(ip -n vb-client -6 route show default) ]]
ip netns exec vb-client python3 ci/fixtures.py "$WORK" wan >"$WORK/wan-fixture.log" 2>&1 &
FIXTURE=$!
python3 ci/fixtures.py "$WORK" host >"$WORK/host-fixture.log" 2>&1 &
HOST_FIXTURE=$!
for attempt in {1..30}; do
  if [[ -f $WORK/wan.ready && -f $WORK/host.ready ]]; then break; fi
  kill -0 "$FIXTURE" && kill -0 "$HOST_FIXTURE" || { echo 'FAIL: fixture exited'; exit 1; }
  sleep .2
done
[[ -f $WORK/wan.ready && -f $WORK/host.ready ]] || { echo 'FAIL: fixture readiness'; exit 1; }
require_lab_addresses fixtures-ready
export VB_C1=$C1 VB_C2=$C2
python3 ci/functional.py "$WORK"
require_lab_addresses functional-complete
nft list table inet vpn_benchmark
docker stop "$C1" "$C2" >/dev/null
for port in 18443 18444 18445; do ip netns exec vb-client python3 ci/probe.py 198.18.254.2 198.18.254.1 "$port" deny; done
echo 'PASS: native checks, startup, TCP ingress allow/deny and stopped endpoints. Functional checks completed. ACME and production acceptance remain pending.'
