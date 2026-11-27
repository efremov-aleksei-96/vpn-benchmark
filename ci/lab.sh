#!/usr/bin/env bash
# Disposable GitHub-hosted VM ONLY.
set -Eeuo pipefail
umask 077
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID == 0 ]] || { echo 'REFUSE: not GitHub-hosted runner'; exit 78; }
cd "$(dirname "$0")/.."
ROOT=$PWD; WORK=$(mktemp -d); chmod 755 "$WORK"
FIXTURE=''; HOST_FIXTURE=''; MATRIX_ACTIVE=0
cleanup() {
  rc=$?; trap - EXIT; set +e
  bad=0
  for pid in "$FIXTURE" "$HOST_FIXTURE"; do
    if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  if [[ -f $WORK/lifecycle.json ]]; then python3 ci/lifecycle.py rollback "$WORK" || bad=1; fi
  if ((MATRIX_ACTIVE)); then
    echo 'FAIL: lifecycle matrix incomplete; retain private journal in disposable VM'
    bad=1
  fi
  if ((bad == 0)) && [[ -f $WORK/legacy-guard.json ]]; then python3 ci/legacy_guard_ci.py remove "$WORK" || bad=1; fi
  if ((bad)); then echo 'FAIL: cleanup incomplete; no broad cleanup attempted'; exit 1; fi
  rm -rf -- "$WORK"
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
export VB_SBOX_IMAGE=$SBOX VB_MITA_IMAGE=$MITA
if [[ ${VB_RELEASE_V161:-0} == 1 ]]; then
  MATRIX_ACTIVE=1
  python3 ci/release_v161/acceptance.py "$WORK"
  MATRIX_ACTIVE=0
  exit 0
fi
if [[ ${VB_TRANSACTION_V2:-0} == 1 ]]; then
  MATRIX_ACTIVE=1
  python3 ci/transaction_v2/integration.py "$WORK"
  MATRIX_ACTIVE=0
  exit 0
fi
python3 ci/legacy_guard_ci.py install "$WORK"
if [[ ${VB_LIFECYCLE_MATRIX:-0} == 1 ]]; then
  MATRIX_ACTIVE=1
  python3 ci/lifecycle.py matrix "$WORK"
  MATRIX_ACTIVE=0
  exit 0
fi
python3 ci/lifecycle.py apply "$WORK"
read -r C1 C2 < <(python3 - "$WORK/lifecycle.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))['containers']
print(c['vpn-test-singbox'],c['vpn-test-mita'])
PY
)
[[ $C1 =~ ^[0-9a-f]{64}$ && $C2 =~ ^[0-9a-f]{64}$ ]]
for port in 18443 18444 18445; do
  ip netns exec vb-client python3 ci/probe.py 198.18.254.2 198.18.254.1 "$port" allow
  ip netns exec vb-client python3 ci/probe.py 198.18.254.3 198.18.254.1 "$port" deny
done
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
python3 ci/lifecycle.py verify "$WORK"
export VB_C1=$C1 VB_C2=$C2
python3 ci/functional.py "$WORK"
python3 ci/test_guard.py "$WORK"
python3 ci/lifecycle.py verify "$WORK"
nft list table inet vpn_benchmark
python3 ci/lifecycle.py stop "$WORK"
for port in 18443 18444 18445; do ip netns exec vb-client python3 ci/probe.py 198.18.254.2 198.18.254.1 "$port" deny; done
echo 'PASS: native checks, startup, TCP ingress allow/deny and stopped endpoints. Functional checks completed. ACME and production acceptance remain pending.'
