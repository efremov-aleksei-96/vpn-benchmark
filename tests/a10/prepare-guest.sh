#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID == 0 && -f /etc/a10-disposable-guest && $(systemd-detect-virt) =~ ^(qemu|kvm)$ ]] || exit 78
cd /opt/vb-a10
export GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl gnupg nftables iptables iproute2 iputils-ping openssl python3
key=/etc/apt/keyrings/docker.asc
install -d -m 0755 /etc/apt/keyrings
curl -fsSL --proto '=https' https://download.docker.com/linux/ubuntu/gpg -o "$key"
gpg --batch --show-keys --with-colons "$key" | awk -F: '$1=="fpr"&&!seen++{print $10}' | grep -Fxq 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
chmod 644 "$key"
echo "deb [arch=amd64 signed-by=$key] https://download.docker.com/linux/ubuntu noble stable" >/etc/apt/sources.list.d/docker.list
apt-get update -qq
# New disposable guest ONLY; configure the same classic image store as
# the outer runner BEFORE Docker installation, never migrate existing data.
[[ ! -e /etc/docker/daemon.json && ! -e /var/lib/docker && ! -e /var/lib/containerd ]]
! command -v dockerd >/dev/null
install -d -m 0755 /etc/docker
printf '%s\n' '{"features":{"containerd-snapshotter":false},"storage-driver":"overlay2"}' >/etc/docker/daemon.json
chmod 0644 /etc/docker/daemon.json
version='5:29.1.3-1~ubuntu.24.04~noble'
apt-get install -y --no-install-recommends "docker-ce=$version" "docker-ce-cli=$version" containerd.io
systemctl enable --now docker
bash ci/transaction_v2/prepare-docker.sh
docker info --format 'A10 guest storage driver={{.Driver}} driver_status={{json .DriverStatus}}'
[[ $(docker info --format '{{.Driver}}') == overlay2 ]]
[[ $(docker info --format '{{json .DriverStatus}}') != *io.containerd.snapshotter.v1* ]]
[[ -z $(docker ps -aq) && -z $(docker image ls -aq) ]]
echo 'A10 empty classic guest image store PASS'
(cd /opt && sha256sum --check vb-a10-mita.sha256)
echo 'A10 transferred Mita archive SHA256 PASS'
# Use the exact pinned sing-box digest; load the image built on the outer CI runner.
SBOX_REF=ghcr.io/sagernet/sing-box@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279
docker pull --platform linux/amd64 "$SBOX_REF"
docker load -i /opt/vb-a10-mita.tar
# Separate assignment from export: export alone can hide a failed substitution.
stage=inspect-sing-box
trap 'rc=$?; echo "A10 guest preparation failed stage=$stage rc=$rc" >&2; exit "$rc"' ERR
VB_SBOX_IMAGE=$(docker image inspect "$SBOX_REF" --format '{{.Id}}')
stage=inspect-mita
VB_MITA_IMAGE=$(docker image inspect vb-mita-a10 --format '{{.Id}}')
expected_mita=$(cat /opt/vb-a10-mita.id)
stage=validate-image-ids
[[ $VB_SBOX_IMAGE =~ ^sha256:[a-f0-9]{64}$ && $VB_MITA_IMAGE =~ ^sha256:[a-f0-9]{64}$ && $expected_mita =~ ^sha256:[a-f0-9]{64}$ ]]
printf 'A10 Mita image expected=%s observed=%s\n' "$expected_mita" "$VB_MITA_IMAGE"
docker info --format 'A10 guest storage driver={{.Driver}} driver_status={{json .DriverStatus}}'
stage=check-mita-identity
[[ "$VB_MITA_IMAGE" == "$expected_mita" ]]
echo 'A10 imported image identity PASS'
export VB_SBOX_IMAGE VB_MITA_IMAGE
stage=mita-service-identity
ids=$(docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --read-only --entrypoint /bin/sh "$VB_MITA_IMAGE" -ec 'printf "%s %s\n" "$(id -u mita)" "$(id -g mita)"')
read -r VB_MITA_UID VB_MITA_GID <<<"$ids"
[[ $VB_MITA_UID =~ ^[1-9][0-9]*$ && $VB_MITA_GID =~ ^[1-9][0-9]*$ ]]
printf 'A10 Mita service identity PASS uid=%s gid=%s\n' "$VB_MITA_UID" "$VB_MITA_GID"
export VB_MITA_UID VB_MITA_GID
stage=generate-reality-keypair
keys=$(docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --entrypoint sing-box "$VB_SBOX_IMAGE" generate reality-keypair)
VB_KEY=$(printf '%s\n' "$keys" | sed -n 's/^PrivateKey:[[:space:]]*//p')
VB_PUB=$(printf '%s\n' "$keys" | sed -n 's/^PublicKey:[[:space:]]*//p')
[[ -n $VB_KEY && -n $VB_PUB ]]; unset keys
export VB_KEY VB_PUB
echo 'A10 ephemeral key generation PASS'
stage=render-fixture
VB_WORK=$(mktemp -d); export VB_WORK; chmod 755 "$VB_WORK"
python3 ci/render.py
unset VB_KEY VB_PUB
echo 'A10 fixture render PASS'
stage=before-reboot
python3 tests/a10/guest.py before "$VB_WORK"
