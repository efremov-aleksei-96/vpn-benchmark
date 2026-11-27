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
version='5:29.1.3-1~ubuntu.24.04~noble'
apt-get install -y --no-install-recommends "docker-ce=$version" "docker-ce-cli=$version" containerd.io
systemctl enable --now docker
bash ci/transaction_v2/prepare-docker.sh
# Use the exact pinned sing-box digest; load the image built on the outer CI runner.
SBOX_REF=ghcr.io/sagernet/sing-box@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279
docker pull --platform linux/amd64 "$SBOX_REF"
docker load -i /opt/vb-a10-mita.tar
export VB_SBOX_IMAGE=$(docker image inspect "$SBOX_REF" --format '{{.Id}}')
export VB_MITA_IMAGE=$(docker image inspect vb-mita-a10 --format '{{.Id}}')
[[ "$VB_MITA_IMAGE" == "$(cat /opt/vb-a10-mita.id)" ]]
ids=$(docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --read-only --entrypoint /bin/sh "$VB_MITA_IMAGE" -ec 'printf "%s %s\n" "$(id -u mita)" "$(id -g mita)"')
read -r VB_MITA_UID VB_MITA_GID <<<"$ids"; export VB_MITA_UID VB_MITA_GID
[[ $VB_MITA_UID =~ ^[1-9][0-9]*$ && $VB_MITA_GID =~ ^[1-9][0-9]*$ ]]
keys=$(docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges --entrypoint sing-box "$VB_SBOX_IMAGE" generate reality-keypair)
export VB_KEY=$(printf '%s\n' "$keys" | sed -n 's/^PrivateKey:[[:space:]]*//p')
export VB_PUB=$(printf '%s\n' "$keys" | sed -n 's/^PublicKey:[[:space:]]*//p')
[[ -n $VB_KEY && -n $VB_PUB ]]; unset keys
export VB_WORK=$(mktemp -d); chmod 755 "$VB_WORK"
python3 ci/render.py
unset VB_KEY VB_PUB
python3 tests/a10/guest.py before "$VB_WORK"
