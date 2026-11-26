#!/usr/bin/env bash
set -euo pipefail
# Fail closed if an inventory command itself fails.
containers=$(docker ps -a --format '{{.Names}}')
networks=$(docker network ls --format '{{.Name}}')
tables=$(sudo nft list tables)
namespaces=$(sudo ip netns list)
links=$(ip -o link show)
for n in vpn-test-singbox vpn-test-mita; do
  if grep -Fxq "$n" <<< "$containers"; then echo "FAIL: leaked container $n"; exit 1; fi
done
for n in vb-sbox vb-mita; do
  if grep -Fxq "$n" <<< "$networks"; then echo "FAIL: leaked network $n"; exit 1; fi
done
if grep -Fxq 'table inet vpn_benchmark' <<< "$tables"; then echo 'FAIL: leaked firewall table'; exit 1; fi
if grep -Eq '^(vb-client|vb-flush-test)([[:space:]]|$)' <<< "$namespaces"; then echo 'FAIL: leaked namespace'; exit 1; fi
for n in vb-wan br-vb-sbox br-vb-mita; do
  if grep -Eq "^[0-9]+: ${n}(@[^:]+)?:" <<< "$links"; then echo "FAIL: leaked interface $n"; exit 1; fi
done
for command in iptables-legacy-save ip6tables-legacy-save; do
  saved=$(sudo "$command")
  if grep -Eq '(^:VB15_|-j VB15_|^-A VB15_)' <<< "$saved"; then echo 'FAIL: leaked independent guard'; exit 1; fi
done
echo 'PASS: lab resources absent after cleanup'
