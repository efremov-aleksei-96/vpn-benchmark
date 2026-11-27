#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && ${GITHUB_REPOSITORY:-} == efremov-aleksei-96/vpn-benchmark ]] || exit 78
[[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} && -z ${DOCKER_API_VERSION:-} ]] || exit 78
[[ $(docker context show) == default && $(docker context inspect default --format '{{.Endpoints.docker.Host}}') == unix:///var/run/docker.sock ]] || exit 78
root=$PWD
d=$(mktemp -d)
qpid=''
cleanup() {
  rc=$?; trap - EXIT; set +e
  if [[ -n $qpid ]]; then kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null; fi
  rm -rf -- "$d"
  exit "$rc"
}
trap cleanup EXIT
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils ubuntu-keyring
keyring=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
[[ -r $keyring ]]
cd "$d"
url=https://cloud-images.ubuntu.com/releases/noble/release
image=ubuntu-24.04-server-cloudimg-amd64.img
for f in "$image" SHA256SUMS SHA256SUMS.gpg; do
  curl -fsSL --retry 2 --max-time 300 --proto '=https' "$url/$f" -o "$f"
done
gpgv --keyring "$keyring" SHA256SUMS.gpg SHA256SUMS
awk -v f="$image" '$2==f || $2=="*"f {print}' SHA256SUMS >image.sum
[[ $(wc -l <image.sum) == 1 ]]
sha256sum -c image.sum
qemu-img info "$image"
qemu-img resize -f qcow2 "$image" 20G
# Only temporary, job-specific SSH keys; no passwords and no shared secrets.
ssh-keygen -q -t ed25519 -N '' -f client
ssh-keygen -q -t ed25519 -N '' -f host
printf 'instance-id: vb-a10-guest\nlocal-hostname: vb-a10-guest\n' >meta-data
python3 - <<'PY'
import pathlib,json
p=pathlib.Path
config={'users':[{'name':'ubuntu','sudo':'ALL=(ALL) NOPASSWD:ALL','shell':'/bin/bash','ssh_authorized_keys':[p('client.pub').read_text().strip()]}],'ssh_pwauth':False,'disable_root':True,'ssh_deletekeys':False,'ssh_keys':{'ed25519_private':p('host').read_text(),'ed25519_public':p('host.pub').read_text()},'write_files':[{'path':'/etc/a10-disposable-guest','content':'A10 disposable QEMU guest\n','permissions':'0600'}]}
p('user-data').write_text('#cloud-config\n'+json.dumps(config)+'\n')
PY
cloud-localds seed.img user-data meta-data
printf '[127.0.0.1]:22222 %s\n' "$(cat host.pub)" >known_hosts
# Verify actual KVM initialization, not just the device's existence.
accel=tcg
cpu=max
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  set +e
  timeout 4 qemu-system-x86_64 -accel kvm -cpu host -m 256 -nodefaults -display none -S >/dev/null 2>&1
  result=$?
  set -e
  if [[ $result == 124 ]]; then accel=kvm; cpu=host; fi
fi
echo "A10 accelerator=$accel"
qemu-system-x86_64 -accel "$accel" -cpu "$cpu" -smp 2 -m 4096 -display none -serial file:"$d/serial.log" -monitor none \
  -drive "if=virtio,format=qcow2,file=$d/$image" -drive "if=virtio,format=raw,readonly=on,file=$d/seed.img" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22222-:22 -device virtio-net-pci,netdev=net0 &
qpid=$!
sshopt=(-i "$d/client" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$d/known_hosts" -o LogLevel=ERROR)
remote() { ssh "${sshopt[@]}" -p 22222 ubuntu@127.0.0.1 "$@"; }
wait_guest() {
  for ((i=0;i<120;i++)); do
    kill -0 "$qpid"
    if remote true >/dev/null 2>&1; then return; fi
    sleep 5
  done
  echo 'A10 guest SSH timeout'; return 1
}
wait_guest
# Preserve failure status and expose only sanitized diagnostic categories.
set +e
remote 'sudo cloud-init status --wait --format=json' >cloud-status.json
cloud_rc=$?
set -e
echo "A10 cloud-init exit=$cloud_rc"
python3 - "$cloud_rc" <<'PY'
import json,pathlib,re,sys
try: data=json.loads(pathlib.Path('cloud-status.json').read_text())
except (ValueError,OSError):
    print('A10 cloud-init diagnostic unavailable or not JSON')
    sys.exit(0)
# Never publish raw cloud-config, logs, host key material or arbitrary values.
# Only error fields from the status report, with key lines/opaque tokens removed.
private_lines=[]
for name in ('host','client'):
    private_lines.extend(x.strip() for x in pathlib.Path(name).read_text().splitlines() if len(x.strip())>15)
def safe(value):
    s=str(value)
    for x in private_lines:s=s.replace(x,'[REDACTED]')
    s=re.sub(r'-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----','[REDACTED]',s,flags=re.S)
    s=re.sub(r'[A-Za-z0-9+/=_-]{32,}','[REDACTED]',s)
    return ''.join(c if c.isprintable() else ' ' for c in s)[:400]
def messages(value):
    if isinstance(value,dict):
        for v in value.values():yield from messages(v)
    elif isinstance(value,list):
        for v in value:yield from messages(v)
    elif isinstance(value,str):yield value
print('A10 cloud-init status='+safe(data.get('status'))+' extended='+safe(data.get('extended_status')))
for stage in ('top','init-local','init','modules-config','modules-final'):
    obj=data if stage=='top' else data.get(stage,{})
    if not isinstance(obj,dict):continue
    for kind in ('errors','recoverable_errors'):
        for msg in list(messages(obj.get(kind,[])))[:12]:
            print('A10 cloud-init '+stage+' '+kind+': '+safe(msg))
PY
# Use the guest's exact installed schema; never print raw config or validator
# output because it contains the disposable SSH host key.
remote 'sudo python3 -' <<'PY'
import json,pathlib,subprocess,tempfile,os
p=pathlib.Path('/var/lib/cloud/instance/user-data.txt')
raw=p.read_text()
assert raw.startswith('#cloud-config\n')
cfg=json.loads(raw.split('\n',1)[1])
assert 'ssh_genkeytypes' not in cfg and 'ed25519_private' in cfg['ssh_keys']
print('A10 guest cloud-init version: '+subprocess.check_output(['cloud-init','--version'],stderr=subprocess.STDOUT,text=True).strip(),flush=True)
with tempfile.TemporaryDirectory(prefix='a10-schema-') as tmp:
    path=pathlib.Path(tmp)/'user-data'
    def check(data):
        path.write_text('#cloud-config\n'+json.dumps(data)+'\n')
        os.chmod(path,0o600)
        return subprocess.run(['cloud-init','schema','-c',str(path)],capture_output=True,text=True)
    good=check(cfg)
    print('A10 corrected config schema exit='+str(good.returncode),flush=True)
    assert good.returncode==0,'corrected config rejected by guest schema'
    bad=check(dict(cfg,ssh_genkeytypes=[]))
    matched='ssh_genkeytypes' in (bad.stdout+bad.stderr)
    print('A10 old config schema exit='+str(bad.returncode)+' field_matched='+str(matched),flush=True)
    assert bad.returncode!=0 and matched,'old empty-list defect not reproduced'
print('A10 schema differential PASS',flush=True)
PY
# Nonzero remains a hard failure. Do not accept degraded initialization.
[[ $cloud_rc == 0 ]]
echo 'A10 cloud-init clean PASS'
remote 'sudo test -f /etc/a10-disposable-guest && sudo mkdir -p /opt/vb-a10 && sudo chown ubuntu:ubuntu /opt/vb-a10'
# Build Mita outside TCG. Source revision checked exactly, local image ID retained.
# Do not modify the outer runner's Docker daemon or migrate its image store.
docker info --format 'A10 outer storage driver={{.Driver}} driver_status={{json .DriverStatus}}'
[[ $(docker info --format '{{.Driver}}') == overlay2 ]]
[[ $(docker info --format '{{json .DriverStatus}}') != *io.containerd.snapshotter.v1* ]]
git clone --depth 1 --branch v3.39.0 https://github.com/enfein/mieru.git "$d/mieru"
[[ $(git -C "$d/mieru" rev-parse HEAD) == bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06 ]]
docker build -t vb-mita-a10 -f "$d/mieru/deployments/docker/mita/Dockerfile" "$d/mieru"
docker image inspect vb-mita-a10 --format '{{.Id}}' >mita.id
docker save vb-mita-a10 -o mita.tar
# Digest of the exact transferred archive, independently checked in guest.
printf '%s  vb-a10-mita.tar\n' "$(sha256sum mita.tar | awk '{print $1}')" >mita.sha256
# Copy only tracked source, no .git, runner tokens, or credentials.
git -C "$root" archive HEAD | remote 'tar -x -C /opt/vb-a10'
scp "${sshopt[@]}" -P 22222 mita.tar mita.id mita.sha256 ubuntu@127.0.0.1:/tmp/
remote 'sudo mv /tmp/mita.tar /opt/vb-a10-mita.tar && sudo mv /tmp/mita.id /opt/vb-a10-mita.id && sudo mv /tmp/mita.sha256 /opt/vb-a10-mita.sha256 && sudo chown -R root:root /opt/vb-a10 && sudo bash /opt/vb-a10/tests/a10/prepare-guest.sh'
old=$(remote 'cat /proc/sys/kernel/random/boot_id')
echo "A10 old boot recorded"
# Start real guest reboot; only the outer runner remains active.
remote 'sudo systemctl reboot' || true
changed=0
for ((i=0;i<120;i++)); do
  kill -0 "$qpid"
  new=$(remote 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
  if [[ $new =~ ^[a-f0-9-]{36}$ && $new != "$old" ]]; then changed=1; break; fi
  sleep 5
done
[[ $changed == 1 ]]
echo 'A10 independent outer-runner boot ID comparison PASS'
# SSH and boot_id may be ready before the Docker unit/API. Observe only;
# never start or restart Docker from this test.
deadline=$((SECONDS+120))
docker_ready=0
while ((SECONDS < deadline)); do
  if version=$(timeout 10 ssh "${sshopt[@]}" -p 22222 ubuntu@127.0.0.1 'sudo systemctl is-active --quiet docker && sudo timeout 5 docker --host unix:///var/run/docker.sock version --format "{{.Server.Version}} {{.Server.APIVersion}}"' 2>/dev/null) && [[ $version == '29.1.3 1.52' ]]; then
    docker_ready=1;break
  fi
  sleep 2
done
if [[ $docker_ready != 1 ]]; then
  echo 'A10 Docker readiness timeout'
  timeout 10 ssh "${sshopt[@]}" -p 22222 ubuntu@127.0.0.1 'systemctl show docker -p ActiveState -p SubState -p Result' || true
  exit 1
fi
echo 'A10 Docker unit and local API ready PASS'
remote 'cd /opt/vb-a10 && sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted python3 tests/a10/guest.py after'
echo 'A10 outer runner PASS; VM will be destroyed'
