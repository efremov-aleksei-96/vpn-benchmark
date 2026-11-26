#!/usr/bin/env python3
"""v1.5 operational candidate. Offline check and plan; live lifecycle locked.
No production action is authorized by the successful synthetic CI run.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import uuid
from template import render_template
from legacy_guard import restore

ROOT = Path(__file__).resolve().parent
SBOX = 'ghcr.io/sagernet/sing-box@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279'
MITA_REV = 'bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06'
TABLE = ('inet', 'vpn_benchmark')
PORTS = (80, 18443, 18444, 18445)
NETWORKS = (('vb-sbox', 'br-vb-sbox', '172.30.241.0/28', '172.30.241.2'),
            ('vb-mita', 'br-vb-mita', '172.30.242.0/28', '172.30.242.2'))
NAMES = ('vpn-test-singbox', 'vpn-test-mita')
LABEL = 'vpn-benchmark=v1.5'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def templates():
    return tuple((ROOT / p).read_text() for p in ('sing-box.json', 'mita.json', 'firewall.nft'))


def check():
    a, b, firewall = templates()
    s, m = json.loads(a), json.loads(b)
    raw, naive = s['inbounds']
    require((raw['type'], raw['listen_port'], naive['type'], naive['listen_port']) == ('vless', 18443, 'naive', 18445), 'inbound mismatch')
    require(raw['users'][0]['flow'] == 'xtls-rprx-vision' and naive['network'] == 'tcp', 'protocol mismatch')
    require(raw['listen'] == naive['listen'] == NETWORKS[0][3], 'sing-box address mismatch')
    require(m['listenIPAddress'] == NETWORKS[1][3] and m['portBindings'] == [{'port': 18444, 'protocol': 'TCP'}], 'Mita address mismatch')
    require(not m['users'][0]['allowPrivateIP'] and not m['users'][0]['allowLoopbackIP'] and m['dns']['dualStack'] == 'ONLY_IPv4', 'Mita isolation mismatch')
    acme = naive['tls']['certificate_provider']
    require(acme['alternative_http_port'] == 8080 and acme['disable_tls_alpn_challenge'] is True and acme['profile'] == 'shortlived', 'ACME mismatch')
    require(acme['provider'] == 'https://acme-staging-v02.api.letsencrypt.org/directory' and acme['data_directory'] == '/acme/staging', 'staging mismatch')
    require('198.18.254.' not in a + b + firewall and 'target.test' not in a+b+firewall and 'vb-wan' not in firewall, 'lab exception present')
    require('198.18.0.0/15' in firewall and '198.18.0.0/15' in a, 'benchmark range must remain denied')
    require(firewall.count('meta nfproto ipv6 counter drop') == 2, 'IPv6 drops missing')
    require(firewall.count('{') == firewall.count('}') and 'flush ruleset' not in firewall, 'firewall text mismatch')
    require((ROOT / 'resolv.conf').read_text().splitlines()[0] == 'nameserver 1.1.1.1', 'DNS mismatch')
    require('chain output {' in firewall and all('0x40000000' in line for line in firewall.splitlines() if line.strip().endswith(' accept') and 'counter' in line), 'permit marking mismatch')
    print('PASS: offline JSON, protocol/port/IP consistency, DNS, lab-exclusion and firewall structure checks')


def read_settings(path):
    cfg = json.loads(Path(path).read_text())
    require(set(cfg) == {'public_ipv4','wan_if','tester_cidrs','reality_host','mita_image_id','acme_mode'}, 'unexpected/missing settings keys')
    ip = ipaddress.IPv4Address(cfg['public_ipv4'])
    require(ip.is_global and not ip.is_multicast and not ip.is_reserved, 'assigned public IPv4 required')
    require(re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', cfg['wan_if']) and cfg['wan_if'] not in {'lo','vb-wan','br-vb-sbox','br-vb-mita'}, 'invalid WAN interface')
    require(isinstance(cfg['tester_cidrs'], list) and 0 < len(cfg['tester_cidrs']) <= 32, 'tester list required')
    nets = [ipaddress.IPv4Network(x, strict=True) for x in cfg['tester_cidrs']]
    require(all(n.prefixlen >= 24 and n.network_address.is_global and n.broadcast_address.is_global and not n.network_address.is_multicast and not n.network_address.is_reserved for n in nets), 'only narrow public IPv4 tester CIDRs /24–/32')
    require(not any(ip in n for n in nets), 'tester CIDR includes server')
    require(len(nets) == len(set(nets)) and not any(a.overlaps(b) for i,a in enumerate(nets) for b in nets[i+1:]), 'duplicate/overlapping tester CIDRs')
    cfg['tester_cidrs'] = [str(n) for n in nets]
    host = cfg['reality_host']
    require(isinstance(host,str) and len(host)<=253 and '.' in host and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in host.split('.')) and host.split('.')[-1].isalpha() and not host.endswith(('.test','.local','.invalid','.localhost')), 'validated public TLS hostname required')
    require(re.fullmatch(r'sha256:[a-f0-9]{64}',cfg['mita_image_id']), 'immutable local Mita image ID required')
    require(cfg['acme_mode'] in ('staging','production'), 'invalid ACME mode')
    return cfg


def render(cfg, secrets):
    require(set(secrets) == {'uuid','private_key','short_id','naive_password','mieru_password'}, 'unexpected/missing secret keys')
    require(str(uuid.UUID(secrets['uuid'])) == secrets['uuid'] and uuid.UUID(secrets['uuid']).version == 4, 'new UUIDv4 required')
    require(re.fullmatch(r'[A-Za-z0-9_-]{43}', secrets['private_key']), 'invalid REALITY private key format')
    require(re.fullmatch(r'[a-f0-9]{16}',secrets['short_id']), 'invalid short ID')
    for key in ('naive_password','mieru_password'):
        require(re.fullmatch(r'[A-Za-z0-9_-]{32,128}',secrets[key]), 'use independent random URL-safe passwords')
    require(secrets['naive_password'] != secrets['mieru_password'], 'password reuse')
    replacements = dict(zip(('PUBLIC_IPV4','WAN_IF','TESTER_IPV4_CIDRS','REALITY_HOST','VLESS_UUID','REALITY_PRIVATE_KEY','REALITY_SHORT_ID','NAIVE_PASSWORD','MIERU_PASSWORD'),(cfg['public_ipv4'],cfg['wan_if'],', '.join(cfg['tester_cidrs']),cfg['reality_host'],secrets['uuid'],secrets['private_key'],secrets['short_id'],secrets['naive_password'],secrets['mieru_password'])))
    out=[render_template(text,{'__'+k+'__':v for k,v in replacements.items()}) for text in templates()]
    s=json.loads(out[0]); m=json.loads(out[1]); acme=s['inbounds'][1]['tls']['certificate_provider']
    if cfg['acme_mode']=='production':
        acme.update(provider='letsencrypt',data_directory='/acme/production')
    return {'sing-box.json':json.dumps(s,indent=2)+'\n','mita.json':json.dumps(m,indent=2)+'\n','firewall.nft':out[2],'resolv.conf':(ROOT/'resolv.conf').read_text(), **{f'legacy{family}.rules':restore(cfg['public_ipv4'],family) for family in (4,6)}}


def cmd(*args):
    return shlex.join(map(str,args))


def plan(cfg, work, uid, gid, run_id):
    require(uid > 0 and gid > 0, 'Mita service identity must be non-root')
    require(re.fullmatch(r'[a-f0-9]{32}',run_id), 'invalid run ID')
    require(work.is_absolute() and ',' not in str(work) and '\n' not in str(work), 'absolute work path without comma/newline required')
    labels=['--label',LABEL,'--label','vpn-benchmark.run='+run_id]
    commands=[]
    for name,bridge,subnet,_ in NETWORKS:
        commands.append(('network '+name,cmd('docker','network','create',*labels,'--driver','bridge','--ipv6=false','--subnet',subnet,'--opt','com.docker.network.bridge.name='+bridge,name)))
    common=['--pull','never','--restart','no','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--cpus','0.75','--pids-limit','128','--log-driver','json-file','--log-opt','max-size=5m','--log-opt','max-file=2']
    def mount(src,dst,ro=True):return ['--mount',f'type=bind,src={work/src},dst={dst}'+(',readonly' if ro else '')]
    def publish(port,dest):return ['-p',f"{cfg['public_ipv4']}:{port}:{dest}/tcp"]
    a=['docker','create','--name',NAMES[0],*labels,*common,'--network','vb-sbox','--ip',NETWORKS[0][3],'--user','65532:65532','--memory','384m','--memory-swap','384m',*publish(18443,18443),*publish(18445,18445),*publish(80,8080),*mount('sing-box.json','/config.json'),*mount('resolv.conf','/etc/resolv.conf'),*mount('acme','/acme',False),'--entrypoint','sing-box',SBOX,'run','-c','/config.json']
    b=['docker','create','--name',NAMES[1],*labels,*common,'--network','vb-mita','--ip',NETWORKS[1][3],'--user',f'{uid}:{gid}','--memory','256m','--memory-swap','256m']
    for d in ('/var/run/mita','/etc/mita','/var/lib/mita'):
        b+=['--tmpfs',f'{d}:rw,nosuid,nodev,noexec,uid={uid},gid={gid},mode=0700']
    b+= [*publish(18444,18444),*mount('mita.json','/config.json'),*mount('resolv.conf','/etc/resolv.conf'),'-e','MITA_UDS_PATH=/var/run/mita/mita.sock','-e','MITA_CONFIG_JSON_FILE=/config.json','--entrypoint','/usr/local/bin/mita',cfg['mita_image_id'],'run']
    return [*commands,('create sing-box',shlex.join(a)),('create Mita',shlex.join(b))]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('check')
    r=sub.add_parser('render',help='offline rendering to a new directory; no Docker or network')
    r.add_argument('settings');r.add_argument('secrets');r.add_argument('output')
    q=sub.add_parser('plan',help='print commands only; never executes them')
    q.add_argument('settings');q.add_argument('work');q.add_argument('--mita-uid',type=int,required=True);q.add_argument('--mita-gid',type=int,required=True);q.add_argument('--run-id',required=True)
    for name in ('apply','start','stop','rollback'):sub.add_parser(name)
    a=p.parse_args()
    if a.action in ('apply','start','stop','rollback'):
        print('BLOCKED: operational adapter not host-validated or authorized; separate reviewed release required.',file=sys.stderr);return 78
    if a.action=='check':check();return 0
    cfg=read_settings(a.settings)
    if a.action=='plan':
        print('# REVIEW ONLY — not an executable batch. Follow README gates, including native sing-box check and immutable IDs.')
        print('# Required transaction: audit mark conflicts; native checks; legacy IPv4 then IPv6; nft table; verify both; networks; containers; start. No live firewall commands emitted.')
        for name,line in plan(cfg,Path(a.work),a.mita_uid,a.mita_gid,a.run_id):print('# '+name+'\n# '+line)
        return 0
    sp=Path(a.secrets);require(sp.is_file() and not sp.is_symlink() and sp.stat().st_mode & 0o077 == 0,'secret input must be a regular private file (0600)')
    secrets=json.loads(sp.read_text());out=render(cfg,secrets)
    d=Path(a.output);os.umask(0o077);d.mkdir(mode=0o700,parents=False,exist_ok=False)
    for name,value in out.items():(d/name).write_text(value)
    print('PASS: private rendered files created; no service or firewall applied. Set per-file ownership per README.')
    return 0


if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,TypeError,KeyError,OSError) as e:
        # Avoid printing config data, secret values or arbitrary exception strings.
        print('FAIL: invalid input or file operation; inspect locally without publishing secrets.',file=sys.stderr);sys.exit(1)
