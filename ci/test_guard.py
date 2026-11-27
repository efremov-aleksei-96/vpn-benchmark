"""Live synthetic tests of both guard layers. Never use on a server."""
import json,os,pathlib,re,shlex,socket,ssl,subprocess,sys,time
from legacy_guard_ci import call,check,need
from legacy_guard import restore
IP='198.18.254.1'
NS=['ip','netns','exec','vb-client']
PORTS=(18443,18444,18445)
def probe(prefix,mode,dest,expect):
    print(call(prefix+[sys.executable,'ci/direct.py',mode,dest,expect]).strip(),flush=True)
def ingress(port,expect,src='198.18.254.2'):
    print(call(NS+[sys.executable,'ci/probe.py',src,IP,str(port),expect]).strip(),flush=True)
def legacy_count(chain,prefix=()):
    raw=call(list(prefix)+['iptables-legacy','-t','filter','-L',chain,'-v','-x','-n'])
    return sum(int(a[0]) for line in raw.splitlines() if (a:=line.split()) and len(a)>2 and a[0].isdigit() and a[2]=='DROP')
def nft_count(chain):
    rules=json.loads(call(['nft','-j','list','chain','inet','vpn_benchmark',chain]))['nftables']
    return sum(e.get('counter',{}).get('packets',0) for item in rules if any('drop' in x for x in item.get('rule',{}).get('expr',[])) for e in item.get('rule',{}).get('expr',[]))
def proxy_fallback(counter):
    # Remove exactly one Docker DNAT rule only inside the disposable VM.
    # This forces an actual published listener through INPUT, not FORWARD.
    listeners=call(['ss','-H','-lntp'])
    need(any(IP+':18443' in l and 'docker-proxy' in l for l in listeners.splitlines()),'real docker-proxy listener not found')
    base=['iptables-nft','-t','nat']
    rows=[shlex.split(l) for l in call(base+['-S','DOCKER']).splitlines() if l.startswith('-A DOCKER ')]
    matches=[(i+1,r[2:]) for i,r in enumerate(rows) if '--dport' in r and r[r.index('--dport')+1]=='18443' and '--to-destination' in r and r[r.index('--to-destination')+1]=='172.30.241.2:18443' and '-d' in r and r[r.index('-d')+1]==IP+'/32']
    need(len(matches)==1,'exact Docker DNAT not found')
    idx,rule=matches[0]
    before=counter()
    call(base+['-D','DOCKER',*rule])
    try:
        ingress(18443,'deny')
        ingress(18443,'deny','198.18.254.3')
        need(counter()>before,'INPUT drop counter did not increase')
        print('GUARD PASS docker-proxy fallback blocked by INPUT',flush=True)
    finally:
        call(base+['-I','DOCKER',str(idx),*rule])
        restored=[shlex.split(l) for l in call(base+['-S','DOCKER']).splitlines() if l.startswith('-A DOCKER ')]
        need(restored==rows,'Docker DNAT rules not restored exactly')
def hold(w):
    # TLS handshake is a positive control for an already established stream.
    with socket.create_connection(('198.18.254.4',443),timeout=5) as raw:
        with ssl.create_default_context(cafile=str(w/'target.pem')).wrap_socket(raw,server_hostname='target.test') as s:
            (w/'held.ready').touch()
            for _ in range(150):
                if (w/'held.go').exists():break
                time.sleep(.1)
            else:raise RuntimeError('hold signal missing')
            s.settimeout(3)
            try:
                s.sendall(b'GET /guard-held HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n')
                got=s.recv(4096)
            except (TimeoutError,OSError):got=b''
            need(not got,'established stream received data after primary loss')
def flush_in_namespace(w):
    name='vb-flush-test';ns=['ip','netns','exec',name]
    need(not any(l.split()[0]==name for l in call(['ip','netns','list']).splitlines() if l),'flush namespace exists')
    call(['ip','netns','add',name]);p=None
    try:
        call(['ip','-n',name,'link','set','lo','up'])
        call(['ip','-n',name,'addr','add',IP+'/32','dev','lo'])
        need(not call(['ip','-n',name,'route','show','default']).strip(),'unexpected namespace route')
        p=subprocess.Popen(ns+[sys.executable,'-c','import socket; s=socket.socket(); s.bind(("198.18.254.1",18443)); s.listen(); exec("while True:\\n c,a=s.accept(); c.close()")'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(30):
            if IP+':18443' in call(ns+['ss','-H','-lnt']):break
            need(p.poll() is None,'flush canary exited');time.sleep(.1)
        else:raise RuntimeError('flush canary unavailable')
        probe(ns,'tcp:18443',IP,'allow')
        for f in (4,6):
            cmd='iptables-legacy-restore' if f==4 else 'ip6tables-legacy-restore'
            call(ns+[cmd,'--noflush'],restore(IP,f))
        call(ns+['nft','-f',str(w/'firewall-original.nft')])
        probe(ns,'tcp:18443',IP,'deny')
        before=legacy_count('VB15_OUT',ns)
        def snapshots():
            return ['\n'.join(l for l in call(ns+[x+'-save']).splitlines() if not l.startswith('#')) for x in ('iptables-legacy','ip6tables-legacy')]
        baseline=snapshots()
        # Global nft flush is scoped to this newly created unrouted namespace.
        call(ns+['nft','flush','ruleset'])
        need(not call(ns+['nft','list','tables']).strip(),'nft flush failed')
        need(snapshots()==baseline,'legacy guard changed by nft flush')
        probe(ns,'tcp:18443',IP,'deny')
        need(legacy_count('VB15_OUT',ns)>before,'legacy OUTPUT did not drop after flush')
        print('GUARD PASS full nft flush in isolated namespace; independent packet drop',flush=True)
    finally:
        if p is not None:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        call(['ip','netns','del',name])
def main(w):
    need(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','CI only')
    check(w)
    journal=json.loads((w/'lifecycle.json').read_text())
    ids=[journal['containers'][x] for x in ('vpn-test-singbox','vpn-test-mita')]
    prefixes=[['nsenter','-t',call(['docker','inspect','--format','{{.State.Pid}}',id]).strip(),'-n'] for id in ids]
    target=['172.30.241.2','172.30.242.2']
    ports=[18443,18444]
    for port in PORTS:ingress(port,'allow')
    before=nft_count('output')
    for dest,port in zip(target,ports):
        probe([],'tcp:'+str(port),dest,'deny')
        probe([],'tcp:'+str(port),IP,'deny')
    need(nft_count('output')>before,'primary OUTPUT drop not observed')
    print('GUARD PASS primary OUTPUT direct/published access denied',flush=True)
    proxy_fallback(lambda:nft_count('input'))
    ingress(18443,'allow')
    p=subprocess.Popen(prefixes[0]+[sys.executable,__file__,'hold',str(w)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if (w/'held.ready').exists():break
            need(p.poll() is None,'held stream failed before fault');time.sleep(.1)
        else:raise RuntimeError('held stream not ready')
        call([sys.executable,'ci/lifecycle.py','verify',str(w)])
        before=legacy_count('VB15_FWD')
        primary=pathlib.Path(journal['firewall_file'])
        need(primary.parent==w and primary.is_file(),'invalid primary recovery file')
        call(['nft','delete','table','inet','vpn_benchmark'])
        try:
            need('table inet vpn_benchmark' not in call(['nft','list','tables']),'primary still present')
            check(w)
            for id in ids:need(call(['docker','inspect','--format','{{.State.Running}}',id]).strip()=='true','container stopped before loss test')
            (w/'held.go').touch()
            need(p.wait(timeout=8)==0,'held stream result failed')
            need(legacy_count('VB15_FWD')>before,'established stream did not reach independent drop')
            need('HTTP /guard-held' not in (w/'wan-fixture.log').read_text(),'held request reached origin')
            print('GUARD PASS established TLS stream blocked after primary loss',flush=True)
            before=legacy_count('VB15_FWD')
            for port in PORTS:
                ingress(port,'deny')
                ingress(port,'deny','198.18.254.3')
            for prefix in prefixes:
                probe(prefix,'tcp','198.18.254.4','deny')
                probe(prefix,'dns-udp','198.18.254.5','deny')
                probe(prefix,'dns-tcp','198.18.254.5','deny')
            need(legacy_count('VB15_FWD')>before,'independent FORWARD drops not observed')
            before=legacy_count('VB15_OUT')
            for dest,port in zip(target,ports):
                probe([],'tcp:'+str(port),dest,'deny')
                probe([],'tcp:'+str(port),IP,'deny')
            need(legacy_count('VB15_OUT')>before,'independent OUTPUT drops not observed')
            before=legacy_count('VB15_IN')
            for prefix,host in zip(prefixes,('172.30.241.1','172.30.242.1')):probe(prefix,'tcp',host,'deny')
            need(legacy_count('VB15_IN')>before,'independent INPUT drops not observed')
            proxy_fallback(lambda:legacy_count('VB15_IN'))
            print('GUARD PASS primary table loss with live containers; ingress, egress, INPUT, OUTPUT blocked',flush=True)
        finally:
            # Recreate only the journalled table, not the whole ruleset.
            if 'table inet vpn_benchmark' not in call(['nft','list','tables']):
                call(['nft','-f',str(primary)])
        call([sys.executable,'ci/lifecycle.py','verify',str(w)])
        for port in PORTS:ingress(port,'allow')
        for prefix in prefixes:probe(prefix,'tcp','198.18.254.4','allow')
        print('GUARD PASS primary restored; allowed paths restored',flush=True)
    finally:
        if p.poll() is None:p.terminate();p.wait(timeout=5)
    flush_in_namespace(w)
    print('GUARD MATRIX PASS',flush=True)
if __name__=='__main__':
    if sys.argv[1]=='hold':hold(pathlib.Path(sys.argv[2]))
    else:main(pathlib.Path(sys.argv[1]).resolve())
