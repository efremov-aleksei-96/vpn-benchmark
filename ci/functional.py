"""Functional acceptance on the disposable runner, never a production system."""
import json,os,pathlib,subprocess,sys,tempfile,time
w=pathlib.Path(sys.argv[1]);ns=['ip','netns','exec','vb-client']
TOKEN=b'vpn-benchmark-local-fixture-v1\n'
def run(args,check=True,timeout=40,**kw):
    return subprocess.run(args,check=check,timeout=timeout,**kw)
def probe(prefix,mode,dest,expect):
    run(prefix+[sys.executable,'ci/direct.py',mode,dest,expect])
def inspect(id,fmt):return subprocess.check_output(['docker','inspect','--format',fmt,id],text=True).strip()
def check_curl(label,url,expected,proxied=True):
    args=ns+['curl','--silent','--show-error','--fail','--http1.1','--max-time','15','--connect-timeout','5','--cacert',str(w/'target.pem'),'--noproxy','']
    args+=['--proxy','socks5h://127.0.0.1:19080'] if proxied else ['--proxy','']
    r=run(args+[url],check=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=18)
    ok=r.returncode==0 and r.stdout==TOKEN
    # For a deny check, an unexpected successful HTTP response is a failure
    # even if its body is not the marker.
    result=ok if expected else r.returncode!=0 and TOKEN not in r.stdout
    print(label,'PASS' if result else 'FAIL','curl_exit',r.returncode,flush=True)
    if not result:raise RuntimeError(label)
def client(label,good):
    config=w/'clients'/(label+('-good' if good else '-bad')+'.json')
    home=pathlib.Path(tempfile.mkdtemp(prefix=label+'-',dir=w/'clients'))
    os.chown(home,65532,65532)
    prefix=ns+['setpriv','--reuid=65532','--regid=65532','--clear-groups','--no-new-privs','env','HOME='+str(home),'XDG_CONFIG_HOME='+str(home),'XDG_CACHE_HOME='+str(home)]
    if label=='mieru':
        cmd=prefix+['MIERU_CONFIG_JSON_FILE='+str(config),os.environ['MIERU_CLIENT'],'run']
    else:
        binary=os.environ['SBOX_CLIENT'];cmd=prefix+[binary,'run','-c',str(config)]
        check=run(prefix+[binary,'check','-c',str(config)],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if check.returncode:raise RuntimeError(label+' client config check failed')
    with (w/(label+'-client.log')).open('wb') as log:
        p=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
        try:
            ready=False
            for _ in range(30):
                if p.poll() is not None:break
                q=run(ns+[sys.executable,'-c','import socket; socket.create_connection(("127.0.0.1",19080),.3).close()'],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                if q.returncode==0:ready=True;break
                time.sleep(.2)
            if not ready:raise RuntimeError(label+' client not listening')
            host=label+'.target.test'
            if good:
                check_curl(label+' authenticated HTTPS','https://'+host+'/'+label+'-good',True)
                check_curl(label+' internal by IP','https://172.30.241.1/'+label+'-internal-ip',False)
                check_curl(label+' internal by DNS','https://internal.test/'+label+'-internal-dns',False)
                check_curl(label+' forbidden WAN destination','https://198.18.254.6/'+label+'-forbidden',False)
                # Verify a valid transaction still works after the negative controls.
                check_curl(label+' positive control','https://'+host+'/'+label+'-control',True)
                logtext=(w/'wan-fixture.log').read_text()
                if 'DNS '+host+' 1' not in logtext or 'HTTP /'+label+'-good' not in logtext:
                    raise RuntimeError(label+' missing DNS/HTTPS fixture evidence')
                print(label,'DNS and HTTPS fixture evidence PASS',flush=True)
            else:
                check_curl(label+' invalid credentials','https://198.18.254.4/'+label+'-bad',False)
                if 'HTTP /'+label+'-bad' in (w/'wan-fixture.log').read_text():raise RuntimeError(label+' invalid credential reached origin')
        except Exception:
            with (w/(label+'-client.log')).open('rb') as errors:
                run([sys.executable,'ci/diagnose.py'],check=False,stdin=errors)
            raise
        finally:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
# Positive controls show fixtures are alive independently of the proxies.
check_curl('HTTPS fixture direct','https://198.18.254.4/direct',True,False)
probe(ns,'tcp','198.18.254.6','allow')
probe(ns,'dns-udp','198.18.254.5','allow')
probe(ns,'dns-tcp','198.18.254.5','allow')
probe(ns,'dns-udp','198.18.254.6','allow')
for ip in ('172.30.241.1','172.30.242.1'):probe([],'tcp',ip,'allow')
for var,peer in [('VB_C1','172.30.242.2'),('VB_C2','172.30.241.2')]:
    cid=os.environ[var];pid=inspect(cid,'{{.State.Pid}}');prefix=['nsenter','-t',pid,'-n']
    probe(prefix,'tcp','198.18.254.4','allow')
    probe(prefix,'dns-udp','198.18.254.5','allow')
    probe(prefix,'dns-tcp','198.18.254.5','allow')
    probe(prefix,'dns-udp','198.18.254.6','deny')
    probe(prefix,'dns-tcp','198.18.254.6','deny')
    probe(prefix,'tcp','198.18.254.6','deny')
    for ip in ('172.30.241.1','172.30.242.1'):probe(prefix,'tcp',ip,'deny')
    # Peer listeners were already proven reachable via the allowed ingress path.
    for port in ([18444] if var=='VB_C1' else [18443,18445]):probe(prefix,'tcp:'+str(port),peer,'deny')
    # Verify no routable IPv6 configuration in the actual disabled-IPv6 network.
    addresses=run(prefix+['ip','-6','addr','show','scope','global'],stdout=subprocess.PIPE,text=True).stdout
    if addresses.strip():raise RuntimeError('unexpected global IPv6 address')
    probe(prefix,'ipv6','fd42:198:18::4','isolated')
    print(var,'IPv6 no-global-address and connect failure PASS (not proof of packet-filter rule)',flush=True)
for label in ('raw','mieru','naive'):
    client(label,True);client(label,False)
    # Re-run good credentials after the negative test; rules out service failure.
    client(label,True)
# Exercise the explicit IPv6 FORWARD drop in addition to testing disabled IPv6.
# Temporarily add only synthetic /64s in the disposable VM; no service changes.
def ipv6_drop_count():
    data=json.loads(subprocess.check_output(['nft','-j','list','chain','inet','vpn_benchmark','forward']))
    packets=0;matched=0
    for obj in data['nftables']:
        expr=obj.get('rule',{}).get('expr',[])
        if any(x.get('match',{}).get('left')=={'meta':{'key':'nfproto'}} and x.get('match',{}).get('right')=='ipv6' for x in expr) and any('drop' in x for x in expr):
            matched+=1
            packets+=sum(x.get('counter',{}).get('packets',0) for x in expr)
    if matched!=2:raise RuntimeError('expected exactly two IPv6 drop rules')
    return packets
probe([],'ipv6','fd42:198:18::4','allow')
old_forward=subprocess.check_output(['sysctl','-n','net.ipv6.conf.all.forwarding'],text=True).strip()
try:
    run(['sysctl','-qw','net.ipv6.conf.all.forwarding=1'])
    for var,bridge,subnet in [('VB_C1','br-vb-sbox','fd42:198:241'),('VB_C2','br-vb-mita','fd42:198:242')]:
        cid=os.environ[var];pid=inspect(cid,'{{.State.Pid}}');prefix=['nsenter','-t',pid,'-n']
        run(['sysctl','-qw','net.ipv6.conf.'+bridge+'.disable_ipv6=0'])
        run(['ip','-6','addr','add',subnet+'::1/64','dev',bridge,'nodad'])
        run(['sysctl','-qw','net.ipv6.conf.'+bridge+'.forwarding=1'])
        run(prefix+['sysctl','-qw','net.ipv6.conf.eth0.disable_ipv6=0'])
        run(prefix+['ip','-6','addr','add',subnet+'::2/64','dev','eth0','nodad'])
        # Host INPUT intentionally drops container-originated Neighbor Discovery.
        # Seed only the synthetic gateway's real L2 address so a TCP SYN can
        # reach the FORWARD hook without allowing ND or changing firewall rules.
        gateway_mac=pathlib.Path('/sys/class/net',bridge,'address').read_text().strip()
        run(prefix+['ip','-6','neigh','replace',subnet+'::1','lladdr',gateway_mac,'nud','permanent','dev','eth0'])
        run(prefix+['ip','-6','route','add','fd42:198:18::/64','via',subnet+'::1','dev','eth0'])
        route=json.loads(subprocess.check_output(prefix+['ip','-j','-6','route','get','fd42:198:18::4']))
        if len(route)!=1 or route[0].get('dev')!='eth0' or route[0].get('gateway')!=subnet+'::1':
            raise RuntimeError(var+' synthetic IPv6 route mismatch')
        neighbor=json.loads(subprocess.check_output(prefix+['ip','-j','-6','neigh','show','to',subnet+'::1','dev','eth0']))
        if len(neighbor)!=1 or neighbor[0].get('lladdr')!=gateway_mac or 'PERMANENT' not in neighbor[0].get('state',[]):
            raise RuntimeError(var+' synthetic IPv6 neighbor mismatch')
        before=ipv6_drop_count()
        probe(prefix,'ipv6','fd42:198:18::4','deny')
        after=ipv6_drop_count()
        print(var,'IPv6 FORWARD drop counter',before,'->',after,flush=True)
        if after<=before:raise RuntimeError(var+' IPv6 drop not observed in nftables counters')
        print(var,'active IPv6 FORWARD drop counter PASS',flush=True)
        run(prefix+['ip','-6','route','del','fd42:198:18::/64','via',subnet+'::1','dev','eth0'])
        run(prefix+['ip','-6','neigh','del',subnet+'::1','dev','eth0'])
        run(prefix+['ip','-6','addr','del',subnet+'::2/64','dev','eth0'])
        run(['ip','-6','addr','del',subnet+'::1/64','dev',bridge])
finally:
    run(['sysctl','-qw','net.ipv6.conf.all.forwarding='+old_forward])
print('PASS: functional acceptance (local fixtures and active IPv6 drop counters)',flush=True)
