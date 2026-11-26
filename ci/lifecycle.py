#!/usr/bin/env python3
"""Transactional v1.5 lifecycle, explicitly locked to disposable GitHub CI.

The runtime adapter deliberately uses the existing synthetic WAN and local TLS
fixture. It does not accept production settings, credentials or interfaces.
"""
import datetime, fcntl, hashlib, json, os, pathlib, re, socket, subprocess, sys, time, uuid

IP='198.18.254.1'
PORTS=(80,18443,18444,18445)
TABLE=('inet','vpn_benchmark')
NETS=(('vb-sbox','br-vb-sbox','172.30.241.0/28','172.30.241.2'),('vb-mita','br-vb-mita','172.30.242.0/28','172.30.242.2'))
NAMES=('vpn-test-singbox','vpn-test-mita')
LABEL='vpn-benchmark'
STAGES=('preflight','native','firewall','network_sbox','network_mita','namespace','create_sbox','create_mita','start_sbox','ready_sbox','start_mita','ready_mita')
LOST=('firewall','network_sbox','network_mita','create_sbox','create_mita','start_sbox','start_mita')
class Failure(Exception): pass
class Injected(Failure): pass
class Lost(Failure): pass
class Incomplete(Failure): pass
def need(ok,msg):
    if not ok: raise Failure(msg)
def call(args,timeout=45,allow=False):
    # No raw logs, no command arguments from errors in public output.
    try: p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired): raise Failure('command unavailable or timed out: '+args[0]) from None
    if p.returncode and not allow: raise Failure('command failed: '+args[0]+' rc='+str(p.returncode))
    return p
def out(*args): return call(list(args)).stdout.strip()
def obj(*args): return json.loads(out(*args))
def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def guard():
    need(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','REFUSE: disposable GitHub-hosted runner only')
def exact_id(s): return bool(re.fullmatch(r'[a-f0-9]{64}',s))
def inventory(kind):
    if kind=='container': rows=out('docker','ps','-a','--no-trunc','--format','{{json .}}')
    else: rows=out('docker','network','ls','--no-trunc','--format','{{json .}}')
    return [json.loads(x) for x in rows.splitlines() if x]
def table_exists():
    return {'family':TABLE[0],'name':TABLE[1]} in [{k:v for k,v in x['table'].items() if k in ('family','name')} for x in obj('nft','-j','list','tables')['nftables'] if 'table' in x]
def links(): return {x['ifname'] for x in obj('ip','-j','link','show')}
def namespaces(): return {x.split()[0] for x in out('ip','netns','list').splitlines() if x}
def table_text(): return out('nft','-s','list','table',*TABLE)
def inspect(kind,id): return obj('docker',kind,'inspect',id)[0]
def owned_rows(kind,runid):
    # Inspect exact candidate names and all run-labelled entries. Successful
    # inventories, never a failed inspect interpreted as absence.
    result={}
    for row in inventory(kind):
        name=row.get('Names') if kind=='container' else row.get('Name')
        if name in (NAMES if kind=='container' else [n[0] for n in NETS]) or ('vpn-benchmark.run='+runid) in (row.get('Labels') or ''):
            x=inspect(kind,row['ID'])
            result[x['Id']]=x
    # Network ls may omit Labels; query the label independently.
    if kind=='network':
        for id in out('docker','network','ls','--no-trunc','--filter','label=vpn-benchmark.run='+runid,'-q').splitlines():
            x=inspect(kind,id);result[x['Id']]=x
    return result
def write_state(path,state):
    tmp=path.with_suffix('.tmp')
    with open(tmp,'w',opener=lambda p,f:os.open(p,f,0o600)) as stream:
        json.dump(state,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def read_state(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_mode&0o077==0,'private journal required')
    return json.loads(path.read_text())

class Lifecycle:
    def __init__(self,work,state_path,sbox,mita,uid,gid,fault='',recover=False):
        self.w=work;self.path=state_path;self.sbox=sbox;self.mita=mita;self.uid=uid;self.gid=gid;self.fault=fault
        need(work.is_absolute() and ',' not in str(work) and '\n' not in str(work),'invalid work path')
        need(all(re.fullmatch(r'sha256:[0-9a-f]{64}',x) for x in (sbox,mita)) and uid>0 and gid>0,'invalid pinned image or user')
        if recover:
            self.s=read_state(state_path)
            need(self.s['work']==str(work) and self.s['images']==[sbox,mita] and self.s['identity']==[uid,gid],'journal identity mismatch')
        else:
            need(not state_path.exists(),'journal already exists; reconcile before apply')
            self.s={'run':uuid.uuid4().hex,'work':str(work),'images':[sbox,mita],'identity':[uid,gid],
                    'events':[],'pending':None,'table':None,'networks':{},'containers':{},'namespace':False,'ns_inode':None,'veth':False,'ifindex':None,'phase':'new'}
            self.save()
    def save(self):write_state(self.path,self.s)
    def event(self,stage,result,**fields):
        self.s['events'].append(dict(time=utc(),stage=stage,result=result,**fields));self.save()
    def point(self,stage):
        self.event(stage,'verified')
        print('LIFECYCLE checkpoint '+stage,flush=True)
        if self.fault=='after:'+stage: raise Injected(stage)
    def mutate(self,stage,args,accept=None):
        self.s['pending']=stage;self.event(stage,'intent',command=args)
        response=call(args).stdout.strip()
        if self.fault=='lost:'+stage:raise Lost(stage)
        if accept is not None:accept(response)
        self.s['pending']=None;self.event(stage,'result',exit=0)
        return response
    def table_guard(self):
        out(sys.executable,'ci/legacy_guard_ci.py','check',str(self.w))
        need(self.s['table'] is not None and table_exists(),'firewall missing')
        need(sha(table_text())==self.s['table'],'firewall fingerprint changed')
    def preflight(self):
        out(sys.executable,'ci/legacy_guard_ci.py','check',str(self.w))
        need(not table_exists(),'existing firewall')
        need(not owned_rows('container',self.s['run']) and not owned_rows('network',self.s['run']),'existing Docker objects')
        need(not links().intersection({'vb-wan','vb-peer',NETS[0][1],NETS[1][1]}) and 'vb-client' not in namespaces(),'existing lab interface')
        need(out('sysctl','-n','net.ipv4.ip_forward')=='1','IPv4 forwarding unavailable')
        for image in (self.sbox,self.mita):need(obj('docker','image','inspect',image)[0]['Id']==image,'image ID mismatch')
        self.point('preflight')
    def native(self):
        # The immutable source template is checked separately from the lab variant.
        for file in ('firewall-original.nft','firewall.nft'):out('nft','-c','-f',str(self.w/file))
        # Add an inert, unique ownership chain; not a new hook or permission.
        original=(self.w/'firewall.nft').read_text()
        anchor='table inet vpn_benchmark {'
        need(original.count(anchor)==1,'unexpected firewall template')
        text=original.replace(anchor,anchor+'\n    chain owner_'+self.s['run']+' { }\n',1)
        target=self.w/('firewall-'+self.s['run']+'.nft')
        text='create table inet vpn_benchmark\n'+text
        target.write_text(text);target.chmod(0o600)
        self.s['firewall_file']=str(target);self.s['firewall_input_hash']=sha(text);self.save()
        out('nft','-c','-f',str(target))
        for file in ('sing-box-acme.json','sing-box-lab.json'):
            out('docker','run','--rm','--network','none','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--entrypoint','sing-box','-v',str(self.w)+':/lab:ro',self.sbox,'check','-c','/lab/'+file)
        # v1.5 writable state, only one dedicated bind; no real ACME requests.
        d=self.w/'acme';d.mkdir(mode=0o700,exist_ok=True);(d/'staging').mkdir(mode=0o700,exist_ok=True)
        for p in (d,d/'staging'):os.chown(p,65532,65532);p.chmod(0o700)
        out('docker','run','--rm','--network','none','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--mount','type=bind,src='+str(d)+',dst=/acme','--entrypoint','/bin/sh',self.mita,'-ec','umask 077; touch /acme/staging/.write-test; rm /acme/staging/.write-test')
        self.point('native')
    def record_table(self,_=''):
        need(table_exists() and 'chain owner_'+self.s['run'] in table_text(),'table ownership not established')
        self.s['table']=sha(table_text());self.save()
    def label_args(self):return ['--label',LABEL+'=v1.5','--label',LABEL+'.run='+self.s['run']]
    def verify_net(self,i,x):
        n,bridge,subnet,_=NETS[i]
        need(exact_id(x['Id']) and x['Name']==n and x['Labels'].get(LABEL+'.run')==self.s['run'] and x['Labels'].get(LABEL)=='v1.5','network ownership mismatch')
        need(x['Driver']=='bridge' and not x['EnableIPv6'] and x['Options'].get('com.docker.network.bridge.name')==bridge and [a.get('Subnet') for a in x['IPAM']['Config']]==[subnet],'network config mismatch')
    def net(self,i):
        n,bridge,subnet,_=NETS[i];stage=('network_sbox','network_mita')[i]
        self.table_guard()
        def accept(id):
            need(exact_id(id),'missing network ID');self.s['networks'][n]=id;self.save();self.verify_net(i,inspect('network',id))
        self.mutate(stage,['docker','network','create',*self.label_args(),'--driver','bridge','--ipv6=false','--subnet',subnet,'--opt','com.docker.network.bridge.name='+bridge,n],accept)
        self.point(stage)
    def namespace(self):
        self.table_guard()
        # The veth is a CI fixture only, created after builds and bridges.
        self.s['pending']='namespace';self.event('namespace','intent')
        out('ip','netns','add','vb-client');self.s['namespace']=True;self.s['ns_inode']=os.stat('/run/netns/vb-client').st_ino;self.save()
        out('ip','link','add','vb-wan','type','veth','peer','name','vb-peer');self.s['veth']=True;self.s['ifindex']=pathlib.Path('/sys/class/net/vb-wan/ifindex').read_text().strip();self.save()
        out('ip','link','set','vb-peer','netns','vb-client')
        out('ip','addr','add',IP+'/29','dev','vb-wan');out('ip','link','set','vb-wan','up')
        for a in ('198.18.254.2','198.18.254.3'):out('ip','-n','vb-client','addr','add',a+'/29','dev','vb-peer')
        for dev in ('lo','vb-peer'):out('ip','-n','vb-client','link','set',dev,'up')
        self.s['ifindex']=pathlib.Path('/sys/class/net/vb-wan/ifindex').read_text().strip()
        self.s['pending']=None;self.save();self.wan_guard();self.point('namespace')
    def wan_guard(self):
        need(self.s['veth'] and pathlib.Path('/sys/class/net/vb-wan/ifindex').read_text().strip()==self.s['ifindex'],'WAN identity mismatch')
        def ips(*args):return {a['local'] for x in obj(*args) for a in x.get('addr_info',[]) if a.get('prefixlen')==29}
        need(IP in ips('ip','-j','-4','addr','show','dev','vb-wan'),'synthetic WAN address missing')
        need({'198.18.254.2','198.18.254.3'}<=ips('ip','-n','vb-client','-j','-4','addr','show','dev','vb-peer'),'synthetic tester address missing')
        need(not out('ip','-n','vb-client','route','show','default') and not out('ip','-n','vb-client','-6','route','show','default'),'unexpected namespace default route')
    def ports(self,i):return {18443:18443,18445:18445,80:8080} if i==0 else {18444:18444}
    def command(self,i):
        n,_,_,addr=NETS[i]
        # Same Docker limits, mounts and publication layout as v1.5 plan,
        # except local TLS test files and synthetic address (CI adapter).
        common=['--pull','never','--restart','no','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--cpus','0.75','--pids-limit','128','--log-driver','json-file','--log-opt','max-size=5m','--log-opt','max-file=2']
        a=['docker','create','--name',NAMES[i],*self.label_args(),*common,'--network',n,'--ip',addr]
        def mount(src,dst,ro=True):return ['--mount','type=bind,src='+str(self.w/src)+',dst='+dst+(',readonly' if ro else '')]
        for p,d in self.ports(i).items():a+=['-p',f'{IP}:{p}:{d}/tcp']
        a+=mount('resolv.conf','/etc/resolv.conf')
        if i==0:
            a+=['--user','65532:65532','--memory','384m','--memory-swap','384m',*mount('sing-box-lab.json','/config.json'),*mount('acme','/acme',False),*mount('cert.pem','/lab/cert.pem'),*mount('key.pem','/lab/key.pem'),'--entrypoint','sing-box',self.sbox,'run','-c','/config.json']
        else:
            a+=['--user',f'{self.uid}:{self.gid}','--memory','256m','--memory-swap','256m']
            for d in ('/var/run/mita','/etc/mita','/var/lib/mita'):a+=['--tmpfs',f'{d}:rw,nosuid,nodev,noexec,uid={self.uid},gid={self.gid},mode=0700']
            a+=mount('mita.json','/config.json')+['-e','MITA_UDS_PATH=/var/run/mita/mita.sock','-e','MITA_CONFIG_JSON_FILE=/config.json','--entrypoint','/usr/local/bin/mita',self.mita,'run']
        return a
    def verify_container(self,i,x,running=False):
        h=x['HostConfig'];cfg=x['Config'];n,_,_,addr=NETS[i]
        need(exact_id(x['Id']) and x['Name']=='/'+NAMES[i] and cfg['Labels'].get(LABEL+'.run')==self.s['run'] and cfg['Labels'].get(LABEL)=='v1.5','container ownership mismatch')
        need(x['Image']==(self.sbox,self.mita)[i] and cfg['User']==('65532:65532',f'{self.uid}:{self.gid}')[i],'image/user mismatch')
        need(not h['Privileged'] and h['ReadonlyRootfs'] and h['RestartPolicy']['Name']=='no' and 'ALL' in h['CapDrop'] and not h.get('CapAdd') and any(s.startswith('no-new-privileges') for s in h['SecurityOpt']),'container security mismatch')
        need(h['Memory']==(384,256)[i]*1024**2 and h['MemorySwap']==h['Memory'] and h['NanoCpus']==750000000 and h['PidsLimit']==128,'limits mismatch')
        expected={str(d)+'/tcp':[{'HostIp':IP,'HostPort':str(p)}] for p,d in self.ports(i).items()}
        need(h['PortBindings']==expected and h['NetworkMode'] in (n,self.s['networks'][n]),'publication/network mismatch')
        actual_mounts={m['Destination']:(m['Source'],m['RW']) for m in x['Mounts'] if m['Type']=='bind'}
        paths={'/config.json':('sing-box-lab.json' if i==0 else 'mita.json',False),'/etc/resolv.conf':('resolv.conf',False)}
        if i==0:paths.update({'/acme':('acme',True),'/lab/cert.pem':('cert.pem',False),'/lab/key.pem':('key.pem',False)})
        need(actual_mounts=={d:(str(self.w/src),rw) for d,(src,rw) in paths.items()},'bind mount mismatch')
        if running:
            networks=x['NetworkSettings']['Networks']
            need(x['State']['Running'] and not x['State']['OOMKilled'] and set(networks)=={n} and networks[n]['IPAddress']==addr and networks[n]['NetworkID']==self.s['networks'][n],'running endpoint mismatch')
    def create(self,i):
        stage=('create_sbox','create_mita')[i];self.table_guard();self.wan_guard()
        def accept(id):
            need(exact_id(id),'missing container ID');self.s['containers'][NAMES[i]]=id;self.save();self.verify_container(i,inspect('container',id))
        self.mutate(stage,self.command(i),accept);self.point(stage)
    def start(self,i):
        self.table_guard();self.wan_guard();id=self.s['containers'][NAMES[i]]
        self.verify_container(i,inspect('container',id))
        for port in self.ports(i):
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:s.bind((IP,port))
        stage=('start_sbox','start_mita')[i]
        self.mutate(stage,['docker','start',id]);self.point(stage)
        for _ in range(12):
            x=inspect('container',id)
            need(x['State']['Running'],'container exited during startup')
            self.verify_container(i,x,True)
            if i==1:
                status=call(['docker','exec',id,'/usr/local/bin/mita','status'],timeout=5,allow=True)
                if status.returncode or 'mita server status is "RUNNING"' not in status.stdout+status.stderr:time.sleep(1);continue
            ports=[p for p in self.ports(i) if p!=80]
            if all(call(['ip','netns','exec','vb-client',sys.executable,'ci/probe.py','198.18.254.2',IP,str(p),'allow'],allow=True,timeout=5).returncode==0 for p in ports):
                self.table_guard();self.wan_guard();self.point(('ready_sbox','ready_mita')[i]);return
            time.sleep(1)
        raise Failure('readiness timeout')
    def apply(self):
        self.preflight();self.native()
        need(not table_exists(),'firewall appeared before apply')
        self.mutate('firewall',['nft','-f',self.s['firewall_file']],self.record_table);self.table_guard();self.point('firewall')
        self.net(0);self.net(1);self.namespace();self.create(0);self.create(1);self.start(0);self.start(1)
        self.s['phase']='ready';self.save()
    def stop(self,fail_stop=False):
        for i in (1,0):
            id=self.s['containers'].get(NAMES[i])
            if id:
                rows=owned_rows('container',self.s['run'])
                if id in rows:
                    self.verify_container(i,rows[id])
                    if rows[id]['State']['Running']:
                        if fail_stop:raise Failure('injected stop failure')
                        self.mutate('stop_'+NAMES[i],['docker','stop','--time','10',id])
                        need(not inspect('container',id)['State']['Running'],'stop not confirmed')
        self.s['phase']='stopped';self.save()
    def verify_absence(self):
        need(not owned_rows('container',self.s['run']) and not owned_rows('network',self.s['run']),'Docker objects remain')
        need(not links().intersection({NETS[0][1],NETS[1][1]}),'bridge remains')
        # Inspect NAT and listening sockets before removing firewall. Match only
        # synthetic bindings, not unrelated runner services using these ports.
        nat=out('nft','-s','list','ruleset')
        need(not self._dnat_remaining(nat),'experimental DNAT remains')
        sockets=out('ss','-H','-lnt')
        need(not any(re.search(r'(?<![0-9.])'+re.escape(IP)+':'+str(p)+r'(?:\s|$)',sockets) for p in PORTS),'synthetic listener remains')
    def _dnat_remaining(self,nat):
        return any('dnat' in line and any(a in line for a in (NETS[0][3],NETS[1][3])) and not ('ct status dnat' in line) for line in nat.splitlines())
    def rollback(self,fail_remove=False,fail_stop=False,fail_network=False):
        # Unknown IDs are deliberately not adopted here. Reconcile is explicit.
        try:
            self.stop(fail_stop=fail_stop)
            for i in (1,0):
                n=NAMES[i];id=self.s['containers'].get(n);rows=owned_rows('container',self.s['run'])
                if id and id in rows:
                    self.verify_container(i,rows[id]);need(not rows[id]['State']['Running'],'container still running')
                    if fail_remove:raise Failure('injected remove failure')
                    self.mutate('remove_'+n,['docker','rm',id])
                    need(id not in owned_rows('container',self.s['run']),'container removal not confirmed')
            need(not owned_rows('container',self.s['run']),'unrecorded container; reconcile required')
            for i in (1,0):
                n=NETS[i][0];id=self.s['networks'].get(n);rows=owned_rows('network',self.s['run'])
                if id and id in rows:
                    self.verify_net(i,rows[id]);need(not rows[id]['Containers'],'network endpoints remain')
                    if fail_network:raise Failure('injected network removal failure')
                    self.mutate('remove_'+n,['docker','network','rm',id])
                    need(id not in owned_rows('network',self.s['run']),'network removal not confirmed')
            self.verify_absence()
            # Only CI fixture names created by this journal are touched.
            # Delete the owned veth while the owned peer namespace still exists.
            # Namespace teardown can destroy the pair asynchronously. On any
            # nonzero deletion result, accept only a successful fresh absence audit.
            if self.s['namespace'] and 'vb-client' in namespaces():
                need(os.stat('/run/netns/vb-client').st_ino==self.s['ns_inode'],'namespace ownership uncertain')
            if self.s['veth'] and 'vb-wan' in links():
                need(pathlib.Path('/sys/class/net/vb-wan/ifindex').read_text().strip()==self.s['ifindex'],'veth ownership uncertain')
                p=call(['ip','link','del','vb-wan'],allow=True)
                if p.returncode:
                    print('LIFECYCLE veth delete rc='+str(p.returncode)+'; verifying absence',flush=True)
                need(not links().intersection({'vb-wan','vb-peer'}),'veth deletion not confirmed')
            if self.s['namespace'] and 'vb-client' in namespaces():
                need(os.stat('/run/netns/vb-client').st_ino==self.s['ns_inode'],'namespace ownership uncertain')
                p=call(['ip','netns','del','vb-client'],allow=True)
                if p.returncode:
                    print('LIFECYCLE namespace delete rc='+str(p.returncode)+'; verifying absence',flush=True)
                need('vb-client' not in namespaces(),'namespace deletion not confirmed')
            need('vb-client' not in namespaces() and not links().intersection({'vb-wan','vb-peer'}),'namespace or veth remains')
            if table_exists():
                self.table_guard()
                self.mutate('remove_firewall',['nft','delete','table',*TABLE])
            need(not table_exists(),'firewall removal not confirmed')
            self.s['phase']='rolled_back';self.s['pending']=None;self.event('rollback','verified')
        except (Failure,OSError,ValueError,KeyError) as exc:
            self.s['phase']='rollback_incomplete';self.event('rollback','incomplete')
            # Failure messages are authored static assertions or executable/exit
            # codes from call(), never raw subprocess output or config values.
            reason=str(exc) if isinstance(exc,Failure) else type(exc).__name__
            print('LIFECYCLE rollback diagnostic: '+reason,flush=True)
            raise Incomplete('rollback incomplete; retain existing firewall') from None
    def reconcile_ci(self,stage,reference):
        # Explicit CI-only reconciliation after simulated lost response.
        # Do not use this as an automatic ownership-adoption policy on a host.
        need(self.s['phase']=='rollback_incomplete','reconcile requires failed rollback')
        intents=[e for e in self.s['events'] if e['stage']==stage and e['result']=='intent']
        need(len(intents)==1,'missing unique command intent')
        def created_after(x):
            created=datetime.datetime.fromisoformat(x['Created'].replace('Z','+00:00'))
            intended=datetime.datetime.fromisoformat(intents[0]['time'])
            need(created>=intended-datetime.timedelta(seconds=2),'resource predates intent')
        if stage=='firewall':
            text=table_text()
            need('chain owner_'+self.s['run'] in text and sha(text.replace('owner_'+self.s['run'],'owner_REFERENCE'))==reference,'unverified table after lost response')
            self.record_table()
        elif stage.startswith('network_'):
            i=0 if stage.endswith('sbox') else 1
            rows=owned_rows('network',self.s['run'])
            matches=[x for x in rows.values() if x['Name']==NETS[i][0]]
            need(len(matches)==1,'ambiguous network');self.verify_net(i,matches[0]);created_after(matches[0])
            self.s['networks'][NETS[i][0]]=matches[0]['Id']
        elif stage.startswith('create_'):
            i=0 if stage.endswith('sbox') else 1
            rows=owned_rows('container',self.s['run'])
            matches=[x for x in rows.values() if x['Name']=='/'+NAMES[i]]
            need(len(matches)==1,'ambiguous container');self.verify_container(i,matches[0]);created_after(matches[0])
            self.s['containers'][NAMES[i]]=matches[0]['Id']
        else:raise Failure('unexpected reconcile stage')
        self.event(stage,'explicit_ci_reconcile')
def assert_clean():
    need(not table_exists() and not links().intersection({'vb-wan','vb-peer',NETS[0][1],NETS[1][1]}) and 'vb-client' not in namespaces(),'residual lab network/firewall')
    need(not owned_rows('container','unused') and not owned_rows('network','unused'),'residual named Docker objects')
def matrix(work,sbox,mita,uid,gid):
    # Reuse downloaded immutable images; never repeat a failed create.
    def new(fault):
        return Lifecycle(work,work/('journal-'+uuid.uuid4().hex+'.json'),sbox,mita,uid,gid,fault)
    l=None
    try:
        l=new('');l.apply()
        reference=sha(table_text().replace('owner_'+l.s['run'],'owner_REFERENCE'))
        l.rollback();assert_clean();print('LIFECYCLE PASS normal apply/rollback',flush=True)
        for stage in STAGES:
            l=new('after:'+stage)
            try:l.apply();raise Failure('fault not injected')
            except Injected as e:need(str(e)==stage,'wrong injected stage')
            l.rollback();assert_clean();print('LIFECYCLE PASS after:'+stage,flush=True)
        for stage in LOST:
            l=new('lost:'+stage)
            try:l.apply();raise Failure('lost response not injected')
            except Lost as e:need(str(e)==stage,'wrong lost response stage')
            if stage.startswith('start_'):
                l.rollback();assert_clean()
            else:
                try:l.rollback();raise Failure('unrecorded resource was automatically removed')
                except Incomplete:need(table_exists(),'firewall removed during uncertainty')
                print('LIFECYCLE PASS retain firewall on lost:'+stage,flush=True)
                l.reconcile_ci(stage,reference);l.rollback();assert_clean()
            print('LIFECYCLE PASS lost:'+stage,flush=True)
        for flag in ('fail_stop','fail_remove','fail_network'):
            l=new('');l.apply()
            try:l.rollback(**{flag:True});raise Failure('rollback fault not injected')
            except Incomplete:
                need(table_exists(),'firewall removed before endpoint cleanup')
                retained=owned_rows('network' if flag=='fail_network' else 'container',l.s['run'])
                need(bool(retained),'missing expected retained resource')
            print('LIFECYCLE PASS retain firewall on '+flag,flush=True)
            # Reopen durable journal, simulating a separate recovery invocation.
            recovered=Lifecycle(work,l.path,sbox,mita,uid,gid,recover=True);recovered.rollback();assert_clean()
            print('LIFECYCLE PASS recovery from journal '+flag,flush=True)
        print('LIFECYCLE MATRIX PASS',flush=True)
    except BaseException:
        if l is not None and l.s['phase']!='rolled_back':
            try:l.rollback()
            except Incomplete:print('LIFECYCLE: rollback incomplete; retain journal and protection',flush=True)
        raise
def main():
    guard()
    os.umask(0o077)
    action=sys.argv[1];work=pathlib.Path(sys.argv[2]).resolve()
    sbox,mita=os.environ['VB_SBOX_IMAGE'],os.environ['VB_MITA_IMAGE']
    uid,gid=int(os.environ['VB_MITA_UID']),int(os.environ['VB_MITA_GID'])
    lockpath='/run/lock/vpn-benchmark-ci-lifecycle.lock'
    with open(lockpath,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if action=='matrix':matrix(work,sbox,mita,uid,gid);return
        path=work/'lifecycle.json'
        if action=='apply':
            l=Lifecycle(work,path,sbox,mita,uid,gid)
            try:l.apply()
            except BaseException:
                l.rollback()
                raise
        elif action in ('stop','rollback','verify'):
            l=Lifecycle(work,path,sbox,mita,uid,gid,recover=True)
            if action=='stop':l.stop()
            elif action=='verify':
                l.table_guard();l.wan_guard()
                for i,n in enumerate(NAMES):l.verify_container(i,inspect('container',l.s['containers'][n]),True)
                print('LIFECYCLE PASS ready state verified',flush=True)
            else:l.rollback();assert_clean()
        else:raise Failure('unsupported action')
if __name__=='__main__':
    try:main()
    except (Failure,OSError,KeyError,ValueError,IndexError) as e:
        print('LIFECYCLE FAIL: '+(str(e) if isinstance(e,Failure) else type(e).__name__),file=sys.stderr);sys.exit(1)
