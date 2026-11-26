"""Production-oriented candidate. Live adapter deliberately sealed.
Transaction engine is testable with a simulated backend; no activation switch.
"""
import datetime as dt
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time
import uuid
import benchmark as b
from legacy_guard import CHAINS, restore, rules

# Only a separately reviewed release may replace this gate. No CLI/env override.
class Failure(RuntimeError): pass
class Incomplete(Failure): pass
class Blocked(Failure): pass

def need(ok, msg):
    if not ok: raise Failure(msg)
def digest(text): return hashlib.sha256(text.encode()).hexdigest()
def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def valid_id(x): return isinstance(x,str) and bool(re.fullmatch(r'[a-f0-9]{64}',x))

def save(path, state):
    tmp=path.with_suffix('.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(state,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if tmp.exists(): tmp.unlink()

@contextmanager
def exclusive_lock(path):
    """No background job. Lock file must live in a trusted private directory."""
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        need(os.fstat(fd).st_mode&0o077==0,'private lock required')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)

class Transaction:
    """One transaction per private directory. Caller holds exclusive host lock."""
    def __init__(self,backend,path,identity,recover=False):
        self.h=backend;self.path=Path(path)
        if recover:
            need(self.path.is_file() and not self.path.is_symlink() and self.path.stat().st_mode&0o077==0,'private journal required')
            self.s=json.loads(self.path.read_text());need(self.s.get('version')==2 and self.s['identity']==identity,'journal version/identity mismatch; manual reconciliation required')
            if self.s.get('pending') and self.s['pending'] not in self.s['uncertain']:
                self.s['uncertain'].append(self.s['pending']);self.event(self.s['pending'],'unresolved_on_reload')
        else:
            need(not self.path.exists(),'journal exists: reconcile first')
            self.s={'version':2,'run':uuid.uuid4().hex,'identity':identity,'phase':'new','events':[],'pending':None,'uncertain':[],'table':None,'legacy':{},'networks':{},'containers':{}}
            self.write()
    def write(self): save(self.path,self.s)
    def event(self,stage,result,**kw):
        self.s['events'].append(dict(time=now(),stage=stage,result=result,**kw));self.write()
    def mutate(self,stage,action,record=None):
        # Retain full intent history even if rollback writes subsequent events.
        self.s['pending']=stage;self.event(stage,'intent')
        try:
            value=action()
            if record: record(value)
        except BaseException:
            self.s['uncertain'].append(stage);self.event(stage,'unknown_or_failed');raise
        self.s['pending']=None;self.event(stage,'result');return value
    def record(self,kind,name,id):
        need(valid_id(id),'invalid immutable resource ID');self.s[kind][name]=id;self.write()
    def record_table(self,value):
        need(isinstance(value,str) and re.fullmatch(r'[a-f0-9]{64}',value),'invalid table fingerprint')
        self.s['table']=value;self.write()
    def record_legacy(self,family,value):
        need(isinstance(value,str) and re.fullmatch(r'[a-f0-9]{64}',value),'invalid legacy fingerprint')
        self.s['legacy'][str(family)]=value;self.write()
    def verify_legacy(self,complete=False):
        if complete:need(set(self.s['legacy'])=={'4','6'},'legacy guard incomplete')
        for f in (4,6):
            expected=self.s['legacy'].get(str(f))
            need(self.h.legacy_fingerprint(f)==expected,'legacy guard missing, changed or unrecorded')
    def guard(self):
        self.verify_legacy(complete=True)
        need(self.s['table'] is not None and self.h.table_fingerprint(self.s['run'])==self.s['table'],'firewall missing or changed')
        self.h.wan_guard()
    def apply(self):
        need(self.s['phase']=='new' and not self.s['pending'] and not self.s['uncertain'],'apply must never retry an uncertain transaction')
        self.s['phase']='applying';self.event('apply','intent')
        try:
            self.h.preflight(self.s['run']);self.event('preflight','verified')
            self.h.native(self.s['run']);self.event('native','verified')
            for f in (4,6):
                self.verify_legacy()
                self.mutate('legacy:'+str(f),lambda:self.h.install_legacy(f),lambda x:self.record_legacy(f,x))
            self.verify_legacy(complete=True)
            self.mutate('firewall',lambda:self.h.install_table(self.s['run']),self.record_table);self.guard()
            for i,(name,*_) in enumerate(b.NETWORKS):
                self.guard();self.mutate('network:'+name,lambda:self.h.create_network(i,self.s['run']),lambda x:self.record('networks',name,x));self.h.verify_network(i,self.s)
            for i,name in enumerate(b.NAMES):
                self.guard();self.mutate('create:'+name,lambda:self.h.create_container(i,self.s),lambda x:self.record('containers',name,x));self.h.verify_container(i,self.s,False)
            for i,name in enumerate(b.NAMES):
                self.guard();self.h.verify_container(i,self.s,False);self.h.bind_check(i)
                self.mutate('start:'+name,lambda:self.h.start(self.s['containers'][name]));self.h.ready(i,self.s);self.guard();self.event('ready:'+name,'verified')
            self.s['phase']='local_ready_external_pending';self.write()
        except BaseException:
            self.rollback();raise
    def stop(self):
        # Even if the firewall vanished, stop known owned endpoints; do not restore foreign rules.
        for i in (1,0):
            name=b.NAMES[i];id=self.s['containers'].get(name)
            if not id: continue
            rows=self.h.inventory('container',self.s['run'])
            if id not in rows: continue
            self.h.verify_container(i,self.s,None)
            if self.h.running(id):
                self.mutate('stop:'+name,lambda:self.h.stop(id));need(not self.h.running(id),'stop not confirmed')
        self.s['phase']='stopped';self.write()
    def rollback(self):
        try:
            self.stop()
            for i in (1,0):
                name=b.NAMES[i];id=self.s['containers'].get(name)
                if id and id in self.h.inventory('container',self.s['run']):
                    self.h.verify_container(i,self.s,None);need(not self.h.running(id),'container still running')
                    self.mutate('remove:'+name,lambda:self.h.remove('container',id))
                    need(id not in self.h.inventory('container',self.s['run']),'container removal not confirmed')
            need(not self.h.inventory('container',self.s['run']),'unrecorded/foreign container; manual reconcile')
            for i in (1,0):
                name=b.NETWORKS[i][0];id=self.s['networks'].get(name)
                if id and id in self.h.inventory('network',self.s['run']):
                    self.h.verify_network(i,self.s);self.h.require_empty(id)
                    self.mutate('remove:'+name,lambda:self.h.remove('network',id))
                    need(id not in self.h.inventory('network',self.s['run']),'network removal not confirmed')
            need(not self.h.inventory('network',self.s['run']),'unrecorded/foreign network; manual reconcile')
            self.h.verify_absence(self.s['run'])
            # A late create/start could still commit after a lost daemon response.
            # Never remove protection merely because a single inventory is empty.
            need(not self.s.get('uncertain'),'unresolved operation outcome; manual reconcile required')
            self.verify_legacy()
            if self.h.table_exists():
                need(self.s['table'] is not None and self.h.table_fingerprint(self.s['run'])==self.s['table'],'unknown firewall ownership')
                self.mutate('remove:firewall',self.h.remove_table)
            need(not self.h.table_exists(),'firewall removal not confirmed')
            # Only remove the independent guard after endpoint absence and primary removal.
            # Recheck inventory, ownership and journal before each family mutation.
            for f in (6,4):
                self.h.verify_absence(self.s['run']);self.verify_legacy()
                need(not self.h.table_exists(),'primary firewall reappeared')
                if str(f) in self.s['legacy']:
                    def remove_guard(f=f):
                        self.h.remove_legacy(f)
                        need(self.h.legacy_fingerprint(f) is None,'legacy removal not confirmed')
                    self.mutate('remove:legacy:'+str(f),remove_guard,lambda _:self.s['legacy'].pop(str(f)))
            self.verify_legacy()
            self.s['phase']='rolled_back_local_external_pending';self.s['pending']=None;self.event('rollback','local_verified')
        except BaseException:
            self.s['phase']='rollback_incomplete';self.event('rollback','incomplete');raise Incomplete('rollback incomplete: retain any existing protection and reconcile') from None

class Host:
    """Unvalidated Linux adapter. Constructor refuses all live use in this release."""
    def __init__(self,cfg,work,uid,gid,sbox_id,expected_ifindex):
        raise Blocked('live lifecycle locked; separate reviewed release required')
        # Unreachable until a separately reviewed release replaces the gate.
        need(os.geteuid()==0,'root required')
        need(not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'),'remote Docker forbidden')
        self.cfg=cfg;self.w=Path(work).resolve();self.uid=uid;self.gid=gid;self.sbox=sbox_id;self.ifindex=expected_ifindex
        need(uid>0 and gid>0 and re.fullmatch(r'sha256:[a-f0-9]{64}',sbox_id),'invalid image identity')
        need(cfg['acme_mode']=='staging','initial release only supports staging')
        need(self.w.is_dir() and self.w.stat().st_uid==0 and self.w.stat().st_mode&0o077==0,'root-owned private directory required')
    def cmd(self,*args,timeout=45,data=None):
        # No shell, no raw stderr in public messages. Local commands only.
        try:r=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout,check=False)
        except (OSError,subprocess.TimeoutExpired):raise Failure('command outcome unknown: '+args[0]) from None
        need(r.returncode==0,'command failed: '+args[0]);return r.stdout.strip()
    def obj(self,*a): return json.loads(self.cmd(*a))
    def inspect(self,kind,id):return self.obj('docker',kind,'inspect',id)[0]
    def inventory(self,kind,run):
        # Inventory succeeds before interpreting absence. Include same-name foreign objects.
        if kind=='container': ids=self.cmd('docker','ps','-aq','--no-trunc').splitlines()
        else: ids=self.cmd('docker','network','ls','-q','--no-trunc').splitlines()
        result={}
        for id in ids:
            x=self.inspect(kind,id);labels=x['Config']['Labels'] if kind=='container' else x.get('Labels');labels=labels or {}
            names=b.NAMES if kind=='container' else [n[0] for n in b.NETWORKS]
            if x['Name'].lstrip('/') in names or labels.get('vpn-benchmark.run')==run:result[x['Id']]=x
        return result
    def table_exists(self):return any(x.get('table',{}).get('family')=='inet' and x['table'].get('name')=='vpn_benchmark' for x in self.obj('nft','-j','list','tables')['nftables'])
    def table_fingerprint(self,run):
        if not self.table_exists():return None
        text=self.cmd('nft','-s','list','table',*b.TABLE)
        return digest(text) if 'chain owner_'+run+' {' in text else None
    @staticmethod
    def legacy_binary(f):
        return {4:'iptables-legacy',6:'ip6tables-legacy'}[f]
    def legacy_snapshot(self,f):
        # Exact scope and first-hook position, preserving actual ordered rule text.
        # Any ambiguous partial chain or unexpected external reference is a hard stop.
        result={}
        for table,chains in CHAINS[f].items():
            lines=self.cmd(self.legacy_binary(f),'-t',table,'-S').splitlines()
            selected=[]
            for chain,hook in chains.items():
                own=[x for x in lines if x=='-N '+chain or x.startswith('-A '+chain+' ')]
                references=[x for x in lines if re.search(r'(?:-j|-g) '+re.escape(chain)+r'(?: |$)',x)]
                if own or references:
                    need(own and own[0]=='-N '+chain and references==['-A '+hook+' -j '+chain],'legacy ownership/jump mismatch')
                    hookrules=[x for x in lines if x.startswith('-A '+hook+' ')]
                    need(hookrules and hookrules[0]==references[0],'legacy jump not first')
                selected.extend(own+references)
            result[table]=selected
        return result
    def legacy_fingerprint(self,f):
        snap=self.legacy_snapshot(f)
        if not any(snap.values()):return None
        return digest(json.dumps(snap,sort_keys=True))
    def verify_legacy_shape(self,f):
        snap=self.legacy_snapshot(f)
        for table,chains in rules(self.cfg['public_ipv4'],f).items():
            for name,entries in chains.items():
                expected=['-N '+name]+['-A '+name+' '+' '.join(x) for x in entries]+['-A '+CHAINS[f][table][name]+' -j '+name]
                observed=[x for x in snap[table] if x=='-N '+name or x.startswith('-A '+name+' ') or x.endswith(' -j '+name)]
                need(observed==expected,'legacy rule readback differs; review native normalization before activation')
    def install_legacy(self,f):
        need(self.legacy_fingerprint(f) is None,'legacy chain conflict')
        self.cmd(self.legacy_binary(f)+'-restore','--noflush',data=restore(self.cfg['public_ipv4'],f))
        self.verify_legacy_shape(f)
        return self.legacy_fingerprint(f)
    def remove_legacy(self,f):
        self.verify_legacy_shape(f)
        self.cmd(self.legacy_binary(f)+'-restore','--noflush',data=restore(self.cfg['public_ipv4'],f,True))
    def wan_guard(self):
        dev=self.cfg['wan_if'];rows=self.obj('ip','-j','-4','addr','show','dev',dev)
        need(len(rows)==1 and rows[0]['ifindex']==self.ifindex and 'UP' in rows[0]['flags'] and any(a.get('local')==self.cfg['public_ipv4'] for a in rows[0]['addr_info']),'WAN address/interface changed')
    def bind_check(self,i):
        for p in ((80,18443,18445) if i==0 else (18444,)):
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:s.bind((self.cfg['public_ipv4'],p))
    def preflight(self,run):
        self.wan_guard();need(not self.table_exists() and not self.inventory('container',run) and not self.inventory('network',run),'existing experimental resources')
        # Unknown Docker proxy/backend or firewall reload semantics are release gates, not guessed here.
        need(self.cmd('docker','context','show')=='default' and self.obj('docker','context','inspect','default')[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','unexpected Docker endpoint')
        need(all(self.legacy_fingerprint(f) is None for f in (4,6)),'legacy guard conflict')
        info=self.obj('docker','info','--format','{{json .}}');need(info.get('FirewallBackend',{}).get('Driver')=='iptables' and 'nf_tables' in self.cmd('iptables','--version'),'unexpected firewall backend');need(not any('rootless' in x or 'userns' in x for x in info.get('SecurityOptions',[])),'unsupported Docker identity mapping')
        need(self.cmd('sysctl','-n','net.ipv4.ip_forward')=='1','IPv4 forwarding disabled')
        bridges={x['ifname'] for x in self.obj('ip','-j','link','show')};need(not bridges.intersection(n[1] for n in b.NETWORKS),'bridge conflict')
        wanted=[ipaddress.ip_network(n[2]) for n in b.NETWORKS]
        routes=self.obj('ip','-j','-4','route','show','table','all')
        for row in routes:
            d=row.get('dst','default')
            if d!='default':need(not any(ipaddress.ip_network(d,strict=False).overlaps(n) for n in wanted),'route overlap')
        for id in self.cmd('docker','network','ls','-q','--no-trunc').splitlines():
            for a in self.inspect('network',id)['IPAM'].get('Config') or []:
                if a.get('Subnet') and ':' not in a['Subnet']:need(not any(ipaddress.ip_network(a['Subnet']).overlaps(n) for n in wanted),'Docker subnet overlap')
        need(self.obj('docker','image','inspect',b.SBOX)[0]['Id']==self.sbox,'sing-box image mismatch')
        need(self.obj('docker','image','inspect',self.cfg['mita_image_id'])[0]['Id']==self.cfg['mita_image_id'],'Mita image mismatch')
        ids=self.cmd('docker','run','--rm','--pull','never','--network','none','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--entrypoint','/bin/sh',self.cfg['mita_image_id'],'-ec','id -u mita; id -g mita').split()
        need(ids==[str(self.uid),str(self.gid)],'Mita identity mismatch')
        self.bind_check(0);self.bind_check(1)
    def native(self,run):
        # Files prepared privately and ownership validated before native invocation.
        for filename,uid,gid,mode in [('sing-box.json',65532,65532,0o600),('mita.json',self.uid,self.gid,0o600),('firewall.nft',0,0,0o600),('resolv.conf',0,0,0o644)]:
            p=self.w/filename;st=p.lstat();need(p.is_file() and not p.is_symlink() and (st.st_uid,st.st_gid,st.st_mode&0o777)==(uid,gid,mode),'config ownership/mode mismatch')
        for p in (self.w/'acme',self.w/'acme'/'staging'):
            st=p.lstat();need(p.is_dir() and not p.is_symlink() and (st.st_uid,st.st_gid,st.st_mode&0o777)==(65532,65532,0o700),'ACME state ownership mismatch')
        text=(self.w/'firewall.nft').read_text();anchor='table inet vpn_benchmark {';need(text.count(anchor)==1,'unexpected table')
        text='create table inet vpn_benchmark\n'+text.replace(anchor,anchor+'\n    chain owner_'+run+' { }\n',1)
        p=self.w/('firewall-'+run+'.nft')
        with open(p,'x',opener=lambda p,f:os.open(p,f,0o600)) as f:f.write(text);f.flush();os.fsync(f.fileno())
        self.cmd('nft','-c','-f',str(p))
        for f in (4,6):
            self.cmd(self.legacy_binary(f)+'-restore','--noflush','--test',data=restore(self.cfg['public_ipv4'],f))
        # Full mark/collision audit, including tc/BPF/policy routing, remains a separate gate.
        # This narrow check is NOT proof that the permit bit is free.
        for args in [('nft','-s','list','ruleset'),('iptables-legacy-save',),('ip6tables-legacy-save',)]:
            need(not re.search(r'40000000|1073741824',self.cmd(*args),re.I),'permit bit collision')
        # Writable state is verified on a separate offline probe directory.
        import tempfile
        with tempfile.TemporaryDirectory(prefix='acme-probe-',dir=self.w) as temp:
            os.chown(temp,65532,65532);os.chmod(temp,0o700)
            self.cmd('docker','run','--rm','--pull','never','--network','none','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--mount','type=bind,src='+temp+',dst=/acme','--entrypoint','/bin/sh',self.cfg['mita_image_id'],'-ec','umask 077; touch /acme/.write-test; rm /acme/.write-test')
        self.cmd('docker','run','--rm','--pull','never','--network','none','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--mount','type=bind,src='+str(self.w/'sing-box.json')+',dst=/config.json,readonly','--entrypoint','sing-box',self.sbox,'check','-c','/config.json')
    def install_table(self,run):
        need(not self.table_exists(),'table already exists');self.cmd('nft','-f',str(self.w/('firewall-'+run+'.nft')));return self.table_fingerprint(run)
    def commands(self,run):return [shlex.split(line) for _,line in b.plan(self.cfg,self.w,self.uid,self.gid,run)]
    def create_network(self,i,run):return self.cmd(*self.commands(run)[i])
    def verify_network(self,i,s):
        name,bridge,subnet,_=b.NETWORKS[i];id=s['networks'][name];x=self.inspect('network',id)
        need(x['Id']==id and x['Name']==name and x['Labels'].get('vpn-benchmark.run')==s['run'] and x['Labels'].get('vpn-benchmark')=='v1.5' and x['Driver']=='bridge' and not x['EnableIPv6'] and x['Options'].get('com.docker.network.bridge.name')==bridge and [a.get('Subnet') for a in x['IPAM']['Config']]==[subnet],'network mismatch')
    def create_container(self,i,s):return self.cmd(*self.commands(s['run'])[2+i])
    def verify_container(self,i,s,running):
        name=b.NAMES[i];id=s['containers'][name];x=self.inspect('container',id);h=x['HostConfig'];c=x['Config'];n,_,_,addr=b.NETWORKS[i]
        need(x['Id']==id and x['Name']=='/'+name and c['Labels'].get('vpn-benchmark.run')==s['run'] and c['Labels'].get('vpn-benchmark')=='v1.5','container ownership mismatch')
        need(x['Image']==(self.sbox,self.cfg['mita_image_id'])[i] and c['User']==('65532:65532',f'{self.uid}:{self.gid}')[i],'image/user mismatch')
        need(not h['Privileged'] and h['ReadonlyRootfs'] and h['RestartPolicy']['Name']=='no' and 'ALL' in h['CapDrop'] and not h.get('CapAdd') and any(z.startswith('no-new-privileges') for z in h['SecurityOpt']),'security mismatch')
        need(h['Memory']==(384,256)[i]*1024**2 and h['MemorySwap']==h['Memory'] and h['NanoCpus']==750000000 and h['PidsLimit']==128,'limits mismatch')
        ports={18443:18443,18445:18445,80:8080} if i==0 else {18444:18444}
        expected={str(d)+'/tcp':[{'HostIp':self.cfg['public_ipv4'],'HostPort':str(p)}] for p,d in ports.items()}
        need(h['PortBindings']==expected and h['NetworkMode'] in (n,s['networks'][n]),'port/network mismatch')
        mounts={'/config.json':('sing-box.json' if i==0 else 'mita.json',False),'/etc/resolv.conf':('resolv.conf',False)}
        if i==0:mounts['/acme']=('acme',True)
        actual={m['Destination']:(m['Source'],m['RW']) for m in x['Mounts'] if m['Type']=='bind'}
        need(actual=={d:(str(self.w/src),rw) for d,(src,rw) in mounts.items()},'bind mount mismatch')
        if running is True:
            nets=x['NetworkSettings']['Networks'];need(x['State']['Running'] and not x['State']['OOMKilled'] and set(nets)=={n} and nets[n]['IPAddress']==addr and nets[n]['NetworkID']==s['networks'][n],'running endpoint mismatch')
        elif running is False:need(not x['State']['Running'],'already running')
    def start(self,id):self.cmd('docker','start',id)
    def ready(self,i,s):
        id=s['containers'][b.NAMES[i]];addr=b.NETWORKS[i][3]
        for _ in range(12):
            self.verify_container(i,s,True);pid=str(self.inspect('container',id)['State']['Pid'])
            sockets=self.cmd('nsenter','-t',pid,'-n','ss','-H','-lnt')
            ports=(18443,18445) if i==0 else (18444,)
            if all(re.search(r'(?<![0-9.])'+re.escape(addr)+':'+str(p)+r'(?:\s|$)',sockets) for p in ports):
                if i==1:need('mita server status is "RUNNING"' in self.cmd('docker','exec',id,'/usr/local/bin/mita','status'),'Mita not ready')
                return
            time.sleep(1)
        raise Failure('local readiness timeout; no TLS bypass')
    def running(self,id):return self.inspect('container',id)['State']['Running']
    def stop(self,id):self.cmd('docker','stop','--time','10',id)
    def require_empty(self,id):need(not self.inspect('network',id)['Containers'],'network has endpoints')
    def remove(self,kind,id):self.cmd('docker',kind,'rm',id)
    def verify_absence(self,run):
        need(not self.inventory('container',run) and not self.inventory('network',run),'Docker residuals')
        need(not {x['ifname'] for x in self.obj('ip','-j','link','show')}.intersection(n[1] for n in b.NETWORKS),'bridge residuals')
        nat=self.cmd('nft','-s','list','ruleset');addrs=[n[3] for n in b.NETWORKS]
        need(not any('dnat' in line and 'ct status dnat' not in line and any(a in line for a in addrs) for line in nat.splitlines()),'DNAT residuals')
        for executable in ('iptables-legacy-save','ip6tables-legacy-save','iptables-nft-save','ip6tables-nft-save'):
            saved=self.cmd(executable)
            need(not any('DNAT' in line and any(a in line for a in addrs) for line in saved.splitlines()),'DNAT residual in iptables backend')
        # Production acceptance also requires independent external probes, not this local check alone.
        self.bind_check(0);self.bind_check(1)
    def remove_table(self):self.cmd('nft','delete','table',*b.TABLE)

if __name__=='__main__':
    print('BLOCKED: live adapter requires separately reviewed release; offline tests only')
    raise SystemExit(78)
