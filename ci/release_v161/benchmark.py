#!/usr/bin/env python3
"""v1.6.2 RC: operational CLI tested only on a disposable synthetic hosted VM.
No production activation switch. Reuses the sealed v1.5 implementation.
"""
import argparse, hashlib, json, os, pathlib, stat, sys, fcntl, uuid
from contextlib import contextmanager
HERE=pathlib.Path(__file__).resolve().parent
V2=HERE.parent/'transaction_v2'
sys.path.insert(0,str(V2))
import integration as lab
import benchmark as base
from lifecycle import Transaction, Failure, Incomplete, need, save
WORK=pathlib.Path('/var/lib/vpn-benchmark-v161-ci')
LOCK=pathlib.Path('/var/lib/vpn-benchmark-v161-ci.lock')
FILES={'sing-box.json':(65532,65532,0o600),'mita.json':None,'firewall.nft':(0,0,0o600),'resolv.conf':(0,0,0o644),'acme/cert.pem':(65532,65532,0o600),'acme/key.pem':(65532,65532,0o600)}
class Refusal(Failure):
    def __init__(self,code):
        self.code=code
        super().__init__(code)
class JournalIO(Refusal):
    def __init__(self):super().__init__('JOURNAL_IO_ERROR')
def require_code(ok,code):
    if not ok:raise Refusal(code)
def trusted(path,mode=0o600):
    s=path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1,'unsafe root-owned file')
    return path
def directory():
    s=WORK.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'unsafe fixed work directory')
    need(WORK.resolve()==WORK,'symlink work directory forbidden')
def read_json(p):
    return json.loads(trusted(p).read_text())
def syncdir(p):
    fd=os.open(p,os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def initialize_lock():
    # Fixture preparation only. Never replace, unlink or recreate an existing lock.
    lab.gate()
    fd=os.open(LOCK,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:os.fsync(fd)
    finally:os.close(fd)
    syncdir(LOCK.parent)
@contextmanager
def lock(readonly=False):
    flags=os.O_RDONLY if readonly else os.O_RDWR
    try:fd=os.open(LOCK,flags|os.O_NOFOLLOW)
    except FileNotFoundError:raise Refusal('LOCK_MISSING') from None
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'unsafe host lock')
        try:fcntl.flock(fd,(fcntl.LOCK_SH if readonly else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        except BlockingIOError:raise Refusal('LOCK_BUSY') from None
        yield
    finally:os.close(fd)
def fingerprints(meta):
    output={}
    for name,expected in FILES.items():
        p=WORK/name;s=p.lstat()
        expected=expected or (meta['uid'],meta['gid'],0o600)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==expected,'configuration owner/mode mismatch')
        output[name]=hashlib.sha256(p.read_bytes()).hexdigest()
    for name in ('acme','acme/staging'):
        s=(WORK/name).lstat()
        need(stat.S_ISDIR(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(65532,65532,0o700),'unsafe ACME directory')
    return output
def metadata():
    directory()
    m=read_json(WORK/'fixture.json')
    need(set(m)=={'uid','gid','sbox','mita','ifindex','files','boot_id'},'invalid fixture metadata')
    import re
    need(type(m['uid']) is int and m['uid']>0 and type(m['gid']) is int and m['gid']>0 and type(m['ifindex']) is int and m['ifindex']>0,'invalid fixture identity')
    need(all(isinstance(m[k],str) and re.fullmatch(r'sha256:[0-9a-f]{64}',m[k]) for k in ('sbox','mita')),'invalid pinned image')
    need(set(m['files'])==set(FILES) and all(re.fullmatch(r'[0-9a-f]{64}',x) for x in m['files'].values()),'invalid manifest')
    return m
def boot_id():return pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def verify_config(m):
    try:ok=fingerprints(m)==m['files']
    except (Failure,OSError):ok=False
    require_code(ok,'CONFIG_DRIFT')
    require_code(boot_id()==m['boot_id'],'BOOT_CHANGED')
def journal_marker(p):return p.with_suffix('.writing')
def save_journal(path,state):
    # The durable witness closes the replace -> directory-fsync ambiguity.
    # It is written before replacing the journal and removed only AFTER the
    # replacement is durable. On error, leave every existing witness intact.
    marker=journal_marker(path);tmp=path.with_suffix('.tmp')
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:os.fsync(fd)
    finally:os.close(fd)
    syncdir(path.parent)
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(state,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
    os.replace(tmp,path);syncdir(path.parent)
    marker.unlink();syncdir(path.parent)
def interrupted_paths(p):
    return [x for x in (p.with_suffix('.tmp'),journal_marker(p)) if os.path.lexists(x)]
def orphan_evidence(p,s):
    recorded={e.get('evidence') for e in s.get('events',[]) if e.get('result')=='interrupted_write_preserved'}
    return [x for x in sorted(p.parent.glob('journal.interrupted-*')) if x.name not in recorded]
class Host(lab.LabHost):
    def __init__(self,m):
        lab.gate();directory()
        # No caller-provided public IP, path, interface, Docker endpoint or credentials.
        # Do not require the WAN to exist merely to inspect or stop known endpoints.
        self.w=WORK;self.ns=None;self.uid=m['uid'];self.gid=m['gid'];self.sbox=m['sbox'];self.ifindex=m['ifindex']
        self.cfg={'public_ipv4':lab.IP,'wan_if':lab.WAN,'tester_cidrs':['198.18.254.2/32'],'reality_host':'example.com','acme_mode':'staging','mita_image_id':m['mita']}
        self.meta=m
    def preflight(self,run):
        verify_config(self.meta)
        super().preflight(run)
    def native(self,run):
        verify_config(self.meta)
        super().native(run)
class Tx(Transaction):
    def guard(self):
        verify_config(self.h.meta)
        super().guard()
    journal_failed=False
    def write(self):
        if self.journal_failed:raise JournalIO()
        try:save_journal(self.path,self.s)
        except BaseException:
            self.journal_failed=True
            raise JournalIO() from None
    def rollback(self):
        # The inherited apply catches BaseException and calls rollback.
        # Do not let that path execute a backend operation after write failure.
        if self.journal_failed:raise JournalIO()
        try:super().rollback()
        except BaseException:
            if self.journal_failed:raise JournalIO() from None
            raise
    def stop(self):
        if self.journal_failed:raise JournalIO()
        # Stop known verified endpoints even if the firewall/config has drifted.
        for i in (1,0):
            name=base.NAMES[i];id=self.s['containers'].get(name)
            if not id:continue
            rows=self.h.inventory('container',self.s['run'])
            if id not in rows:continue
            self.h.verify_container(i,self.s,None)
            if self.h.running(id):
                self.mutate('stop:'+name,lambda:self.h.stop(id))
                require_code(not self.h.running(id),'RECOVERY_REQUIRED')
        rows=self.h.inventory('container',self.s['run'])
        require_code(set(rows)<=set(self.s['containers'].values()) and
                     not any(x['State']['Running'] for x in rows.values()) and
                     not self.s['pending'] and not self.s['uncertain'],'RECOVERY_REQUIRED')
        self.s['phase']='stopped';self.write()
def identity(m):return {'release':'v1.6.2-rc','fixture':'synthetic-only','metadata':m}
def load(h,m,readonly):
    p=WORK/'journal.json';tmp=p.with_suffix('.tmp')
    s=read_json(p)
    need(s.get('version')==2 and s.get('identity')==identity(m),'journal identity mismatch')
    need(isinstance(s.get('uncertain'),list) and isinstance(s.get('events'),list),'invalid journal')
    t=object.__new__(Tx);t.h=h;t.path=p;t.s=s
    # Read-only reporting never invokes Transaction(recover=True).
    if readonly:return t
    # Move ALL interrupted files aside before any new journal write.
    for x in interrupted_paths(p):
        trusted(x)
        evidence=WORK/('journal.interrupted-'+uuid.uuid4().hex)
        os.rename(x,evidence);syncdir(WORK)
    for x in orphan_evidence(p,s):
        trusted(x)
        if 'journal_write_interrupted' not in s['uncertain']:s['uncertain'].append('journal_write_interrupted')
        t.event('journal','interrupted_write_preserved',evidence=x.name)
    # Ensure a visible recovered journal is durable before any backend mutation.
    try:
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        syncdir(WORK)
    except OSError:raise JournalIO() from None
    if s.get('pending') and s['pending'] not in s['uncertain']:
        s['uncertain'].append(s['pending']);t.event(s['pending'],'unresolved_on_reload')
    return t
def listeners_ready(h,t,i):
    id=t.s['containers'][base.NAMES[i]]
    x=h.inspect('container',id);pid=x['State']['Pid']
    need(type(pid) is int and pid>0,'invalid listener PID')
    addr=base.NETWORKS[i][3];ports=(18443,18445) if i==0 else (18444,)
    lines=h.cmd('nsenter','-t',str(pid),'-n','ss','-H','-lnt').splitlines()
    endpoints={line.split()[3] for line in lines if len(line.split())>=4}
    need(all(addr+':'+str(port) in endpoints for port in ports),'listener missing')
    y=h.inspect('container',id)
    need(y['State']['Running'] and y['State']['Pid']==pid and y['State']['StartedAt']==x['State']['StartedAt'],'endpoint changed during observation')
def status(h,m):
    p=WORK/'journal.json'
    t=load(h,m,True) if os.path.lexists(p) else None
    try:config_ok=fingerprints(m)==m['files']
    except (Failure,OSError,KeyError):config_ok=False
    run=t.s['run'] if t else 'unowned'
    containers=h.inventory('container',run);networks=h.inventory('network',run)
    interrupted=bool(interrupted_paths(p));orphans=bool(orphan_evidence(p,t.s if t else {}))
    result={'phase':t.s['phase'] if t else 'new','pending':t.s['pending'] if t else None,'uncertain':t.s['uncertain'] if t else [],'interrupted_write':interrupted,'orphan_evidence':orphans,'config_ok':config_ok,'boot_same':boot_id()==m['boot_id'],'containers':len(containers),'networks':len(networks),'primary_present':h.table_exists(),'local_ready':False}
    unknown=bool(set(containers)-set(t.s['containers'].values()) or set(networks)-set(t.s['networks'].values())) if t else bool(containers or networks)
    result['recovery_required']=bool(result['pending'] or result['uncertain'] or interrupted or orphans or unknown or not result['boot_same'] or not config_ok or result['phase']=='rollback_incomplete')
    for f in (4,6):
        try:
            actual=h.legacy_fingerprint(f);result['legacy'+str(f)]='absent' if actual is None else ('owned' if t and actual==t.s['legacy'].get(str(f)) else 'unverified')
        except Failure:result['legacy'+str(f)]='unverified'
    if t and result['phase']=='local_ready_external_pending' and not result['recovery_required']:
        try:
            t.guard()
            need(set(containers)==set(t.s['containers'].values()) and set(networks)==set(t.s['networks'].values()),'inventory mismatch')
            for i in (0,1):
                h.verify_network(i,t.s);h.verify_container(i,t.s,True);listeners_ready(h,t,i)
            result['local_ready']=True
        except (Failure,OSError,KeyError,TypeError):result['recovery_required']=True
    print(json.dumps(result,sort_keys=True))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('check','render','plan','preflight','apply','status','stop','rollback','start'))
    a,rest=p.parse_known_args()
    # Offline operations keep the exact base parser and semantics.
    if a.action in ('check','render','plan'):
        base.ROOT=lab.ROOT/'candidate'
        sys.argv=[sys.argv[0],a.action,*rest];return base.main()
    if a.action=='start':raise Refusal('START_DISABLED')
    need(not rest,'no arbitrary live parameters accepted')
    try:lab.gate()
    except Failure:raise Refusal('LAB_REQUIRED') from None
    os.umask(0o077)
    need(not os.environ.get('DOCKER_API_VERSION'),'forced Docker API forbidden')
    directory()
    with lock(a.action=='status'):
        m=metadata();h=Host(m);j=WORK/'journal.json'
        if a.action=='status':status(h,m);return 0
        if a.action in ('apply','preflight'):
            require_code(not os.path.lexists(j),'JOURNAL_EXISTS')
            require_code(not interrupted_paths(j) and not orphan_evidence(j,{}),'RECOVERY_REQUIRED')
            verify_config(m)
            if a.action=='preflight':h.preflight('preflight');print('RC preflight PASS');return 0
            t=Tx(h,j,identity(m));t.apply();print('RC apply local_ready_external_pending');return 0
        t=load(h,m,False)
        if a.action=='stop':t.stop();print('RC stop verified');return 0
        t.rollback();print('RC rollback local_verified');return 0
if __name__=='__main__':
    try:sys.exit(main())
    except (Failure,OSError,ValueError,KeyError,TypeError) as e:
        # No arbitrary exception content, config or credentials in public output.
        code=e.code if isinstance(e,Refusal) else ('RECOVERY_REQUIRED' if isinstance(e,Incomplete) else 'REFUSED')
        detail=str(e) if isinstance(e,Failure) else type(e).__name__
        print('RC REFUSED '+code+': '+detail,file=sys.stderr);sys.exit(78)
