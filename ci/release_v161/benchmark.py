#!/usr/bin/env python3
"""v1.6.1 RC: operational CLI tested only on a disposable synthetic hosted VM.
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
LOCK=pathlib.Path('/run/lock/vpn-benchmark-v161-ci.lock')
FILES={'sing-box.json':(65532,65532,0o600),'mita.json':None,'firewall.nft':(0,0,0o600),'resolv.conf':(0,0,0o644),'acme/cert.pem':(65532,65532,0o600),'acme/key.pem':(65532,65532,0o600)}
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
@contextmanager
def lock(readonly=False):
    # Existing lock for status; never create a file in read-only mode.
    flags=os.O_RDONLY if readonly else os.O_RDWR|os.O_CREAT
    fd=os.open(LOCK,flags|os.O_NOFOLLOW,0o600)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'unsafe host lock')
        try:fcntl.flock(fd,(fcntl.LOCK_SH if readonly else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        except BlockingIOError:raise Failure('host transaction lock busy') from None
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
    need(fingerprints(m)==m['files'],'configuration fingerprint changed')
    need(boot_id()==m['boot_id'],'boot changed; no activation')
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
    def write(self):
        # The base atomic write remains unchanged. Stale temporary files are
        # handled before any mutating recovery, not by silently deleting them.
        super().write()
def identity(m):return {'release':'v1.6.1-rc','fixture':'synthetic-only','metadata':m}
def load(h,m,readonly):
    p=WORK/'journal.json';tmp=p.with_suffix('.tmp')
    s=read_json(p)
    need(s.get('version')==2 and s.get('identity')==identity(m),'journal identity mismatch')
    need(isinstance(s.get('uncertain'),list) and isinstance(s.get('events'),list),'invalid journal')
    t=object.__new__(Tx);t.h=h;t.path=p;t.s=s
    # Read-only reporting never invokes Transaction(recover=True).
    if readonly:return t
    if os.path.lexists(tmp):
        trusted(tmp)
        # Keep the original interrupted bytes. Never promote this file.
        evidence=WORK/('journal.interrupted-'+uuid.uuid4().hex)
        os.rename(tmp,evidence);syncdir(WORK)
        if 'journal_write_interrupted' not in s['uncertain']:s['uncertain'].append('journal_write_interrupted')
        t.event('journal','interrupted_write_preserved',evidence=evidence.name)
    recorded={e.get('evidence') for e in s['events'] if e.get('result')=='interrupted_write_preserved'}
    for p in sorted(WORK.glob('journal.interrupted-*')):
        if p.name not in recorded:
            trusted(p)
            if 'journal_write_interrupted' not in s['uncertain']:s['uncertain'].append('journal_write_interrupted')
            t.event('journal','interrupted_write_preserved',evidence=p.name)
    if s.get('pending') and s['pending'] not in s['uncertain']:
        s['uncertain'].append(s['pending']);t.event(s['pending'],'unresolved_on_reload')
    return t
def status(h,m):
    p=WORK/'journal.json'
    t=load(h,m,True) if os.path.lexists(p) else None
    try:verify_config(m);config_ok=True
    except (Failure,OSError):config_ok=False
    run=t.s['run'] if t else 'unowned'
    result={'phase':t.s['phase'] if t else 'new','pending':t.s['pending'] if t else None,'uncertain':t.s['uncertain'] if t else [],'interrupted_write':os.path.lexists(p.with_suffix('.tmp')),'config_ok':config_ok,'boot_same':boot_id()==m['boot_id'],'containers':len(h.inventory('container',run)),'networks':len(h.inventory('network',run)),'primary_present':h.table_exists()}
    for f in (4,6):
        try:
            actual=h.legacy_fingerprint(f);result['legacy'+str(f)]='absent' if actual is None else ('owned' if t and actual==t.s['legacy'].get(str(f)) else 'unverified')
        except Failure:result['legacy'+str(f)]='unverified'
    if t and result['phase']=='local_ready_external_pending':
        try:
            t.guard()
            for i in (0,1):h.verify_network(i,t.s);h.verify_container(i,t.s,True)
            result['local_ready']=True
        except (Failure,OSError,KeyError):result['local_ready']=False
    print(json.dumps(result,sort_keys=True))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('check','render','plan','preflight','apply','status','stop','rollback','start'))
    a,rest=p.parse_known_args()
    # Offline operations keep the exact base parser and semantics.
    if a.action in ('check','render','plan'):
        base.ROOT=lab.ROOT/'candidate'
        sys.argv=[sys.argv[0],a.action,*rest];return base.main()
    if a.action=='start':raise Failure('start disabled; use reviewed new transaction after rollback')
    need(not rest,'no arbitrary live parameters accepted')
    lab.gate();os.umask(0o077)
    need(not os.environ.get('DOCKER_API_VERSION'),'forced Docker API forbidden')
    directory()
    with lock(a.action=='status'):
        m=metadata();h=Host(m);j=WORK/'journal.json'
        if a.action=='status':status(h,m);return 0
        if a.action in ('apply','preflight'):
            need(not os.path.lexists(j) and not os.path.lexists(j.with_suffix('.tmp')),'existing journal or interrupted initial write; manual review required')
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
        print('RC REFUSED: '+(str(e) if isinstance(e,Failure) else type(e).__name__),file=sys.stderr);sys.exit(78)
