#!/usr/bin/env python3
"""Hosted-only v1.6.2 acceptance. Test-only reconciliation is not a live API."""
import importlib.util,json,os,pathlib,signal,subprocess,sys,time
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('release_v161',HERE/'benchmark.py')
rc=importlib.util.module_from_spec(spec);spec.loader.exec_module(rc)
lab=rc.lab
from integration import call,need,copy_owned,no_ns,IP,WAN,CLIENT,canaries,configure_fixture
from lifecycle import Failure,save
WORK=rc.WORK
def cli(action,reason=None):
    p=subprocess.run([sys.executable,str(HERE/'benchmark.py'),action],capture_output=True,text=True,timeout=180)
    if reason is None:need(p.returncode==0,'CLI '+action+' failed: '+p.stderr.strip())
    else:need(p.returncode==78 and p.stderr.startswith('RC REFUSED '+reason+':'),'unexpected refusal: '+action+' expected '+reason)
    return p.stdout.strip()
def rollback_can_complete(exists,primary,expected,legacy,recorded,uncertain=False):
    return not uncertain and (not exists or (primary is not None and primary==expected)) and all(legacy[f]==recorded.get(str(f)) for f in (4,6))
def report(id,msg):print(id+' PASS '+msg,flush=True)
def journal():return rc.read_json(WORK/'journal.json')
def state():return json.loads(cli('status'))
def preserve(label):
    # CI only, after independently verified resource absence.
    d=WORK/('test-evidence-'+label);d.mkdir(mode=0o700)
    for p in [WORK/'journal.json',*WORK.glob('journal.interrupted-*')]:
        os.rename(p,d/p.name)
    rc.syncdir(d);rc.syncdir(WORK)
def kill():os.kill(os.getpid(),signal.SIGKILL)
def killed(fn):
    pid=os.fork()
    if pid==0:
        try:fn()
        except BaseException:os._exit(90)
        os._exit(91)
    _,st=os.waitpid(pid,0)
    need(os.WIFSIGNALED(st) and os.WTERMSIG(st)==signal.SIGKILL,'real SIGKILL checkpoint not reached')
def atomic_tests():
    p=WORK/'atomic-test.json';rc.save_journal(p,{'step':'old'})
    def before():
        os.replace=lambda a,b:kill()
        rc.save_journal(p,{'step':'new'})
    killed(before)
    need(json.loads(p.read_text())=={'step':'old'} and json.loads(p.with_suffix('.tmp').read_text())=={'step':'new'},'before-replace evidence wrong')
    need(rc.journal_marker(p).exists(),'before-replace witness missing')
    os.rename(p.with_suffix('.tmp'),WORK/'atomic-before-evidence.json')
    os.rename(rc.journal_marker(p),WORK/'atomic-before-witness')
    def after():
        original=os.replace
        def f(a,b):original(a,b);kill()
        os.replace=f;rc.save_journal(p,{'step':'new'})
    killed(after)
    need(json.loads(p.read_text())=={'step':'new'} and not p.with_suffix('.tmp').exists(),'after-replace state wrong')
    need(rc.journal_marker(p).exists(),'after-replace witness missing')
    os.rename(rc.journal_marker(p),WORK/'atomic-after-witness')
    report('A02','SIGKILL before and after atomic replace; witness retained, not power loss')
def no_resources(h,run):
    h.verify_absence(run);need(not h.table_exists() and all(h.legacy_fingerprint(f) is None for f in (4,6)),'guard remains')
def ingress(expected,src='198.18.254.2'):
    for port in (18443,18444,18445):
        print(call('ip','netns','exec',CLIENT,sys.executable,'ci/probe.py',src,IP,str(port),expected),flush=True)
def filtered_ingress():
    from test_guard import nft_count
    before=nft_count('forward')
    ingress('deny','198.18.254.3')
    need(nft_count('forward')>before,'primary FORWARD drop not observed')
def normal_tests(m,h):
    lab.sources()
    env=dict(os.environ);env.pop('GITHUB_ACTIONS',None);env.pop('RUNNER_ENVIRONMENT',None)
    for action in ('preflight','apply','status','stop','rollback'):
        p=subprocess.run([sys.executable,str(HERE/'benchmark.py'),action],env=env,capture_output=True)
        need(p.returncode==78 and p.stderr.startswith(b'RC REFUSED LAB_REQUIRED:'),'new CLI not sealed outside lab: '+action)
    p=subprocess.run([sys.executable,str(HERE/'benchmark.py'),'start'],env=env,capture_output=True)
    need(p.returncode==78 and p.stderr.startswith(b'RC REFUSED START_DISABLED:'),'start not sealed outside lab')
    report('A12','sealed base hashes and live locks; RC refuses non-CI execution')
    atomic_tests()
    with rc.lock():
        cli('apply','LOCK_BUSY');need(not (WORK/'journal.json').exists(),'competing apply wrote journal')
    report('A01','competing apply denied while exclusive lock held')
    p=WORK/'sing-box.json';old=p.read_bytes();p.write_bytes(old+b'\n')
    try:cli('apply','CONFIG_DRIFT');need(not (WORK/'journal.json').exists(),'drift accepted before apply')
    finally:p.write_bytes(old)
    print(cli('preflight'),flush=True);print(cli('apply'),flush=True)
    s=state();need(s['phase']=='local_ready_external_pending' and s['local_ready'] and s['containers']==2 and s['networks']==2,'CLI not ready')
    ingress('allow');filtered_ingress()
    j=WORK/'journal.json';before=(j.read_bytes(),j.stat().st_mtime_ns)
    state();need((j.read_bytes(),j.stat().st_mtime_ns)==before,'status changed journal')
    report('A06','status read-only on active journal')
    p.write_bytes(old+b'\n');s=state();need(not s['config_ok'] and not s['local_ready'],'status missed drift')
    cli('start','START_DISABLED');print(cli('stop'),flush=True);ingress('deny')
    print(cli('rollback'),flush=True);no_resources(h,journal()['run'])
    report('A05','drift blocks apply and ready status; stop and rollback work')
    report('A07','real preflight/apply/status/stop/rollback')
    canary=canaries(h);print(cli('rollback'),flush=True);no_resources(h,journal()['run'])
    need(canaries(h)==canary,'repeat rollback changed unrelated rules')
    report('A08','repeat rollback, resource absence and canaries')
    p.write_bytes(old)
    def interrupted():
        os.replace=lambda a,b:kill()
        rc.save_journal(j,dict(journal(),phase='untrusted_tmp'))
    killed(interrupted)
    tmp=j.with_suffix('.tmp');raw=tmp.read_bytes()
    before=(j.read_bytes(),j.stat().st_mtime_ns,tmp.read_bytes(),tmp.stat().st_mtime_ns)
    need(state()['interrupted_write'],'status missed stale tmp')
    need((j.read_bytes(),j.stat().st_mtime_ns,tmp.read_bytes(),tmp.stat().st_mtime_ns)==before,'status modified interrupted evidence')
    marker=rc.journal_marker(j);need(marker.exists(),'interrupted witness missing')
    cli('rollback','RECOVERY_REQUIRED')
    ev=list(WORK.glob('journal.interrupted-*'))
    need(len(ev)==2 and sorted(x.read_bytes() for x in ev)==sorted([raw,b'']) and not tmp.exists() and not marker.exists() and 'journal_write_interrupted' in journal()['uncertain'] and journal()['phase']=='rollback_incomplete','interrupted evidence not preserved')
    no_resources(h,journal()['run']);report('A04','stale tmp preserved, never promoted; uncertainty retained')
    preserve('interrupted')
def docker_restart(m,h):
    print(cli('apply'),flush=True);t=rc.load(h,m,True);t.guard()
    call('systemctl','restart','docker')
    s=state();need(s['containers']==2 and not s['local_ready'] and s['recovery_required'],'unexpected Docker inventory or readiness after restart')
    t.guard()
    for id in t.s['containers'].values():need(not h.running(id),'restart=no endpoint unexpectedly running')
    ingress('deny');ingress('deny','198.18.254.3')
    print(cli('rollback'),flush=True);no_resources(h,t.s['run'])
    report('A09','Docker restart, endpoints stopped, guards unchanged, ingress denied, verified rollback')
    preserve('docker-restart')
def crash_case(m,h,case):
    def child():
        with rc.lock():
            t=rc.Tx(h,WORK/'journal.json',rc.identity(m))
            if case=='legacy4':
                orig=h.install_legacy
                def injected(f):
                    r=orig(f)
                    if f==4:kill()
                    return r
                h.install_legacy=injected
            else:
                orig=h.create_network
                def injected(i,run):
                    r=orig(i,run)
                    if i==0:kill()
                    return r
                h.create_network=injected
            t.apply()
    killed(child)
    expected='legacy:4' if case=='legacy4' else 'network:vb-sbox'
    need(state()['pending']==expected,'wrong durable pending stage')
    before=(WORK/'journal.json').read_bytes()
    cli('apply','JOURNAL_EXISTS');need((WORK/'journal.json').read_bytes()==before,'uncertain apply replayed')
    cli('rollback','RECOVERY_REQUIRED');t=rc.load(h,m,True)
    need(expected in t.s['uncertain'] and t.s['phase']=='rollback_incomplete','uncertainty lost')
    need(not h.inventory('container',t.s['run']),'unexpected endpoint')
    # This cleanup is ONLY for the controlled test injection. No journal adoption.
    if case=='legacy4':
        need(h.legacy_fingerprint(4) is not None and h.legacy_fingerprint(6) is None and not h.table_exists(),'wrong retained guard')
        h.verify_legacy_shape(4);h.verify_absence(t.s['run']);h.remove_legacy(4)
    else:
        rows=h.inventory('network',t.s['run']);need(len(rows)==1,'unexpected network inventory')
        id=next(iter(rows));x=rows[id]
        need(x['Name']=='vb-sbox' and x['Labels'].get('vpn-benchmark.run')==t.s['run'],'foreign network')
        ss=dict(t.s,networks=dict(t.s['networks'],**{'vb-sbox':id}))
        h.verify_network(0,ss);h.require_empty(id);h.remove('network',id)
        h.verify_absence(t.s['run']);t.verify_legacy(complete=True)
        need(h.table_fingerprint(t.s['run'])==t.s['table'],'primary changed')
        h.remove_table()
        for f in (6,4):
            h.verify_absence(t.s['run']);need(h.legacy_fingerprint(f)==t.s['legacy'][str(f)],'guard changed')
            h.remove_legacy(f)
    no_resources(h,t.s['run'])
    report('A03','SIGKILL after actual '+case+' mutation; no replay; retained protection; test-only cleanup')
    preserve('sigkill-'+case)
def acceptance(work):
    w=WORK;need(not os.path.lexists(w),'fixed work directory exists');rc.initialize_lock();w.mkdir(mode=0o700)
    uid=int(os.environ['VB_MITA_UID']);gid=int(os.environ['VB_MITA_GID'])
    copy_owned(work/'mita.json',w/'mita.json',uid,gid,0o600)
    copy_owned(work/'firewall.nft',w/'firewall.nft',0,0,0o600)
    copy_owned(work/'resolv.conf',w/'resolv.conf',0,0,0o644)
    acme=w/'acme';acme.mkdir(mode=0o700);(acme/'staging').mkdir(mode=0o700)
    for p in (acme,acme/'staging'):os.chown(p,65532,65532)
    for name in ('cert.pem','key.pem'):copy_owned(work/name,acme/name,65532,65532,0o600)
    s=json.loads((work/'sing-box-lab.json').read_text())
    s['inbounds'][1]['tls'].update(certificate_path='/acme/cert.pem',key_path='/acme/key.pem')
    p=w/'sing-box.json';p.write_text(json.dumps(s));os.chown(p,65532,65532);p.chmod(0o600)
    call('docker','run','--rm','--pull','never','--network','none','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--mount','type=bind,src='+str(work/'sing-box-acme.json')+',dst=/config.json,readonly','--entrypoint','sing-box',os.environ['VB_SBOX_IMAGE'],'check','-c','/config.json')
    no_ns(CLIENT);need(not {x['ifname'] for x in json.loads(call('ip','-j','link','show'))}&{WAN,'vb-peer'},'existing fixture link')
    call('ip','netns','add',CLIENT);t=None;h=None;baseline=None;original=None
    ns_inode=os.stat('/run/netns/'+CLIENT).st_ino
    try:
        call('ip','link','add',WAN,'type','veth','peer','name','vb-peer','netns',CLIENT)
        original=json.loads(call('ip','-j','link','show','dev',WAN))[0]['ifindex']
        configure_fixture(original,ns_inode,'RC')
        m={'uid':uid,'gid':gid,'sbox':os.environ['VB_SBOX_IMAGE'],'mita':os.environ['VB_MITA_IMAGE'],'ifindex':original,'boot_id':rc.boot_id()}
        m['files']=rc.fingerprints(m);save(w/'fixture.json',m)
        h=rc.Host(m);baseline=canaries(h,True)
        try:
            normal_tests(m,h);docker_restart(m,h)
            crash_case(m,h,'legacy4');crash_case(m,h,'network')
            need(canaries(h)==baseline,'unrelated rules changed')
            print('A10 NOT_RUN: hosted VM reboot unsupported',flush=True)
            print('A11 evaluated by existing independent regression jobs',flush=True)
            print('RC ACCEPTANCE PASS available scenarios; production blocked',flush=True)
        finally:
            if canaries(h)==baseline:
                for f in (4,6):
                    h.cmd(h.legacy_binary(f),'-t','filter','-F','VB2_CANARY')
                    h.cmd(h.legacy_binary(f),'-t','filter','-X','VB2_CANARY')
                h.cmd('nft','delete','table','inet','vb2_canary')
    finally:
        # Scope cleanup to original immutable link and namespace identity.
        rows=[x for x in json.loads(call('ip','-j','link','show')) if x['ifname']==WAN]
        if rows:
            need(original is not None and len(rows)==1 and rows[0]['ifindex']==original,'fixture cleanup identity mismatch')
            proc=subprocess.run(['ip','link','del',WAN],capture_output=True,text=True,timeout=45)
            if proc.returncode:print('V2 fixture veth delete rc='+str(proc.returncode)+'; checking absence',flush=True)
            need(not {x['ifname'] for x in json.loads(call('ip','-j','link','show'))}&{WAN,'vb-peer'},'fixture veth deletion not confirmed')
        if any(x.split()[0]==CLIENT for x in call('ip','netns','list').splitlines() if x):
            need(os.stat('/run/netns/'+CLIENT).st_ino==ns_inode,'fixture namespace identity mismatch')
            proc=subprocess.run(['ip','netns','del',CLIENT],capture_output=True,text=True,timeout=45)
            if proc.returncode:print('V2 fixture namespace delete rc='+str(proc.returncode)+'; checking absence',flush=True)
        no_ns(CLIENT)
        need(not {x['ifname'] for x in json.loads(call('ip','-j','link','show'))}&{WAN,'vb-peer'},'fixture links remain')

if __name__=='__main__':
    lab.gate();os.umask(0o077)
    acceptance(pathlib.Path(sys.argv[1]).resolve())
