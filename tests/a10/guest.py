#!/usr/bin/env python3
"""A10 only: real reboot of a disposable QEMU guest. No host execution."""
import importlib.util,json,os,pathlib,subprocess,sys,hashlib,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('a10_acceptance',ROOT/'ci/release_v161/acceptance.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
rc=a.rc
from integration import call,need,copy_owned,no_ns,IP,WAN,CLIENT,configure_fixture
from lifecycle import save,Failure
WORK=rc.WORK
def gate():
    rc.lab.gate()
    need(call('systemd-detect-virt')=='qemu' or call('systemd-detect-virt')=='kvm','QEMU/KVM guest required')
    need(pathlib.Path('/etc/a10-disposable-guest').is_file(),'guest marker required')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inspect(t):
    h=t.h
    need(set(h.inventory('container',t.s['run']))==set(t.s['containers'].values()) and set(h.inventory('network',t.s['run']))==set(t.s['networks'].values()),'unexpected reboot inventory')
    out={}
    for name,id in t.s['containers'].items():
        x=h.inspect('container',id)
        need(x['Name']=='/'+name and x['Id']==id and x['Config']['Labels'].get('vpn-benchmark.run')==t.s['run'] and x['HostConfig']['RestartPolicy']['Name']=='no','container identity or restart policy mismatch')
        out[name]={'id':id,'running':x['State']['Running'],'started':x['State']['StartedAt']}
    for i in (0,1):h.verify_network(i,t.s)
    return out
def before(work):
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
    if True:  # leave the fixture active across the reboot
        call('ip','link','add',WAN,'type','veth','peer','name','vb-peer','netns',CLIENT)
        original=json.loads(call('ip','-j','link','show','dev',WAN))[0]['ifindex']
        configure_fixture(original,ns_inode,'A10')
        m={'uid':uid,'gid':gid,'sbox':os.environ['VB_SBOX_IMAGE'],'mita':os.environ['VB_MITA_IMAGE'],'ifindex':original,'boot_id':rc.boot_id()}
        m['files']=rc.fingerprints(m);save(w/'fixture.json',m)
        h=rc.Host(m)
        print(a.cli('preflight'),flush=True);print(a.cli('apply'),flush=True)
        s=a.state();need(s['local_ready'] and s['containers']==2 and s['networks']==2,'not ready before reboot')
        a.ingress('allow');a.filtered_ingress()
        t=rc.load(h,m,True);t.guard()
        rows=inspect(t);need(all(x['running'] for x in rows.values()),'not running before reboot')
        save(w/'a10-before.json',{'boot':rc.boot_id(),'lock_inode':rc.LOCK.stat().st_ino,'journal_sha':sha(w/'journal.json'),'metadata_sha':sha(w/'fixture.json'),'files':m['files'],'containers':rows,'networks':t.s['networks'],'table':t.s['table'],'legacy':t.s['legacy']})
        os.sync()
        print('A10 BEFORE PASS active endpoints, both guards, positive/negative probes, durable snapshot',flush=True)
def after():
    w=WORK;m=rc.metadata();prior=rc.read_json(w/'a10-before.json')
    need(rc.boot_id()!=prior['boot'],'boot ID did not change')
    need(sha(w/'journal.json')==prior['journal_sha'] and sha(w/'fixture.json')==prior['metadata_sha'] and rc.fingerprints(m)==prior['files'],'persistent files changed')
    need(not rc.interrupted_paths(w/'journal.json'),'unexpected interrupted journal')
    h=rc.Host(m);t=rc.load(h,m,True);rows=inspect(t)
    need(set(rows)==set(prior['containers']) and t.s['networks']==prior['networks'],'owned inventory changed')
    for name,x in rows.items():
        need(x['id']==prior['containers'][name]['id'] and not x['running'] and x['started']==prior['containers'][name]['started'],'endpoint started after reboot')
    # The candidate must provide its own persistent lock, not test repair.
    need(rc.LOCK.stat().st_ino==prior['lock_inode'],'persistent lock identity changed')
    s=a.state()
    need(not s['boot_same'] and s['config_ok'] and not s['local_ready'] and s['recovery_required'] and s['containers']==2,'stale boot accepted as ready')
    need(sha(w/'journal.json')==prior['journal_sha'],'status wrote journal')
    print('A10 observed firewall primary='+str(s['primary_present'])+' legacy4='+s['legacy4']+' legacy6='+s['legacy6'],flush=True)
    # Actual endpoint probes, not simply absence of the old veth. Recreate
    # synthetic transport only, deliberately never update old boot/ifindex.
    no_ns(CLIENT);need(not {x['ifname'] for x in json.loads(call('ip','-j','link','show'))}&{WAN,'vb-peer'},'unexpected surviving fixture')
    call('ip','netns','add',CLIENT)
    call('ip','link','add',WAN,'type','veth','peer','name','vb-peer','netns',CLIENT)
    probe_ifindex=json.loads(call('ip','-j','link','show','dev',WAN))[0]['ifindex']
    configure_fixture(probe_ifindex,os.stat('/run/netns/'+CLIENT).st_ino,'A10 postboot')
    # Confirm path to host by ARP/neighbour and IP-level ping before negatives.
    for src in ('198.18.254.2','198.18.254.3'):
        call('ip','netns','exec',CLIENT,'ping','-I',src,'-c','1','-W','3',IP)
    a.ingress('deny');a.ingress('deny','198.18.254.3')
    for p in (80,):
        print(call('ip','netns','exec',CLIENT,sys.executable,str(ROOT/'ci/probe.py'),'198.18.254.2',IP,str(p),'deny'),flush=True)
    need(not any(line.split()[3].rsplit(':',1)[-1] in ('80','18443','18444','18445') for line in call('ss','-H','-lnt').splitlines()),'unexpected experiment listener')
    a.cli('apply','JOURNAL_EXISTS');a.cli('start','START_DISABLED')
    need(sha(w/'journal.json')==prior['journal_sha'],'refused activation modified journal')
    # A missing guard is a refusal, not an automatic repair. Only the tested
    # CLI may remove known owned objects; check that no remaining guard changes.
    def legacy_snapshot():
        return {f:[h.cmd(h.legacy_binary(f),'-t',table,'-S') for table in (('mangle','filter') if f==4 else ('filter',))] for f in (4,6)}
    original={}
    for f in (4,6):
        try:original[f]=h.legacy_fingerprint(f)
        except Failure:original[f]='unverified'
    exists=h.table_exists();primary=h.table_fingerprint(t.s['run'])
    primary_raw=h.cmd('nft','-s','list','table','inet','vpn_benchmark') if exists else None
    legacy_raw=legacy_snapshot()
    if not a.rollback_can_complete(exists,primary,t.s['table'],original,t.s['legacy'],bool(t.s['uncertain'] or t.s['pending'])):
        a.cli('rollback','RECOVERY_REQUIRED')
        result=a.state();need(result['phase']=='rollback_incomplete','guard mismatch not retained as incomplete')
        # Refusal alone is not proof that known endpoints were cleaned up.
        h.verify_absence(t.s['run'])
        need(h.table_exists()==exists and (not exists or h.cmd('nft','-s','list','table','inet','vpn_benchmark')==primary_raw) and legacy_snapshot()==legacy_raw,'remaining protection modified')
    else:
        print(a.cli('rollback'),flush=True);a.no_resources(h,t.s['run'])
    a.ingress('deny')
    print('A10 REBOOT SAFETY PASS changed boot ID, persistent journal, no autorestart, verified ingress denial and blocked reapply',flush=True)
    print('A10 guest will be discarded; no claim of automated production reconciliation',flush=True)
if __name__=='__main__':
    os.umask(0o077);gate()
    if sys.argv[1]=='before':before(pathlib.Path(sys.argv[2]))
    elif sys.argv[1]=='after':after()
    else:raise SystemExit(78)
