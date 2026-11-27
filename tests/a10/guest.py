#!/usr/bin/env python3
"""A10 only: real reboot of a disposable QEMU guest. No host execution."""
import importlib.util,json,os,pathlib,subprocess,sys,hashlib,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('a10_acceptance',ROOT/'ci/release_v161/acceptance.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
rc=a.rc
from integration import call,need,copy_owned,no_ns,IP,WAN,CLIENT
from lifecycle import save
WORK=rc.WORK
def gate():
    rc.lab.gate()
    need(call('systemd-detect-virt')=='qemu' or call('systemd-detect-virt')=='kvm','QEMU/KVM guest required')
    need(pathlib.Path('/etc/a10-disposable-guest').is_file(),'guest marker required')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inspect(t):
    h=t.h
    out={}
    for name,id in t.s['containers'].items():
        x=h.inspect('container',id)
        need(x['Name']=='/'+name and x['Id']==id and x['Config']['Labels'].get('vpn-benchmark.run')==t.s['run'] and x['HostConfig']['RestartPolicy']['Name']=='no','container identity or restart policy mismatch')
        out[name]={'id':id,'running':x['State']['Running'],'started':x['State']['StartedAt']}
    for i in (0,1):h.verify_network(i,t.s)
    return out
def before(work):
    w=WORK;need(not os.path.lexists(w),'fixed work directory exists');w.mkdir(mode=0o700)
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
        for dev in ('lo','vb-peer'):call('ip','-n',CLIENT,'link','set',dev,'up')
        call('ip','link','set',WAN,'up')
        # Wait for both ends to have carrier before assigning the synthetic addresses.
        for _ in range(30):
            link=json.loads(call('ip','-j','link','show','dev',WAN))[0]
            need(link['ifindex']==original,'fixture link replaced')
            if 'LOWER_UP' in link['flags']:break
            time.sleep(.1)
        else:raise Failure('synthetic veth carrier missing')
        for ip in ('198.18.254.2','198.18.254.3'):call('ip','-n',CLIENT,'addr','add',ip+'/29','dev','vb-peer')
        call('ip','addr','add',IP+'/29','dev',WAN)
        # Only during fixture creation: allow async link setup to settle, then
        # verify exact address and identity. No address repair after apply starts.
        def verify_fixture():
            host=json.loads(call('ip','-j','-4','addr','show','dev',WAN))
            peer=json.loads(call('ip','-n',CLIENT,'-j','-4','addr','show','dev','vb-peer'))
            print('V2 fixture readback WAN='+str([(r['ifindex'],r.get('flags'),[(a.get('local'),a.get('prefixlen')) for a in r.get('addr_info',[])]) for r in host])+' peer='+str([(r['ifindex'],[(a.get('local'),a.get('prefixlen')) for a in r.get('addr_info',[])]) for r in peer]),flush=True)
            need(len(host)==1 and host[0]['ifindex']==original and 'LOWER_UP' in host[0]['flags'] and any(a.get('local')==IP and a.get('prefixlen')==29 for a in host[0].get('addr_info',[])),'fixture WAN address/identity lost')
            need(len(peer)==1 and {'198.18.254.2','198.18.254.3'}<={a['local'] for a in peer[0].get('addr_info',[]) if a.get('prefixlen')==29},'tester addresses missing')
            need(not call('ip','-n',CLIENT,'route','show','default') and not call('ip','-n',CLIENT,'-6','route','show','default'),'unexpected default route')
        # Recover only a missing address on the same owned link before any
        # Transaction exists. Never repair a running deployment or a replaced link.
        # Repeated loss is a failure, not an ignored guard.
        stable=0
        repairs=0
        for attempt in range(15):
            link=json.loads(call('ip','-j','link','show','dev',WAN))
            need(len(link)==1 and link[0]['ifindex']==original and 'LOWER_UP' in link[0]['flags'],'fixture link identity/carrier lost')
            host=json.loads(call('ip','-j','-4','addr','show','dev',WAN))
            present=len(host)==1 and any(a.get('local')==IP and a.get('prefixlen')==29 for a in host[0].get('addr_info',[]))
            if not present:
                need(not host or (len(host)==1 and host[0]['ifindex']==original and not host[0].get('addr_info')),'unexpected WAN address state')
                repairs+=1
                need(repairs<=2,'fixture WAN repeatedly loses address')
                print('V2 fixture missing IPv4 before transaction; reassigning once per observed loss, attempt='+str(repairs),flush=True)
                # No address flush or route changes. Only the absent synthetic address.
                call('ip','addr','add',IP+'/29','dev',WAN)
                stable=0
            else:
                verify_fixture()
                stable+=1
                if stable>=4:break
            time.sleep(.5)
        else:raise Failure('fixture WAN did not stabilize')
        print('V2 fixture stable; repairs='+str(repairs),flush=True)


        m={'uid':uid,'gid':gid,'sbox':os.environ['VB_SBOX_IMAGE'],'mita':os.environ['VB_MITA_IMAGE'],'ifindex':original,'boot_id':rc.boot_id()}
        m['files']=rc.fingerprints(m);save(w/'fixture.json',m)
        h=rc.Host(m)
        print(a.cli('preflight'),flush=True);print(a.cli('apply'),flush=True)
        s=a.state();need(s['local_ready'] and s['containers']==2 and s['networks']==2,'not ready before reboot')
        a.ingress('allow');a.ingress('deny','198.18.254.3')
        t=rc.load(h,m,True);t.guard()
        rows=inspect(t);need(all(x['running'] for x in rows.values()),'not running before reboot')
        save(w/'a10-before.json',{'boot':rc.boot_id(),'journal_sha':sha(w/'journal.json'),'metadata_sha':sha(w/'fixture.json'),'files':m['files'],'containers':rows,'networks':t.s['networks'],'table':t.s['table'],'legacy':t.s['legacy']})
        os.sync()
        print('A10 BEFORE PASS active endpoints, both guards, positive/negative probes, durable snapshot',flush=True)
def after():
    w=WORK;m=rc.metadata();prior=rc.read_json(w/'a10-before.json')
    need(rc.boot_id()!=prior['boot'],'boot ID did not change')
    need(sha(w/'journal.json')==prior['journal_sha'] and sha(w/'fixture.json')==prior['metadata_sha'] and rc.fingerprints(m)==prior['files'],'persistent files changed')
    need(not (w/'journal.tmp').exists(),'unexpected temporary journal')
    h=rc.Host(m);t=rc.load(h,m,True);rows=inspect(t)
    need(set(rows)==set(prior['containers']) and t.s['networks']==prior['networks'],'owned inventory changed')
    for name,x in rows.items():
        need(x['id']==prior['containers'][name]['id'] and not x['running'] and x['started']==prior['containers'][name]['started'],'endpoint started after reboot')
    # /run lock is volatile. First exercise the unchanged CLI as-is.
    if not rc.LOCK.exists():
        a.cli('status',False)
        print('A10 observed status refusal: volatile lock absent after reboot',flush=True)
        # Explicit test harness initialization of empty lock, not a deployment
        # action and not a journal edit. Candidate itself remains unchanged.
        with rc.lock():pass
        print('A10 test-only lock initialization; standalone postboot status gap remains',flush=True)
    s=a.state()
    need(not s['boot_same'] and not s['local_ready'] and s['containers']==2,'stale boot accepted as ready')
    need(sha(w/'journal.json')==prior['journal_sha'],'status wrote journal')
    print('A10 observed firewall primary='+str(s['primary_present'])+' legacy4='+s['legacy4']+' legacy6='+s['legacy6'],flush=True)
    # Actual endpoint probes, not simply absence of the old veth. Recreate
    # synthetic transport only, deliberately never update old boot/ifindex.
    no_ns(CLIENT);need(not {x['ifname'] for x in json.loads(call('ip','-j','link','show'))}&{WAN,'vb-peer'},'unexpected surviving fixture')
    call('ip','netns','add',CLIENT)
    call('ip','link','add',WAN,'type','veth','peer','name','vb-peer','netns',CLIENT)
    for dev in ('lo','vb-peer'):call('ip','-n',CLIENT,'link','set',dev,'up')
    call('ip','link','set',WAN,'up')
    for ip in ('198.18.254.2','198.18.254.3'):call('ip','-n',CLIENT,'addr','add',ip+'/29','dev','vb-peer')
    call('ip','addr','add',IP+'/29','dev',WAN)
    # Same bounded address stabilization as before; no change to old metadata.
    probe_ifindex=json.loads(call('ip','-j','link','show','dev',WAN))[0]['ifindex']
    stable=0;repairs=0
    for _ in range(15):
        time.sleep(.5)
        link=json.loads(call('ip','-j','link','show','dev',WAN))
        need(len(link)==1 and link[0]['ifindex']==probe_ifindex and 'LOWER_UP' in link[0]['flags'],'probe interface changed')
        host=json.loads(call('ip','-j','-4','addr','show','dev',WAN))
        if not (len(host)==1 and any(x.get('local')==IP and x.get('prefixlen')==29 for x in host[0].get('addr_info',[]))):
            need(not host or (len(host)==1 and host[0]['ifindex']==probe_ifindex and not host[0].get('addr_info')),'unexpected probe address')
            repairs+=1;need(repairs<=2,'probe address repeatedly lost')
            call('ip','addr','add',IP+'/29','dev',WAN);stable=0;continue
        need(not call('ip','-n',CLIENT,'route','show','default') and not call('ip','-n',CLIENT,'-6','route','show','default'),'unexpected default route')
        stable+=1
        if stable>=4:break
    else:raise RuntimeError('postboot probe fixture unstable')
    # Confirm path to host by ARP/neighbour and IP-level ping before negatives.
    call('ip','netns','exec',CLIENT,'ping','-c','1','-W','3',IP)
    a.ingress('deny');a.ingress('deny','198.18.254.3')
    for p in (80,):
        print(call('ip','netns','exec',CLIENT,sys.executable,str(ROOT/'ci/probe.py'),'198.18.254.2',IP,str(p),'deny'),flush=True)
    need(not any(line.split()[3].rsplit(':',1)[-1] in ('80','18443','18444','18445') for line in call('ss','-H','-lnt').splitlines()),'unexpected experiment listener')
    a.cli('apply',False);a.cli('start',False)
    need(sha(w/'journal.json')==prior['journal_sha'],'refused activation modified journal')
    # A missing guard is a refusal, not an automatic repair. Only the tested
    # CLI may remove known owned objects; check that no remaining guard changes.
    original={f:h.legacy_fingerprint(f) for f in (4,6)}
    primary=h.table_fingerprint(t.s['run'])
    if s['primary_present'] or any(x is not None for x in original.values()):
        need(s['primary_present']==(primary is not None),'foreign primary after reboot')
    # The existing CLI may complete rollback if ALL expected guards survive;
    # normally they disappear and must cause rollback_incomplete.
    if primary!=t.s['table'] or any(original[f]!=t.s['legacy'].get(str(f)) for f in (4,6)):
        a.cli('rollback',False)
        result=a.state();need(result['phase']=='rollback_incomplete','guard mismatch not retained as incomplete')
        need(h.table_fingerprint(t.s['run'])==primary and all(h.legacy_fingerprint(f)==original[f] for f in (4,6)),'remaining protection modified')
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
