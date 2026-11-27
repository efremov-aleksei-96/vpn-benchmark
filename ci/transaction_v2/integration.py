#!/usr/bin/env python3
"""Real integration of byte-identical sealed operational archive sources.
All inputs are synthetic. Fault cases use real netfilter in unrouted namespaces.
Normal case uses inherited operational Host methods with real Docker.
"""
import hashlib,json,os,pathlib,re,shutil,subprocess,sys,time,traceback
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.extend([str(ROOT/'candidate'),str(ROOT/'ci')])
import benchmark as b
from lifecycle import Host,Transaction,Blocked,Failure,Incomplete,exclusive_lock,need
from legacy_guard import restore
IP='198.18.254.1';WAN='vb-wan';CLIENT='vb-client';FAULT='vb-v2-fault'
def gate():
    need(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable hosted CI only')
    need(not os.environ.get('DOCKER_HOST') and not os.environ.get('DOCKER_CONTEXT'),'remote Docker forbidden')
def call(*args,data=None):
    p=subprocess.run(args,input=data,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
    need(p.returncode==0,'fixture command failed: '+args[0]+' rc='+str(p.returncode))
    return p.stdout.strip()
def sources():
    for file,sha in [('lifecycle.py','7028ab00ed08b3d7a89adbc5ff41711323a9a990eda4fec8af518fbc26704c6e'),('benchmark.py','c96a300abe817ff05b523b2966617453e01199326bb9becfd11a822f1021cedd')]:
        need(hashlib.sha256((HERE/file).read_bytes()).hexdigest()==sha,'archive source mismatch')
    b.ROOT=ROOT/'candidate';b.check()
    env=dict(os.environ,PYTHONPATH=str(ROOT/'candidate')+':'+str(ROOT/'ci'))
    for file,args in [('benchmark.py',[n]) for n in ('apply','start','stop','rollback')]+[('lifecycle.py',[])]:
        p=subprocess.run([sys.executable,str(HERE/file),*args],capture_output=True,env=env)
        need(p.returncode==78,'archive live CLI not sealed')
    try:Host({},HERE,1,1,'',0)
    except Blocked:pass
    else:raise Failure('archive Host constructor not sealed')
    print('V2 PASS exact archive sources and production locks',flush=True)
class LabHost(Host):
    def __init__(self,w,ns=None):
        gate();self.w=w.resolve();self.ns=ns
        self.cfg={'public_ipv4':IP,'wan_if':WAN,'tester_cidrs':['198.18.254.2/32'],'reality_host':'example.com','acme_mode':'staging','mita_image_id':os.environ['VB_MITA_IMAGE']}
        self.uid=int(os.environ['VB_MITA_UID']);self.gid=int(os.environ['VB_MITA_GID']);self.sbox=os.environ['VB_SBOX_IMAGE']
        need(self.w.is_dir() and self.w.stat().st_uid==0 and self.w.stat().st_mode&0o077==0,'private work required')
        need(self.uid>0 and self.gid>0 and all(re.fullmatch(r'sha256:[a-f0-9]{64}',x) for x in (self.sbox,self.cfg['mita_image_id'])),'invalid fixture identity')
        rows=self.obj('ip','-j','-4','addr','show','dev',WAN)
        need(len(rows)==1 and any(a.get('local')==IP for a in rows[0].get('addr_info',[])),'synthetic WAN IPv4 missing before transaction')
        self.ifindex=rows[0]['ifindex']
    def cmd(self,*args,timeout=45,data=None):
        # Only the synthetic TLS check needs its local cert/key bind. The
        # production ACME config was checked independently without this mount.
        native=('docker','run','--rm','--pull','never','--network','none','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--read-only','--mount','type=bind,src='+str(self.w/'sing-box.json')+',dst=/config.json,readonly','--entrypoint','sing-box',self.sbox,'check','-c','/config.json')
        if self.ns is None and args==native:
            tls=json.loads((self.w/'sing-box.json').read_text())['inbounds'][1]['tls']
            need(tls.get('certificate_path')=='/acme/cert.pem' and tls.get('key_path')=='/acme/key.pem' and 'certificate_provider' not in tls,'unexpected synthetic TLS config')
            for filename in ('cert.pem','key.pem'):
                p=self.w/'acme'/filename;st=p.lstat()
                need(p.is_file() and not p.is_symlink() and (st.st_uid,st.st_gid,st.st_mode&0o777)==(65532,65532,0o600),'unsafe synthetic TLS file')
            # Verify that the old check fails specifically for the missing file,
            # without printing arbitrary stderr or any credential values.
            probe=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
            if probe.returncode:
                missing=any(path in probe.stderr for path in ('/acme/cert.pem','/acme/key.pem')) and ('no such file' in probe.stderr.lower() or 'not found' in probe.stderr.lower())
                print('V2 native check without fixture mount rc='+str(probe.returncode)+' missing_TLS_file='+str(missing),flush=True)
                need(missing,'unclassified synthetic native check failure')
            else:
                print('V2 native check without fixture mount succeeded; checking complete fixture too',flush=True)
            pos=args.index('--entrypoint')
            args=args[:pos]+('--mount','type=bind,src='+str(self.w/'acme')+',dst=/acme,readonly')+args[pos:]
            result=super().cmd(*args,timeout=timeout,data=data)
            print('V2 PASS native synthetic TLS check with read-only fixture mount',flush=True)
            return result
        if self.ns:args=('ip','netns','exec',self.ns,*args)
        return super().cmd(*args,timeout=timeout,data=data)
    def verify_legacy_shape(self,f):
        try:super().verify_legacy_shape(f)
        except Failure:
            print('V2 READBACK MISMATCH',f,json.dumps(self.legacy_snapshot(f),sort_keys=True),flush=True)
            raise
class FaultHost(LabHost):
    def __init__(self,w,case):
        super().__init__(w,FAULT);self.case=case;self.hit=False
    def preflight(self,run):
        self.wan_guard();need(not self.table_exists() and all(self.legacy_fingerprint(f) is None for f in (4,6)),'namespace not clean')
        self.verify_absence(run)
    def native(self,run):
        anchor='table inet vpn_benchmark {';text=(self.w/'firewall.nft').read_text()
        need(text.count(anchor)==1,'invalid template')
        p=self.w/('firewall-'+run+'.nft')
        p.write_text('create table inet vpn_benchmark\n'+text.replace(anchor,anchor+'\n    chain owner_'+run+' { }\n',1))
        self.cmd('nft','-c','-f',str(p))
        for f in (4,6):self.cmd(self.legacy_binary(f)+'-restore','--noflush','--test',data=restore(IP,f))
    def bind_check(self,i):
        for p in ((80,18443,18445) if i==0 else (18444,)):
            self.cmd(sys.executable,'-c','import socket,sys; s=socket.socket(); s.bind((sys.argv[1],int(sys.argv[2]))); s.close()',IP,str(p))
    def create_network(self,i,run):raise Failure('fault case must not create Docker endpoints')
    def partial(self,remove=False):
        first=restore(IP,4,remove).split('*filter\n',1)[0]
        try:self.cmd('iptables-legacy-restore','--noflush',data=first+'*filter\n-A VB2_NONEXISTENT -j DROP\nCOMMIT\n')
        except Failure:
            snap=self.legacy_snapshot(4)
            need(bool(snap['mangle'])!=remove and bool(snap['filter'])==remove,'actual partial COMMIT not observed')
            self.hit=True;print('V2 ACTUAL PARTIAL COMMIT '+('remove' if remove else 'install'),flush=True)
            raise Failure('actual partial commit')
        raise Failure('invalid restore unexpectedly succeeded')
    def install_legacy(self,f):
        if f==4 and self.case=='partial_install4':return self.partial()
        value=super().install_legacy(f)
        if self.case=='lost_install'+str(f):self.hit=True;raise Failure('lost response after actual install')
        return value
    def install_table(self,run):
        value=super().install_table(run)
        if self.case=='lost_install_nft':self.hit=True;raise Failure('lost response after actual nft install')
        return value
    def remove_table(self):
        super().remove_table()
        if self.case=='lost_remove_nft':self.hit=True;raise Failure('lost response after actual nft removal')
    def remove_legacy(self,f):
        if f==4 and self.case=='partial_remove4':return self.partial(True)
        super().remove_legacy(f)
        if self.case=='lost_remove'+str(f):self.hit=True;raise Failure('lost response after actual legacy removal')
class FaultTransaction(Transaction):
    def event(self,stage,result,**kw):
        super().event(stage,result,**kw);h=self.h
        triggers={'after_install4':'legacy:4','after_install6':'legacy:6','after_nft':'firewall','changed_legacy':'legacy:4','changed_nft':'firewall','lost_remove_nft':'firewall','lost_remove6':'firewall','lost_remove4':'firewall','partial_remove4':'firewall'}
        if result=='result' and stage==triggers.get(h.case) and not getattr(self,'injected',False):
            self.injected=True
            if h.case=='changed_legacy':h.cmd('iptables-legacy','-t','filter','-A','VB15_IN','-j','DROP')
            if h.case=='changed_nft':h.cmd('nft','add','chain','inet','vpn_benchmark','vb2_foreign')
            if not h.case.startswith(('lost_remove','partial_remove')):h.hit=True
            raise Failure('injected after durable result')
def canaries(h,install=False):
    if install:
        h.cmd('nft','add','table','inet','vb2_canary')
        for f in (4,6):
            h.cmd(h.legacy_binary(f),'-t','filter','-N','VB2_CANARY')
            h.cmd(h.legacy_binary(f),'-t','filter','-A','VB2_CANARY','-j','RETURN')
    return [h.cmd('nft','-s','list','table','inet','vb2_canary')]+[h.cmd(h.legacy_binary(f),'-t','filter','-S','VB2_CANARY') for f in (4,6)]
def status(h):return (h.legacy_fingerprint(4) is not None,h.legacy_fingerprint(6) is not None,h.table_exists())
def no_ns(name):need(not any(x.split()[0]==name for x in call('ip','netns','list').splitlines() if x),'existing namespace')
def faults(work):
    expected={
      'after_install4':((False,False,False),False),'after_install6':((False,False,False),False),'after_nft':((False,False,False),False),
      'lost_install4':((True,False,False),True),'lost_install6':((True,True,False),True),'lost_install_nft':((True,True,True),True),'partial_install4':((True,False,False),True),
      'lost_remove_nft':((True,True,False),True),'lost_remove6':((True,False,False),True),'lost_remove4':((False,False,False),True),'partial_remove4':((True,False,False),True),
      'changed_legacy':((True,False,False),True),'changed_nft':((True,True,True),True)}
    failures=[]
    for case,(remaining,incomplete) in expected.items():
        w=work/('fault-'+case);w.mkdir(mode=0o700);shutil.copyfile(work/'firewall.nft',w/'firewall.nft')
        no_ns(FAULT);call('ip','netns','add',FAULT)
        try:
            call('ip','-n',FAULT,'link','set','lo','up')
            call('ip','-n',FAULT,'link','add',WAN,'type','dummy')
            call('ip','-n',FAULT,'addr','add',IP+'/32','dev',WAN)
            call('ip','-n',FAULT,'link','set',WAN,'up')
            need(not call('ip','-n',FAULT,'route','show','default'),'unexpected default route')
            h=FaultHost(w,case);baseline=canaries(h,True);ident={'fixture':case,'ip':IP}
            t=FaultTransaction(h,w/'journal.json',ident)
            try:t.apply()
            except Failure:pass
            else:raise Failure('injected case applied')
            need(h.hit,'requested fault not reached')
            need(status(h)==remaining,'unexpected retained firewall state')
            need(t.s['phase']==('rollback_incomplete' if incomplete else 'rolled_back_local_external_pending'),'wrong rollback phase')
            need(not h.inventory('container',t.s['run']) and not h.inventory('network',t.s['run']),'Docker resources created')
            r=Transaction(h,w/'journal.json',ident,recover=True)
            try:r.apply()
            except Failure:pass
            else:raise Failure('repeat apply unexpectedly allowed')
            if incomplete:
                try:r.rollback()
                except Incomplete:pass
                else:raise Failure('unsafe automatic reconciliation')
            need(status(h)==remaining and canaries(h)==baseline,'recovery changed guard or unrelated firewall')
            print('V2 FAULT PASS '+case+' phase='+r.s['phase']+' remaining='+str(remaining),flush=True)
        except Exception as e:failures.append(case);print('V2 FAULT FAIL '+case+': '+str(e),flush=True)
        finally:
            # Teardown of the entire disposable namespace is NOT a successful rollback.
            call('ip','netns','del',FAULT);no_ns(FAULT)
    need(not failures,'failed cases: '+','.join(failures))
    print('V2 FIREWALL FAULT MATRIX PASS 13/13',flush=True)
def copy_owned(src,dst,uid,gid,mode):
    shutil.copyfile(src,dst);os.chown(dst,uid,gid);dst.chmod(mode)
def normal(work):
    w=work/'v2-normal';w.mkdir(mode=0o700)
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
        h=LabHost(w);baseline=canaries(h,True)
        print('V2 actual Docker backend '+str(h.obj('docker','info','--format','{{json .}}').get('FirewallBackend')),flush=True)
        t=Transaction(h,w/'journal.json',{'fixture':'normal','ip':IP,'images':[h.sbox,h.cfg['mita_image_id']]})
        t.apply()
        need(t.s['phase']=='local_ready_external_pending' and status(h)==(True,True,True),'normal lifecycle not ready')
        print('V2 PASS original Host native, Docker plan, actual installation and readiness',flush=True)
        def ingress(expected,src='198.18.254.2'):
            for port in (18443,18444,18445):
                print(call('ip','netns','exec',CLIENT,sys.executable,'ci/probe.py',src,IP,str(port),expected),flush=True)
        try:
            from test_guard import nft_count,legacy_count
            ingress('allow');before=nft_count('forward')
            ingress('deny','198.18.254.3')
            need(nft_count('forward')>before,'primary FORWARD drop not observed')
            primary=w/('firewall-'+t.s['run']+'.nft');h.remove_table()
            try:
                need(not h.table_exists(),'primary still present');t.verify_legacy(complete=True)
                for id in t.s['containers'].values():need(h.running(id),'endpoint stopped before loss test')
                try:t.guard()
                except Failure:pass
                else:raise Failure('guard accepted absent primary')
                before=legacy_count('VB15_FWD')
                ingress('deny')
                need(legacy_count('VB15_FWD')>before,'independent DROP counter did not increase')
                print('V2 PASS live containers fail closed after primary loss',flush=True)
            finally:
                if not h.table_exists():h.cmd('nft','-f',str(primary))
            t.guard();ingress('allow')
        finally:t.rollback()
        need(status(h)==(False,False,False) and t.s['phase']=='rolled_back_local_external_pending','rollback incomplete')
        h.verify_absence(t.s['run']);need(canaries(h)==baseline,'unrelated firewall changed')
        print('V2 NORMAL PASS real Docker endpoints, both levels, safe removal and unrelated rules',flush=True)
    except Exception:
        if t is not None:print('V2 NORMAL failure phase='+t.s['phase']+' pending='+str(t.s['pending'])+' uncertain='+str(t.s['uncertain']),flush=True)
        raise
    finally:
        # Only known canary resources, never experiment guard chains.
        if h is not None and baseline is not None and canaries(h)==baseline:
            for f in (4,6):
                h.cmd(h.legacy_binary(f),'-t','filter','-F','VB2_CANARY')
                h.cmd(h.legacy_binary(f),'-t','filter','-X','VB2_CANARY')
            h.cmd('nft','delete','table','inet','vb2_canary')
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
def main():
    gate();os.umask(0o077);work=pathlib.Path(sys.argv[1]).resolve();sources();errors=[]
    with exclusive_lock(work/'transaction-v2.lock'):
        for label,fn in [('faults',faults),('normal',normal)]:
            try:fn(work)
            except Exception as e:
                errors.append(label);print('V2 FAIL '+label+': '+str(e),flush=True);traceback.print_exc()
    need(not errors,'v2 integration failed: '+','.join(errors))
    print('V2 INTEGRATION PASS',flush=True)
if __name__=='__main__':main()
