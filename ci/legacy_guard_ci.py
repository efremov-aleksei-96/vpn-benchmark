"""CI-only adapter for the independent iptables-legacy guard."""
import hashlib,json,os,pathlib,re,subprocess,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'candidate'))
from legacy_guard import CHAINS,restore
IP='198.18.254.1'
def need(x,msg):
    if not x:raise RuntimeError(msg)
def call(args,data=None):
    p=subprocess.run(args,input=data,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if p.returncode:raise RuntimeError(args[0]+' failed: '+p.stderr[:350])
    return p.stdout
def binary(f):return 'iptables-legacy' if f==4 else 'ip6tables-legacy'
def save(f):return call([binary(f)+'-save'])
def owned(f):
    result={}
    for table,chains in CHAINS[f].items():
        rules=call([binary(f),'-t',table,'-S']).splitlines()
        selected=[]
        for chain,hook in chains.items():
            own=[l for l in rules if l=='-N '+chain or l.startswith('-A '+chain+' ')]
            jumps=[l for l in rules if l.endswith(' -j '+chain)]
            selected.extend(own+jumps)
            if own or jumps:
                need(own and jumps==['-A '+hook+' -j '+chain],'guard chain or jump mismatch')
                hookrules=[l for l in rules if l.startswith('-A '+hook+' ')]
                need(hookrules and hookrules[0]==jumps[0],'guard jump not first')
        result[table]=selected
    return result
def statepath(w):return w/'legacy-guard.json'
def write(w,s):
    p=statepath(w);tmp=p.with_suffix('.tmp')
    fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as f:json.dump(s,f,sort_keys=True);f.flush();os.fsync(f.fileno())
    os.replace(tmp,p)
    fd=os.open(w,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def state(w):
    p=statepath(w);need(p.is_file() and not p.is_symlink() and p.stat().st_uid==0 and p.stat().st_mode&0o077==0,'guard journal missing or unsafe')
    return json.loads(p.read_text())
def clean_inventory():
    need(not any('vpn-test-singbox' in l or 'vpn-test-mita' in l for l in call(['docker','ps','-a','--format','{{.Names}}']).splitlines()),'test container remains')
    need(not set(call(['docker','network','ls','--format','{{.Name}}']).splitlines())&{'vb-sbox','vb-mita'},'test network remains')
    need('table inet vpn_benchmark' not in call(['nft','list','tables']),'primary firewall remains')
    need(not any(x['ifname'] in ('br-vb-sbox','br-vb-mita','vb-wan','vb-peer') for x in json.loads(call(['ip','-j','link','show']))),'test link remains')
    need(not any(x.split()[0] in ('vb-client','vb-flush-test') for x in call(['ip','netns','list']).splitlines() if x),'test namespace remains')
    nat=call(['nft','-s','list','ruleset'])
    need(not any('dnat to 172.30.241.2' in x or 'dnat to 172.30.242.2' in x for x in nat.splitlines()),'test DNAT remains')
    need(not any(re.search(r'198\.18\.254\.1:(?:80|18443|18444|18445)(?:\s|$)',x) for x in call(['ss','-H','-lnt']).splitlines()),'test listener remains')
def check(w):
    s=state(w)
    for f in (4,6):
        expected=s['families'].get(str(f))
        need(expected and owned(f)==expected,'independent guard missing or changed')
def install(w):
    need(not statepath(w).exists(),'guard journal already exists')
    clean_inventory()
    info=json.loads(call(['docker','info','--format','{{json .}}']))
    backend=info.get('FirewallBackend',{}).get('Driver')
    need(backend in (None,'iptables') and 'nf_tables' in call(['iptables','--version']),'CI must match iptables-nft Docker backend')
    need('-N DOCKER' in call(['iptables-nft','-t','nat','-S','DOCKER']),'Docker nft NAT chain missing')
    # Conservative CI collision gate. A real host requires the wider mark audit.
    for f in (4,6):
        need(not any(owned(f).values()),'existing guard names')
        need(not re.search(r'40000000|1073741824',save(f),re.I),'permit bit already used')
        call([binary(f)+'-restore','--noflush','--test'],restore(IP,f))
    need(not re.search(r'40000000|1073741824',call(['nft','-s','list','ruleset']),re.I),'permit bit already used in nft')
    s={'families':{},'pending':None};write(w,s)
    for f in (4,6):
        s['pending']=f;write(w,s)
        call([binary(f)+'-restore','--noflush'],restore(IP,f))
        s['families'][str(f)]=owned(f);s['pending']=None;write(w,s)
    check(w);print('GUARD PASS independent IPv4/IPv6 guard installed',flush=True)
def remove(w):
    clean_inventory();s=state(w);need(s['pending'] is None,'unknown guard mutation; retain protection')
    for f in (6,4):
        expected=s['families'].get(str(f))
        if not expected:
            need(not any(owned(f).values()),'unrecorded guard');continue
        need(owned(f)==expected,'guard ownership mismatch; retain protection')
        s['pending']='remove'+str(f);write(w,s)
        call([binary(f)+'-restore','--noflush'],restore(IP,f,True))
        need(not any(owned(f).values()),'guard removal not confirmed')
        del s['families'][str(f)];s['pending']=None;write(w,s)
    statepath(w).unlink();print('GUARD PASS removed after independent endpoint audit',flush=True)
def main():
    need(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','CI only')
    os.umask(0o077);w=pathlib.Path(sys.argv[2]).resolve()
    {'install':install,'check':check,'remove':remove}[sys.argv[1]](w)
if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError,KeyError) as e:print('GUARD FAIL: '+str(e),file=sys.stderr);sys.exit(1)
