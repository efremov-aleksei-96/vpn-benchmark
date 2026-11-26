import copy, json, os, pathlib, secrets, subprocess, uuid
w=pathlib.Path(os.environ['VB_WORK']); src=pathlib.Path('candidate')
repl={'__PUBLIC_IPV4__':'198.18.254.1','__WAN_IF__':'vb-wan','__TESTER_IPV4_CIDRS__':'198.18.254.2/32','__VLESS_UUID__':str(uuid.uuid4()),'__REALITY_HOST__':'example.com','__REALITY_PRIVATE_KEY__':os.environ['VB_KEY'],'__REALITY_SHORT_ID__':secrets.token_hex(8),'__NAIVE_PASSWORD__':secrets.token_urlsafe(24),'__MIERU_PASSWORD__':secrets.token_urlsafe(24)}
for name in ['sing-box.json','mita.json','firewall.nft']:
    text=(src/name).read_text()
    for k,v in repl.items(): text=text.replace(k,v)
    assert '__' not in text, 'unresolved placeholder'
    target=w/('sing-box-acme.json' if name=='sing-box.json' else name);target.write_text(text)
    target.chmod(0o600)
    owner=(int(os.environ['VB_MITA_UID']),int(os.environ['VB_MITA_GID'])) if name=='mita.json' else (65532,65532)
    assert all(x>0 for x in owner), 'non-root ownership required'
    os.chown(target,*owner)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=VPN benchmark local lab','-addext','subjectAltName=IP:198.18.254.1','-keyout',str(w/'key.pem'),'-out',str(w/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for p in [w/'key.pem',w/'cert.pem']:
    p.chmod(0o600);os.chown(p,65532,65532)
s=json.loads((w/'sing-box-acme.json').read_text());t=s['inbounds'][1]['tls'];t.pop('certificate_provider');t.update(certificate_path='/lab/cert.pem',key_path='/lab/key.pem');p=w/'sing-box-lab.json';p.write_text(json.dumps(s));p.chmod(0o600);os.chown(p,65532,65532)

# CI fixtures only. Never persist these substitutions to candidate/.
# Keep the original rendered firewall and ACME config for independent native checks.
(w/'firewall-original.nft').write_text((w/'firewall.nft').read_text())
f=(w/'firewall.nft').read_text()
anchor='        iifname { "br-vb-sbox", "br-vb-mita" } ip daddr @forbidden4 counter drop'
assert f.count(anchor)==1
f=f.replace(anchor, '''        # Synthetic WAN HTTPS and DNS endpoints, never production exceptions.
        iifname { "br-vb-sbox", "br-vb-mita" } oifname "vb-wan" ip daddr 198.18.254.4 tcp dport 443 ct direction original ct state { new, established } counter accept
        iifname { "br-vb-sbox", "br-vb-mita" } oifname "vb-wan" ip daddr 198.18.254.5 udp dport 53 ct direction original ct state { new, established } counter accept
        iifname { "br-vb-sbox", "br-vb-mita" } oifname "vb-wan" ip daddr 198.18.254.5 tcp dport 53 ct direction original ct state { new, established } counter accept
'''+anchor)
# Synthetic allows must receive the same per-packet permit bit as production.
f=f.replace('counter accept','counter meta mark set meta mark | 0x40000000 accept')
# Remove general production egress allows in the lab variant. Only local fixtures may be reached.
f='\n'.join(line for line in f.splitlines() if not ('oifname "vb-wan"' in line and ('ip daddr 1.1.1.1' in line or ('tcp dport 443' in line and 'ip daddr 198.18.254.4' not in line))))+'\n'
(w/'firewall.nft').write_text(f)
s=json.loads((w/'sing-box-lab.json').read_text())
s['dns']['servers'][0]['server']='198.18.254.5'
s['inbounds'][0]['tls']['server_name']='target.test'
s['inbounds'][0]['tls']['reality']['handshake']['server']='198.18.254.4'
# Resolve first, then permit precisely the synthetic TLS target.
s['route']['rules'].insert(1,{'ip_cidr':['198.18.254.4/32'],'port':443,'network':'tcp','action':'route','outbound':'direct'})
(w/'sing-box-lab.json').write_text(json.dumps(s))
(w/'resolv.conf').write_text('nameserver 198.18.254.5\noptions timeout:2 attempts:1\n')
(w/'resolv.conf').chmod(0o644)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=target.test','-addext','subjectAltName=DNS:target.test,DNS:*.target.test,DNS:internal.test,IP:198.18.254.4,IP:198.18.254.6,IP:172.30.241.1,IP:172.30.242.1','-keyout',str(w/'target.key'),'-out',str(w/'target.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
# Certificate is public test material, private keys remain 0600.
(w/'target.pem').chmod(0o644); (w/'cert.pem').chmod(0o644)
clients=w/'clients'; clients.mkdir(mode=0o700); os.chown(clients,65532,65532)
def store(name,obj):
    p=clients/name; p.write_text(json.dumps(obj)); p.chmod(0o600); os.chown(p,65532,65532)
def config(out):
    return {'log':{'level':'warn'},'inbounds':[{'type':'socks','tag':'local','listen':'127.0.0.1','listen_port':19080}],'outbounds':[dict(out,tag='proxy')],'route':{'final':'proxy'}}
raw={'type':'vless','server':'198.18.254.1','server_port':18443,'uuid':repl['__VLESS_UUID__'],'flow':'xtls-rprx-vision','network':'tcp','tls':{'enabled':True,'server_name':'target.test','utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':os.environ['VB_PUB'],'short_id':repl['__REALITY_SHORT_ID__']}}}
naive={'type':'naive','server':'198.18.254.1','server_port':18445,'username':'benchmark','password':repl['__NAIVE_PASSWORD__'],'tls':{'enabled':True,'server_name':'198.18.254.1','certificate_path':str(w/'cert.pem')}}
mieru={'profiles':[{'profileName':'lab','user':{'name':'benchmark','password':repl['__MIERU_PASSWORD__']},'servers':[{'ipAddress':'198.18.254.1','portBindings':[{'port':18444,'protocol':'TCP'}]}],'handshakeMode':'HANDSHAKE_STANDARD'}],'activeProfile':'lab','rpcPort':8964,'socks5Port':19080,'loggingLevel':'WARN','socks5ListenLAN':False}
for label,out in [('raw',raw),('naive',naive)]:
    store(label+'-good.json',config(out))
    bad=copy.deepcopy(out)
    if label=='raw': bad['uuid']=str(uuid.uuid4())
    else: bad['password']=secrets.token_urlsafe(24)
    store(label+'-bad.json',config(bad))
store('mieru-good.json',mieru)
bad=copy.deepcopy(mieru);bad['profiles'][0]['user']['password']=secrets.token_urlsafe(24)
store('mieru-bad.json',bad)
