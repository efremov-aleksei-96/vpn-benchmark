import json, os, pathlib, secrets, subprocess, uuid
w=pathlib.Path(os.environ['VB_WORK']); src=pathlib.Path('candidate')
repl={'__PUBLIC_IPV4__':'198.18.254.1','__WAN_IF__':'vb-wan','__TESTER_IPV4_CIDRS__':'198.18.254.2/32','__VLESS_UUID__':str(uuid.uuid4()),'__REALITY_HOST__':'example.com','__REALITY_PRIVATE_KEY__':os.environ['VB_KEY'],'__REALITY_SHORT_ID__':secrets.token_hex(8),'__NAIVE_PASSWORD__':secrets.token_urlsafe(24),'__MIERU_PASSWORD__':secrets.token_urlsafe(24)}
for name in ['sing-box.json','mita.json','firewall.nft']:
    text=(src/name).read_text()
    for k,v in repl.items(): text=text.replace(k,v)
    assert '__' not in text, 'unresolved placeholder'
    target=w/('sing-box-acme.json' if name=='sing-box.json' else name);target.write_text(text)
    target.chmod(0o600);os.chown(target,65532,65532)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=VPN benchmark local lab','-addext','subjectAltName=IP:198.18.254.1','-keyout',str(w/'key.pem'),'-out',str(w/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for p in [w/'key.pem',w/'cert.pem']:
    p.chmod(0o600);os.chown(p,65532,65532)
s=json.loads((w/'sing-box-acme.json').read_text());t=s['inbounds'][1]['tls'];t.pop('certificate_provider');t.update(certificate_path='/lab/cert.pem',key_path='/lab/key.pem');p=w/'sing-box-lab.json';p.write_text(json.dumps(s));p.chmod(0o600);os.chown(p,65532,65532)
