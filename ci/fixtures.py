"""Local-only DNS/HTTPS test fixtures; no upstream resolution."""
import http.server, pathlib, socket, socketserver, ssl, struct, sys, threading, time
w=pathlib.Path(sys.argv[1]); mode=sys.argv[2]
TOKEN=b"vpn-benchmark-local-fixture-v1\n"
def dns_answer(data):
    if len(data)<12: return b''
    pos=12; labels=[]
    while pos<len(data) and data[pos]:
        n=data[pos];pos+=1
        if n>63 or pos+n>len(data): return b''
        labels.append(data[pos:pos+n].decode('ascii','ignore'));pos+=n
    pos+=1
    if pos+4>len(data): return b''
    typ,cls=struct.unpack_from('!HH',data,pos); end=pos+4; name='.'.join(labels).lower()
    addr='198.18.254.4' if name=='target.test' or name.endswith('.target.test') else '172.30.241.1' if name=='internal.test' else None
    answer=b''
    if typ==1 and cls==1 and addr:
        answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton(addr)
    print('DNS',name,typ,flush=True)
    return data[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(answer)),0,0)+data[12:end]+answer
class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request; out=dns_answer(data)
        if out: sock.sendto(out,self.client_address)
class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        f=self.request.makefile('rb'); head=f.read(2)
        if len(head)!=2:return
        data=f.read(struct.unpack('!H',head)[0]);out=dns_answer(data)
        if out:self.request.sendall(struct.pack('!H',len(out))+out)
class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print('HTTP',self.path,flush=True)
        self.send_response(200);self.send_header('Content-Length',str(len(TOKEN)));self.end_headers();self.wfile.write(TOKEN)
    def log_message(self,*args): pass
class ThreadTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True; daemon_threads=True
class ThreadTCP6(ThreadTCP):
    address_family=socket.AF_INET6
class Canary(socketserver.BaseRequestHandler):
    def handle(self): pass
class ThreadUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address=True; daemon_threads=True
class TLSServer(http.server.ThreadingHTTPServer):
    allow_reuse_address=True; daemon_threads=True
    def get_request(self):
        sock,addr=super().get_request();sock.settimeout(5)
        print('TCP_ACCEPT '+sock.getsockname()[0],flush=True)
        try:return ctx.wrap_socket(sock,server_side=True),addr
        except Exception:sock.close();raise
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(w/'target.pem',w/'target.key');ctx.set_alpn_protocols(['h2','http/1.1'])
servers=[]
if mode=='wan':
    servers.append(ThreadTCP6(('fd42:198:18::4',443),Canary))
    for addr in ('198.18.254.4','198.18.254.6'): servers.append(TLSServer((addr,443),HTTP))
    for addr in ('198.18.254.5','198.18.254.6'):
        servers += [ThreadUDP((addr,53),Udp),ThreadTCP((addr,53),Tcp)]
elif mode=='host':
    for addr in ('172.30.241.1','172.30.242.1'):servers.append(TLSServer((addr,443),HTTP))
else:raise ValueError('mode')
for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
(w/(mode+'.ready')).touch()
while True:time.sleep(60)
