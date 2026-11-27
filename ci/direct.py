"""Probe only synthetic addresses; print no payload or credentials."""
import socket,struct,sys
from probe import error_outcome,matches
mode,dest,expect=sys.argv[1:]
actual='PROBE_ERROR'
try:
    if mode=='tcp' or mode.startswith('tcp:'):
        port=443 if mode=='tcp' else int(mode.split(':')[1])
        with socket.create_connection((dest,port),timeout=2):actual='CONNECTED'
    elif mode in ('dns-udp','dns-tcp'):
        question=b'\x31\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06target\x04test\x00\x00\x01\x00\x01'
        if mode=='dns-udp':
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                s.settimeout(2);s.connect((dest,53));s.send(question);data=s.recv(512)
        else:
            with socket.create_connection((dest,53),timeout=2) as s:
                s.settimeout(2);s.sendall(struct.pack('!H',len(question))+question);f=s.makefile('rb');n=struct.unpack('!H',f.read(2))[0];data=f.read(n)
        actual='CONNECTED' if len(data)>12 and data[:2]==question[:2] and data[-4:]==socket.inet_aton('198.18.254.4') else 'INVALID_RESPONSE'
    elif mode=='ipv6':
        with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:
            s.settimeout(2);s.connect((dest,443));actual='CONNECTED'
    else: raise ValueError('mode')
except OSError as e:actual=error_outcome(e)
except struct.error:actual='INVALID_RESPONSE'
print(mode,dest,actual,'expected',expect,flush=True)
sys.exit(0 if matches(actual,expect) else 1)
