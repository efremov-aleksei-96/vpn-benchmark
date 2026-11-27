"""Probe only synthetic addresses; print no payload or credentials."""
import socket,struct,sys
from probe import error_outcome,matches

def outcome(mode,dest):
    connected=False
    try:
        if mode=='tcp' or mode.startswith('tcp:'):
            port=443 if mode=='tcp' else int(mode.split(':')[1])
            with socket.create_connection((dest,port),timeout=2):return 'CONNECTED'
        if mode in ('dns-udp','dns-tcp'):
            question=b'\x31\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06target\x04test\x00\x00\x01\x00\x01'
            if mode=='dns-udp':
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                    s.settimeout(2);s.connect((dest,53));s.send(question);data=s.recv(512)
            else:
                with socket.create_connection((dest,53),timeout=2) as s:
                    # A completed TCP handshake itself disproves a port block.
                    connected=True
                    s.sendall(struct.pack('!H',len(question))+question)
                    with s.makefile('rb') as f:
                        header=f.read(2)
                        if len(header)!=2:return 'INVALID_RESPONSE'
                        n=struct.unpack('!H',header)[0];data=f.read(n)
                        if len(data)!=n:return 'INVALID_RESPONSE'
            return 'CONNECTED' if len(data)>12 and data[:2]==question[:2] and data[-4:]==socket.inet_aton('198.18.254.4') else 'INVALID_RESPONSE'
        if mode=='ipv6':
            with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:
                s.settimeout(2);s.connect((dest,443));return 'CONNECTED'
        raise ValueError('mode')
    except OSError as e:return 'CONNECTED_NO_RESPONSE' if connected else error_outcome(e)
    except struct.error:return 'INVALID_RESPONSE'
def main():
    mode,dest,expect=sys.argv[1:];actual=outcome(mode,dest)
    print(mode,dest,actual,'expected',expect,flush=True)
    return 0 if matches(actual,expect) else 1
if __name__=='__main__':sys.exit(main())
