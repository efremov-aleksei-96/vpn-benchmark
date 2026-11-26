import socket, sys
src,dst,port,expected=sys.argv[1:]; port=int(port)
try:
    with socket.create_connection((dst,port),timeout=3,source_address=(src,0)):
        actual='allow'
except OSError:
    actual='deny'
print(f'TCP {src} -> {dst}:{port}: {actual}, expected {expected}',flush=True)
if actual!=expected: sys.exit(1)
