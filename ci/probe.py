"""Synthetic TCP ingress. Distinguish unavailable service from broken fixture."""
import errno,json,socket,subprocess,sys

def error_outcome(e):
    if isinstance(e,TimeoutError) or e.errno==errno.ETIMEDOUT:return 'TIMEOUT'
    if e.errno==errno.ECONNREFUSED:return 'REFUSED'
    if e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH):return 'NO_ROUTE'
    if e.errno==errno.EADDRNOTAVAIL:return 'INVALID_SOURCE'
    return 'PROBE_ERROR'
def matches(actual,expected):
    return actual in {'allow':{'CONNECTED'},'deny':{'REFUSED','TIMEOUT'},
                      'isolated':{'NO_ROUTE','REFUSED','TIMEOUT'}}[expected]
def no_new_observation(marker,before,after):
    return after.startswith(before) and marker in before.splitlines() and marker not in after[len(before):].splitlines()
def https_denied(code,body,token,blocked_addr=None,before='',after=''):
    # Only observed proxy/network rejection categories, not arbitrary curl errors.
    if code not in (28,35,97) or token in body:return False
    if blocked_addr is None:return True
    # The protected origin must have demonstrated TCP accept observability
    # before the negative test. A new accept disproves destination isolation.
    marker='TCP_ACCEPT '+blocked_addr
    return no_new_observation(marker,before,after)
def source_ready(src,dst):
    # All ingress callers run inside the synthetic client namespace.
    def query(*args):
        return json.loads(subprocess.check_output(['ip','-j','-4',*args],text=True,timeout=3))
    rows=query('addr','show','dev','vb-peer')
    if len(rows)!=1 or 'LOWER_UP' not in rows[0]['flags'] or not any(a.get('local')==src and a.get('prefixlen')==29 for a in rows[0].get('addr_info',[])):return 'INVALID_SOURCE'
    routes=query('route','get',dst,'from',src)
    if len(routes)!=1 or routes[0].get('dev')!='vb-peer':return 'NO_ROUTE'
    return None
def tcp_outcome(src,dst,port):
    try:
        bad=source_ready(src,dst)
        if bad:return bad
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):return 'PROBE_ERROR'
    try:
        with socket.create_connection((dst,port),timeout=3,source_address=(src,0)):return 'CONNECTED'
    except OSError as e:return error_outcome(e)
def main():
    src,dst,port,expected=sys.argv[1:];actual=tcp_outcome(src,dst,int(port))
    print(f'TCP {src} -> {dst}:{port}: {actual}, expected {expected}',flush=True)
    return 0 if matches(actual,expected) else 1
if __name__=='__main__':sys.exit(main())
