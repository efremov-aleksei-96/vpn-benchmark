"""Pure renderer for the independent legacy guard. No live entrypoint.
The named chains are exclusive to one VPN Benchmark transaction.
The permit bit MUST be reserved across nftables, both iptables backends,
policy routing, tc and other packet-mark users before any real activation.
"""
import ipaddress
MARK='0x40000000/0x40000000'
CLEAR='0x0/0x40000000'
BRIDGES=('br-vb-sbox','br-vb-mita')
TARGETS=('172.30.241.2','172.30.242.2')
PORTS='80,18443,18444,18445'
CHAINS={4:{'mangle':{'VB15_MARK':'FORWARD'},'filter':{'VB15_IN':'INPUT','VB15_OUT':'OUTPUT','VB15_FWD':'FORWARD'}},6:{'filter':{'VB15_IN':'INPUT','VB15_OUT':'OUTPUT','VB15_FWD':'FORWARD'}}}
def rules(ip,family):
    ip=str(ipaddress.IPv4Address(ip))
    filt={k:[] for k in CHAINS[family]['filter']}
    for br in BRIDGES:
        filt['VB15_IN'].append(['-i',br,'-j','DROP'])
        filt['VB15_OUT'].append(['-o',br,'-j','DROP'])
        for side in ('-i','-o'):
            filt['VB15_FWD'].append([side,br]+(['-m','mark','!','--mark',MARK] if family==4 else [])+['-j','DROP'])
    if family==4:
        for target in TARGETS:filt['VB15_OUT'].append(['-d',target+'/32','-j','DROP'])
        for chain in ('VB15_IN','VB15_OUT'):
            filt[chain].append(['-d',ip+'/32','-p','tcp','-m','multiport','--dports',PORTS,'-j','DROP'])
        # Clear even a previously marked packet at the legacy mangle FORWARD hook
        # (-150), before the nftables permit hook (-5) and legacy filter hook (0).
        return {'mangle':{'VB15_MARK':[[side,br,'-j','MARK','--set-xmark',CLEAR] for br in BRIDGES for side in ('-i','-o')]},'filter':filt}
    return {'filter':filt}
def restore(ip,family,remove=False):
    lines=[]
    for table,chains in rules(ip,family).items():
        lines.append('*'+table)
        if remove:
            for chain,hook in CHAINS[family][table].items():lines.append('-D '+hook+' -j '+chain)
            for chain in chains:lines+=['-F '+chain,'-X '+chain]
        else:
            for chain in chains:lines.append(':'+chain+' - [0:0]')
            for chain,entries in chains.items():
                for rule in entries:lines.append('-A '+chain+' '+' '.join(rule))
            for chain,hook in CHAINS[family][table].items():lines.append('-I '+hook+' 1 -j '+chain)
        lines.append('COMMIT')
    return '\n'.join(lines)+'\n'
