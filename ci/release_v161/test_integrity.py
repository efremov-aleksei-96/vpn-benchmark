#!/usr/bin/env python3
"""Fast, unprivileged regression tests. No real Docker, IP or firewall commands."""
import contextlib, errno, importlib.util, io, json, os, pathlib, runpy, sys, tempfile, types, unittest
from unittest import mock
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
spec=importlib.util.spec_from_file_location('integrity_rc',HERE/'benchmark.py')
rc=importlib.util.module_from_spec(spec);spec.loader.exec_module(rc)
import probe,direct
aspec=importlib.util.spec_from_file_location('integrity_acceptance',HERE/'acceptance.py')
acceptance=importlib.util.module_from_spec(aspec);aspec.loader.exec_module(acceptance)

class Integrity(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.w=pathlib.Path(self.tmp.name)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(rc,'WORK',self.w).start()
        mock.patch.object(rc,'LOCK',self.w/'lock').start()
    def test_missing_lock_never_created_by_operation(self):
        with self.assertRaises((rc.Failure,OSError)):
            with rc.lock(): pass
        self.assertFalse(rc.LOCK.exists())
    def tx(self):
        h=mock.Mock()
        t=object.__new__(rc.Tx);t.h=h;t.path=self.w/'journal.json'
        t.s={'run':'a'*32,'phase':'local_ready_external_pending','pending':None,'uncertain':[],
             'containers':{'vpn-test-singbox':'a'*64},'networks':{},'events':[],'legacy':{},'table':None}
        return t,h
    def test_unrecorded_running_container_cannot_report_stopped(self):
        t,h=self.tx()
        h.inventory.return_value={'b'*64:{'State':{'Running':True}}}
        with mock.patch.object(t,'write'):
            with self.assertRaises(rc.Failure):t.stop()
        self.assertNotEqual(t.s['phase'],'stopped');h.stop.assert_not_called()
    def test_failed_replace_preserves_tmp(self):
        t,h=self.tx()
        with mock.patch('os.replace',side_effect=OSError(errno.EIO,'injected')):
            with self.assertRaises((rc.Failure,OSError)):t.write()
        self.assertTrue(t.path.with_suffix('.tmp').exists())
    def test_status_does_not_ready_with_uncertainty(self):
        t,h=self.tx();t.s['uncertain']=['lost']
        t.guard=mock.Mock()
        (self.w/'journal.json').touch()
        result=self.status_result(t,h)
        self.assertFalse(result['local_ready']);self.assertTrue(result['recovery_required'])
    def test_bad_source_is_not_deny(self):
        with mock.patch.object(probe,'source_ready',return_value=None),mock.patch('socket.create_connection',side_effect=OSError(errno.EADDRNOTAVAIL,'injected')):
            actual=probe.tcp_outcome('198.18.254.2','198.18.254.1',18443)
        self.assertEqual(actual,'INVALID_SOURCE');self.assertFalse(probe.matches(actual,'deny'))

    def status_result(self,t,h,boot='boot',extra=None,listener_failure=False):
        # All other predicates pass. A negative result cannot hide behind a
        # failed fixture, inventory, file hash, or boot check.
        t.s['containers']={'vpn-test-singbox':'a'*64,'vpn-test-mita':'b'*64}
        t.s['networks']={'vb-sbox':'c'*64,'vb-mita':'d'*64}
        t.s['table']='f'*64;t.s['legacy']={'4':'4'*64,'6':'6'*64}
        containers={x:{'State':{'Running':True}} for x in t.s['containers'].values()}
        if extra:containers[extra]={'State':{'Running':True}}
        h.inventory.side_effect=lambda kind,run:containers if kind=='container' else {x:{} for x in t.s['networks'].values()}
        h.legacy_fingerprint.side_effect=lambda f:t.s['legacy'][str(f)]
        h.table_exists.return_value=True;h.table_fingerprint.return_value=t.s['table']
        t.guard=mock.Mock();(self.w/'journal.json').touch()
        out=io.StringIO()
        m={'boot_id':'boot','files':{}}
        with mock.patch.object(rc,'load',return_value=t),mock.patch.object(rc,'fingerprints',return_value={}),mock.patch.object(rc,'boot_id',return_value=boot),mock.patch.object(rc,'listeners_ready',side_effect=rc.Failure('listener missing') if listener_failure else None),contextlib.redirect_stdout(out):
            rc.status(h,m)
        return json.loads(out.getvalue())
    def test_status_positive_control(self):
        t,h=self.tx();self.assertTrue(self.status_result(t,h)['local_ready'])
    def test_status_pending(self):
        t,h=self.tx();t.s['pending']='start';self.assertFalse(self.status_result(t,h)['local_ready'])
    def test_status_orphan(self):
        t,h=self.tx();(self.w/'journal.interrupted-orphan').touch()
        r=self.status_result(t,h);self.assertTrue(r['orphan_evidence']);self.assertFalse(r['local_ready'])
    def test_status_interrupted_marker(self):
        t,h=self.tx();rc.journal_marker(t.path).touch()
        r=self.status_result(t,h);self.assertTrue(r['interrupted_write']);self.assertFalse(r['local_ready'])
    def test_status_extra_resource(self):
        t,h=self.tx();self.assertFalse(self.status_result(t,h,extra='e'*64)['local_ready'])
    def test_status_missing_listener(self):
        t,h=self.tx();self.assertFalse(self.status_result(t,h,listener_failure=True)['local_ready'])
    def test_status_boot_distinct_from_config(self):
        t,h=self.tx();r=self.status_result(t,h,boot='new')
        self.assertTrue(r['config_ok']);self.assertFalse(r['boot_same']);self.assertFalse(r['local_ready'])
    def test_listener_missing_actual_observation(self):
        t,h=self.tx()
        h.inspect.return_value={'State':{'Pid':123,'Running':True,'StartedAt':'x'}}
        h.cmd.return_value='LISTEN 0 128 172.30.241.2:18443 0.0.0.0:*'
        with self.assertRaises(rc.Failure):rc.listeners_ready(h,t,0)
        h.cmd.return_value+='\nLISTEN 0 128 172.30.241.2:18445 0.0.0.0:*'
        rc.listeners_ready(h,t,0)
    def test_invalid_lock_refused(self):
        rc.LOCK.symlink_to(self.w/'other')
        with self.assertRaises((OSError,rc.Failure)):
            with rc.lock():pass
        self.assertTrue(rc.LOCK.is_symlink())
    def test_lock_contention_same_inode(self):
        rc.LOCK.touch(mode=0o600);st=rc.LOCK.stat()
        # Actual flock, unprivileged test substitutes ONLY uid/gid readback.
        trusted=types.SimpleNamespace(st_mode=st.st_mode,st_uid=0,st_gid=0,st_nlink=1)
        with mock.patch.object(rc.os,'fstat',return_value=trusted):
            with rc.lock():
                with self.assertRaisesRegex(rc.Failure,'LOCK_BUSY'):
                    with rc.lock(True):pass
            with rc.lock(True):pass
        self.assertEqual(rc.LOCK.stat().st_ino,st.st_ino)
    def test_failed_record_blocks_automatic_rollback(self):
        t,h=self.tx()
        t.s.update(phase='new',containers={},networks={},legacy={},table=None)
        h.legacy_fingerprint.return_value=None
        h.install_legacy.return_value='a'*64
        original=rc.save_journal;writes=[]
        def fail_record(p,s):
            writes.append(s['pending'])
            if len(writes)==5:raise OSError(errno.EIO,'record write failed')
            original(p,s)
        with mock.patch.object(rc,'save_journal',side_effect=fail_record):
            with self.assertRaisesRegex(rc.Failure,'JOURNAL_IO_ERROR'):t.apply()
            self.assertTrue(t.journal_failed)
            with self.assertRaises(rc.JournalIO):t.rollback()
        self.assertEqual(len(writes),5)
        h.install_legacy.assert_called_once_with(4)
        h.inventory.assert_not_called();h.remove_legacy.assert_not_called()
        h.install_table.assert_not_called();h.create_network.assert_not_called()
        self.assertEqual(json.loads(t.path.read_text())['pending'],'legacy:4')
    def test_failed_intent_never_calls_backend(self):
        t,h=self.tx()
        with mock.patch.object(rc,'save_journal',side_effect=OSError(errno.ENOSPC,'injected')):
            with self.assertRaises(rc.JournalIO):t.mutate('start',h.start)
        h.start.assert_not_called()
        with self.assertRaises(rc.JournalIO):t.rollback()
        self.assertEqual(h.method_calls,[])
    def test_failed_directory_fsync_after_replace_preserves_witness(self):
        t,h=self.tx()
        original=rc.syncdir;calls=[]
        def sync(p):
            calls.append(p)
            if len(calls)==2:raise OSError(errno.EIO,'injected')
            original(p)
        with mock.patch.object(rc,'syncdir',side_effect=sync):
            with self.assertRaises(rc.JournalIO):t.write()
        self.assertTrue(t.path.exists());self.assertTrue(rc.journal_marker(t.path).exists())
        self.assertFalse(t.path.with_suffix('.tmp').exists())
    def test_file_fsync_failure_preserves_tmp(self):
        t,h=self.tx();original=os.fsync;calls=[]
        def sync(fd):
            calls.append(fd)
            if len(calls)==3:raise OSError(errno.EIO,'injected')
            original(fd)
        with mock.patch.object(os,'fsync',side_effect=sync):
            with self.assertRaises(rc.JournalIO):t.write()
        self.assertTrue(t.path.with_suffix('.tmp').exists());self.assertTrue(rc.journal_marker(t.path).exists())
    def test_enospc_during_json_write_preserves_tmp(self):
        t,h=self.tx()
        with mock.patch.object(json,'dump',side_effect=OSError(errno.ENOSPC,'injected')):
            with self.assertRaises(rc.JournalIO):t.write()
        self.assertTrue(t.path.with_suffix('.tmp').exists())
    def test_existing_tmp_never_overwritten(self):
        t,h=self.tx();p=t.path.with_suffix('.tmp');p.write_bytes(b'evidence')
        with self.assertRaises(rc.JournalIO):t.write()
        self.assertEqual(p.read_bytes(),b'evidence')
    def test_refusal_must_match_reason(self):
        wrong=types.SimpleNamespace(returncode=78,stderr='RC REFUSED CONFIG_DRIFT: detail',stdout='')
        with mock.patch.object(acceptance.subprocess,'run',return_value=wrong):
            with self.assertRaises(rc.Failure):acceptance.cli('apply','LOCK_BUSY')
            acceptance.cli('apply','CONFIG_DRIFT')
    def test_rollback_truth_table(self):
        decide=acceptance.rollback_can_complete
        legacy={4:'4',6:'6'};recorded={'4':'4','6':'6'}
        self.assertTrue(decide(True,'p','p',legacy,recorded))
        self.assertTrue(decide(False,None,'p',legacy,recorded))
        self.assertFalse(decide(True,None,'p',legacy,recorded))
        self.assertFalse(decide(True,'foreign','p',legacy,recorded))
        self.assertFalse(decide(False,None,'p',{4:None,6:'6'},recorded))
        self.assertFalse(decide(False,None,'p',legacy,recorded,True))
    def test_probe_outcomes(self):
        self.assertTrue(probe.matches('CONNECTED','allow'))
        for outcome in ('NO_ROUTE','INVALID_SOURCE','INVALID_RESPONSE','PROBE_ERROR'):
            self.assertFalse(probe.matches(outcome,'deny'))
        self.assertTrue(probe.matches('NO_ROUTE','isolated'))
        for e,outcome in [(OSError(errno.ENETUNREACH,'x'),'NO_ROUTE'),(OSError(errno.ECONNREFUSED,'x'),'REFUSED'),(TimeoutError(),'TIMEOUT'),(OSError(errno.EIO,'x'),'PROBE_ERROR')]:
            self.assertEqual(probe.error_outcome(e),outcome)
    def test_probe_route_failure_never_connects(self):
        with mock.patch.object(probe,'source_ready',return_value='NO_ROUTE'),mock.patch('socket.create_connection') as connect:
            self.assertEqual(probe.tcp_outcome('198.18.254.2','198.18.254.1',18443),'NO_ROUTE')
            connect.assert_not_called()

    def legacy_fixture(self):
        spec=importlib.util.spec_from_file_location('legacy_ci_only',ROOT/'ci/lifecycle.py')
        old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        l=object.__new__(old.Lifecycle)
        l.s={'pending':'namespace','containers':{},'veth':True,'ifindex':'7','ns_inode':9}
        return old,l
    def test_legacy_fixture_recovers_missing_address_only_before_container(self):
        old,l=self.legacy_fixture();present={(old.IP,29)}
        with mock.patch.object(l,'fixture_addresses',side_effect=[set(),set(),present,present,present,present]),mock.patch.object(old,'out') as out,mock.patch.object(old.time,'sleep'):
            l.stabilize_fixture()
            out.assert_called_once_with('ip','addr','add',old.IP+'/29','dev','vb-wan')
        l.s['pending']=None
        with mock.patch.object(l,'fixture_addresses',return_value=set()),mock.patch.object(old,'out') as out:
            with self.assertRaises(old.Failure):l.wan_guard()
            with self.assertRaises(old.Failure):l.stabilize_fixture()
            out.assert_not_called()
    def test_legacy_fixture_repeated_loss_fails_closed(self):
        old,l=self.legacy_fixture()
        with mock.patch.object(l,'fixture_addresses',return_value=set()),mock.patch.object(old,'out') as out,mock.patch.object(old.time,'sleep'):
            with self.assertRaisesRegex(old.Failure,'repeatedly loses'):l.stabilize_fixture()
            self.assertEqual(out.call_count,2)
    def test_legacy_fixture_foreign_address_not_repaired(self):
        old,l=self.legacy_fixture()
        with mock.patch.object(l,'fixture_addresses',return_value={('198.18.254.7',29)}),mock.patch.object(old,'out') as out:
            with self.assertRaises(old.Failure):l.stabilize_fixture()
            out.assert_not_called()

    def test_status_interrupted_phase_without_pending(self):
        t,h=self.tx();t.s['phase']='applying'
        r=self.status_result(t,h)
        self.assertTrue(r['recovery_required']);self.assertFalse(r['local_ready'])
    def test_status_stopped_running_endpoint(self):
        t,h=self.tx();t.s['phase']='stopped'
        r=self.status_result(t,h)
        self.assertTrue(r['recovery_required']);self.assertFalse(r['local_ready'])
    def test_status_unowned_firewall(self):
        h=mock.Mock();h.inventory.return_value={};h.legacy_fingerprint.return_value=None
        m={'boot_id':'boot','files':{}}
        for present in (False,True):
            h.table_exists.return_value=present
            out=io.StringIO()
            with mock.patch.object(rc,'fingerprints',return_value={}),mock.patch.object(rc,'boot_id',return_value='boot'),contextlib.redirect_stdout(out):
                rc.status(h,m)
            self.assertEqual(json.loads(out.getvalue())['recovery_required'],present)
    def test_docker_context_refusal(self):
        h=mock.Mock();h.cmd.return_value='remote'
        with self.assertRaisesRegex(rc.Failure,'DOCKER_ENDPOINT'):rc.local_docker(h)
        h.obj.assert_not_called()
        h.cmd.return_value='default'
        h.obj.return_value=[{'Endpoints':{'docker':{'Host':'tcp://example.invalid:2376'}}}]
        with self.assertRaisesRegex(rc.Failure,'DOCKER_ENDPOINT'):rc.local_docker(h)
        h.obj.return_value=[{'Endpoints':{'docker':{'Host':'unix:///var/run/docker.sock'}}}]
        rc.local_docker(h)
    def test_docker_actual_commands_pinned(self):
        self.assertEqual(rc.lab.local_docker_args(('docker','stop','a')),('docker','--host','unix:///var/run/docker.sock','stop','a'))
        self.assertEqual(rc.lab.local_docker_args(('docker','context','show')),('docker','context','show'))
        self.assertEqual(rc.lab.local_docker_args(('ip','link')),('ip','link'))
    def test_wan_guard_carrier_and_exact_addresses(self):
        h=object.__new__(rc.Host);h.ifindex=7
        host={'ifindex':7,'flags':['UP','LOWER_UP'],'addr_info':[{'family':'inet','local':rc.lab.IP,'prefixlen':29}]}
        peer={'ifindex':8,'flags':['UP','LOWER_UP'],'addr_info':[{'family':'inet','local':a,'prefixlen':29} for a in ('198.18.254.2','198.18.254.3')]}
        h.obj=mock.Mock(side_effect=lambda *args:[peer] if 'vb-peer' in args else [host]);h.cmd=mock.Mock(return_value='')
        h.wan_guard()
        host['flags']=['UP']
        with self.assertRaises(rc.Failure):h.wan_guard()
        host['flags']=['UP','LOWER_UP'];host['addr_info'].append({'family':'inet','local':'198.18.254.7','prefixlen':29})
        with self.assertRaises(rc.Failure):h.wan_guard()
    def test_dns_tcp_handshake_is_not_deny(self):
        sock=mock.MagicMock();sock.__enter__.return_value=sock
        sock.sendall.side_effect=TimeoutError()
        with mock.patch('socket.create_connection',return_value=sock):
            actual=direct.outcome('dns-tcp','198.18.254.5')
        self.assertEqual(actual,'CONNECTED_NO_RESPONSE')
        self.assertFalse(probe.matches(actual,'deny'))
        with mock.patch('socket.create_connection',side_effect=TimeoutError()):
            self.assertEqual(direct.outcome('dns-tcp','198.18.254.5'),'TIMEOUT')
    def test_dns_tcp_short_body_rejected(self):
        sock=mock.MagicMock();sock.__enter__.return_value=sock
        f=sock.makefile.return_value.__enter__.return_value;f.read.side_effect=[b'\x00\x20',b'\x31\x37'+b'\0'*8+b'\xc6\x12\xfe\x04']
        with mock.patch('socket.create_connection',return_value=sock):
            self.assertEqual(direct.outcome('dns-tcp','198.18.254.5'),'INVALID_RESPONSE')
    def test_shared_fixture_repair_exact_identity(self):
        lab=rc.lab;adds=[];host_reads=0
        def fake(*args):
            nonlocal host_reads
            if args[:4]==('ip','-n',lab.CLIENT,'-j') and 'link' in args:
                return json.dumps([{'ifindex':8}])
            if args[:4]==('ip','-n',lab.CLIENT,'-j'):
                return json.dumps([{'ifindex':8,'flags':['LOWER_UP'],'addr_info':[{'family':'inet','local':x,'prefixlen':29} for x in ('198.18.254.2','198.18.254.3')]}])
            if args[:3]==('ip','-j','addr'):
                host_reads+=1
                addresses=[] if host_reads<=3 else [{'family':'inet','local':lab.IP,'prefixlen':29}]
                return json.dumps([{'ifindex':7,'flags':['LOWER_UP'],'addr_info':addresses}])
            if args==('ip','addr','add',lab.IP+'/29','dev',lab.WAN):adds.append(args)
            return ''
        with mock.patch.object(lab,'call',side_effect=fake),mock.patch.object(lab.os,'stat',return_value=types.SimpleNamespace(st_ino=9)),mock.patch.object(lab.time,'sleep'):
            lab.configure_fixture(7,9,'test')
        self.assertEqual(len(adds),2);self.assertEqual(host_reads,7)
    def test_shared_fixture_replaced_namespace_refused(self):
        lab=rc.lab
        with mock.patch.object(lab,'call',return_value='[{"ifindex":8}]') as call,mock.patch.object(lab.os,'stat',return_value=types.SimpleNamespace(st_ino=10)):
            with self.assertRaisesRegex(rc.Failure,'namespace replaced'):lab.configure_fixture(7,9,'test')
            self.assertFalse(any('addr' in a.args and 'add' in a.args for a in call.call_args_list))

    def test_https_denial_requires_observed_origin_and_no_new_accept(self):
        addr='198.18.254.6';token=b'fixture';before='TCP_ACCEPT '+addr+'\n'
        self.assertTrue(probe.https_denied(35,b'',token,addr,before,before+'DNS target.test 1\n'))
        self.assertFalse(probe.https_denied(35,b'',token,addr,before,before+'TCP_ACCEPT '+addr+'\n'))
        self.assertFalse(probe.https_denied(35,b'',token,addr,'',''))
        self.assertFalse(probe.https_denied(35,b'',token,addr,before,''))
        self.assertFalse(probe.https_denied(60,b'',token,addr,before,before))
        self.assertFalse(probe.https_denied(0,b'',token,addr,before,before))
        self.assertFalse(probe.https_denied(35,token,token,addr,before,before))

    def test_dns_origin_positive_control_and_no_new_receive(self):
        for marker in ('DNS_UDP_RECEIVED 198.18.254.6','DNS_TCP_RECEIVED 198.18.254.5'):
            before=marker+'\n'
            self.assertTrue(probe.no_new_observation(marker,before,before+'DNS target.test 1\n'))
            self.assertFalse(probe.no_new_observation(marker,before,before+marker+'\n'))
            self.assertFalse(probe.no_new_observation(marker,'',''))
            self.assertFalse(probe.no_new_observation(marker,before,''))
    def test_dns_requires_exact_synthetic_answer(self):
        import struct,socket
        question=b'\x31\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06target\x04test\x00\x00\x01\x00\x01'
        answer=question[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+question[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+socket.inet_aton('198.18.254.4')
        self.assertTrue(direct.dns_response_valid(question,answer))
        self.assertFalse(direct.dns_response_valid(question,question+b'\xc6\x12\xfe\x04'))
        self.assertFalse(direct.dns_response_valid(question,answer[:2]+b'\x81\x83'+answer[4:]))
    def test_a10_existing_docker_guard_exits(self):
        import subprocess
        script=(ROOT/'tests/a10/prepare-guest.sh').read_text()
        lines=[x for x in script.splitlines() if 'command -v dockerd' in x]
        self.assertEqual(len(lines),1)
        for exists in (True,False):
            r=subprocess.run(['bash','-ec','command(){ return '+('0' if exists else '1')+'; }\n'+lines[0]+'\nprintf REACHED'],capture_output=True,text=True)
            self.assertEqual(r.returncode,78 if exists else 0)
            self.assertEqual('REACHED' in r.stdout,not exists)
    def test_a10_dependency_paths(self):
        import fnmatch,re
        s=(ROOT/'.github/workflows/a10.yml').read_text().split('  workflow_dispatch:',1)[0]
        paths=re.findall(r"^\s+- '([^']+)'",s,re.M)
        for p in ('ci/release_v161/benchmark.py','ci/release_v161/acceptance.py','ci/release_v161/test_integrity.py','ci/transaction_v2/integration.py','ci/transaction_v2/prepare-docker.sh','ci/transaction_v2/lifecycle.py','ci/render.py','ci/template.py','ci/probe.py','ci/direct.py','ci/test_guard.py','ci/legacy_guard_ci.py','ci/lifecycle.py','candidate/firewall.nft','tests/a10/guest.py'):
            self.assertTrue(any(fnmatch.fnmatchcase(p,x) for x in paths),p)


    def test_reality_decoy_and_application_origin_are_distinct(self):
        render=(ROOT/'ci/render.py').read_text()
        import ast
        tree=ast.parse(render)
        assignment=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(x,ast.Subscript) and ast.unparse(x)=="s['inbounds'][0]['tls']['reality']['handshake']['server']" for x in n.targets))
        self.assertEqual(ast.literal_eval(assignment.value),'198.18.254.5')
        self.assertIn("'ip_cidr':['198.18.254.4/32']",render)
        self.assertIn('iifname "br-vb-sbox" oifname "vb-wan" ip daddr 198.18.254.5 tcp dport 443',render)
        # Actual denial predicate ignores decoy traffic but rejects origin traffic.
        marker='TCP_ACCEPT 198.18.254.4\n'
        self.assertTrue(probe.https_denied(35,b'',b'fixture','198.18.254.4',marker,marker+'TCP_ACCEPT 198.18.254.5\n'))
        self.assertFalse(probe.https_denied(35,b'',b'fixture','198.18.254.4',marker,marker+marker))
    def test_signed_index_retry_never_installs_after_failure(self):
        import subprocess
        script=(ROOT/'ci/transaction_v2/prepare-docker.sh').read_text()
        fragment=script[script.index('  updated=0'):script.index('  # Exact signed version;')]
        for succeed_on,expected_calls,expected_rc in ((1,1,0),(2,2,0),(4,3,100)):
            command="opts=(); calls=0\napt-get(){ ((calls+=1)); echo CALL; [[ $calls -ge "+str(succeed_on)+" ]]; }\nsleep(){ :; }\n"+fragment+"\necho INSTALL\n"
            result=subprocess.run(['bash','-ec',command],capture_output=True,text=True)
            self.assertEqual(result.returncode,expected_rc)
            self.assertEqual(result.stdout.splitlines().count('CALL'),expected_calls)
            self.assertEqual('INSTALL' in result.stdout,expected_rc==0)
if __name__=='__main__':unittest.main(verbosity=2)
