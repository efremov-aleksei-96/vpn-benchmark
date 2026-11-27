#!/usr/bin/env python3
"""Fast, unprivileged regression tests. No real Docker, IP or firewall commands."""
import contextlib, errno, importlib.util, io, json, os, pathlib, runpy, sys, tempfile, types, unittest
from unittest import mock
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
spec=importlib.util.spec_from_file_location('integrity_rc',HERE/'benchmark.py')
rc=importlib.util.module_from_spec(spec);spec.loader.exec_module(rc)
import probe
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
             'containers':{'vpn-test-singbox':'a'*64},'networks':{},'events':[]}
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
        containers={x:{} for x in t.s['containers'].values()}
        if extra:containers[extra]={}
        h.inventory.side_effect=lambda kind,run:containers if kind=='container' else {x:{} for x in t.s['networks'].values()}
        h.legacy_fingerprint.return_value=None;h.table_exists.return_value=True
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

if __name__=='__main__':unittest.main(verbosity=2)
