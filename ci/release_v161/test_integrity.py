#!/usr/bin/env python3
"""Fast, unprivileged regression tests. No real Docker, IP or firewall commands."""
import contextlib, errno, importlib.util, io, json, os, pathlib, runpy, sys, tempfile, types, unittest
from unittest import mock
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
spec=importlib.util.spec_from_file_location('integrity_rc',HERE/'benchmark.py')
rc=importlib.util.module_from_spec(spec);spec.loader.exec_module(rc)

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
        h.inventory.return_value={}
        h.legacy_fingerprint.return_value=None;h.table_exists.return_value=True
        m={'boot_id':'boot'}
        out=io.StringIO()
        with mock.patch.object(rc,'load',return_value=t),mock.patch.object(rc,'verify_config'),mock.patch.object(rc,'boot_id',return_value='boot'),contextlib.redirect_stdout(out):
            rc.status(h,m)
        self.assertFalse(json.loads(out.getvalue())['local_ready'])
    def test_bad_source_is_not_deny(self):
        with mock.patch('sys.argv',['probe.py','198.18.254.2','198.18.254.1','18443','deny']),mock.patch('socket.create_connection',side_effect=OSError(errno.EADDRNOTAVAIL,'injected')),contextlib.redirect_stdout(io.StringIO()):
            try:runpy.run_path(str(ROOT/'ci/probe.py'),run_name='__main__')
            except SystemExit as e:self.assertNotEqual(e.code,0)
            else:self.fail('invalid source accepted as deny')

if __name__=='__main__':unittest.main(verbosity=2)
