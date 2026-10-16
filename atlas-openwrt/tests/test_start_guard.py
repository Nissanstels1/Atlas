import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'root/usr/lib/atlas'))
import unittest
from unittest.mock import Mock,patch
import start_guard


class Clock:
    def __init__(self):self.now=0
    def time(self):return self.now
    def sleep(self,seconds):self.now+=seconds


class Child:
    def __init__(self):self.code=None;self.terminated=False
    def poll(self):return self.code
    def terminate(self):self.code=0;self.terminated=True
    def kill(self):self.code=-9
    def wait(self,timeout):return self.code


class GuardTests(unittest.TestCase):
    def test_rolled_back_clock_waits_without_permanently_blocking_retry(self):
        self.assertFalse(start_guard.clock_ready(100))
        self.assertFalse(start_guard.clock_ready(1700000000,1800000000))
        self.assertTrue(start_guard.clock_ready(1800000000,1800000000))
        self.assertTrue(start_guard.clock_ready(1799999800,1800000000))

    def run_guard(self,ready,stopped=lambda:False,attach=None,restore=None):
        self.child=Child();self.clock=Clock();self.attach=attach or Mock();self.restore=restore or Mock(return_value=True);self.report=Mock()
        result=start_guard.supervise(self.child,ready,self.attach,self.restore,self.report,
            stopped=stopped,clock=self.clock.time,sleep=self.clock.sleep,start_timeout=3,interval=1)
        return result

    def test_delayed_engine_does_not_capture_dns_before_ready(self):
        observations=[]
        def ready():
            observations.append(self.attach.call_count)
            return self.clock.now>=1
        self.assertEqual(self.run_guard(ready,stopped=lambda:self.clock.now>=2),0)
        self.assertEqual(observations[:2],[0,0]);self.attach.assert_called_once();self.restore.assert_called_once()
        self.assertTrue(self.child.terminated)

    def test_unready_engine_times_out_without_capture(self):
        self.assertEqual(self.run_guard(lambda:False),1)
        self.attach.assert_not_called();self.restore.assert_called_once()
        self.assertEqual(self.report.call_args.args[0],'ready-timeout')

    def test_engine_exits_before_ready_and_dns_stays_original(self):
        def ready():self.child.code=2;return False
        self.assertEqual(self.run_guard(ready),1)
        self.attach.assert_not_called();self.assertEqual(self.report.call_args.args[0],'engine-exited')

    def test_engine_exits_during_readiness_probe_without_dns_capture(self):
        def ready():
            self.child.code = 2
            return True
        self.assertEqual(self.run_guard(ready), 1)
        self.attach.assert_not_called()
        self.assertEqual(self.report.call_args.args[0], 'engine-exited')
        self.assertFalse(any(c.args[0] == 'ready' for c in self.report.call_args_list))

    def test_engine_exits_during_dns_attach_without_ready_report(self):
        attach = Mock(side_effect=lambda: setattr(self.child, 'code', 2))
        self.assertEqual(self.run_guard(lambda: True, attach=attach), 1)
        self.restore.assert_called_once()
        self.assertEqual(self.report.call_args.args[0], 'engine-exited')
        self.assertFalse(any(c.args[0] == 'ready' for c in self.report.call_args_list))

    def test_hung_running_engine_is_restored_and_terminated(self):
        self.assertEqual(self.run_guard(lambda:self.clock.now==0),1)
        self.assertEqual(self.report.call_args.args[0],'engine-unresponsive')
        self.restore.assert_called_once();self.assertTrue(self.child.terminated)

    def test_transient_controller_failure_does_not_restart(self):
        self.assertEqual(self.run_guard(lambda:self.clock.now!=1,stopped=lambda:self.clock.now>=3),0)
        self.attach.assert_called_once();self.assertEqual(self.report.call_args.args[0],'stopped')

    def test_failed_dns_integration_restores_options(self):
        self.assertEqual(self.run_guard(lambda:True,attach=Mock(side_effect=RuntimeError('secret'))),1)
        self.assertEqual(self.report.call_args.args[0],'dns-integration-failed')
        self.restore.assert_called_once();self.assertNotIn('secret',str(self.report.call_args_list))

    def test_failed_restore_is_not_reported_as_success(self):
        self.run_guard(lambda:False,restore=Mock(return_value=False))
        self.assertFalse(self.report.call_args.kwargs['network_restored'])

    def test_stop_during_probe_does_not_attach_dns(self):
        flag=[False]
        def ready():flag[0]=True;return True
        self.assertEqual(self.run_guard(ready,stopped=lambda:flag[0]),0)
        self.attach.assert_not_called()

    def test_stop_during_attach_is_never_reported_ready(self):
        flag=[False]
        self.assertEqual(self.run_guard(lambda:True,stopped=lambda:flag[0],attach=Mock(side_effect=lambda:flag.__setitem__(0,True))),0)
        self.assertFalse(any(c.args[0]=='ready' for c in self.report.call_args_list))

    def test_readiness_is_not_a_claim_of_internet_access(self):
        self.run_guard(lambda:True,stopped=lambda:self.clock.now>=1)
        ready=next(c for c in self.report.call_args_list if c.args[0]=='ready')
        self.assertFalse(ready.kwargs['internet_verified'])


if __name__=='__main__':unittest.main()
