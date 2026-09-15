#!/usr/bin/env python3
# Check objective: Validate the private whole-platform replay checkpoint.
"""Offline contract checks for the private whole-platform replay checkpoint."""
from __future__ import annotations
import json, os, shutil, signal, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HELPER=ROOT/'scripts/release/platform_bootstrap_replay.py'

class Replay(unittest.TestCase):
 def setUp(self):
  self.temp=Path(tempfile.mkdtemp()).resolve();self.addCleanup(shutil.rmtree,self.temp,True)
  self.work=self.temp/'deployment-work';self.work.mkdir(mode=0o700)
  self.inputs=self.work/'platform-bootstrap-inputs';self.inputs.mkdir(mode=0o700)
  self.baseline=self.temp/'baseline.json';self.session=self.temp/'private-eks-session.json'
  for p in (self.baseline,self.session): p.write_text('{}');p.chmod(0o600)
  for name in ('argocd.tfvars.json','vault.tfvars.json','vault-image-overrides.json'):
   p=self.inputs/name;p.write_text('{}');p.chmod(0o600)
 def call(self,*args,ok=True):
  p=subprocess.run([sys.executable,str(HELPER),*args],text=True,capture_output=True,timeout=8)
  if ok:self.assertEqual(p.returncode,0,p.stderr)
  return p
 def initialize(self):
  self.call('initialize','--work-dir',str(self.work),'--account','123456789012','--region','ap-northeast-2','--deployment','test-node','--baseline-config',str(self.baseline),'--session',str(self.session),'--argocd-input',str(self.inputs/'argocd.tfvars.json'),'--vault-input',str(self.inputs/'vault.tfvars.json'),'--vault-overlay',str(self.inputs/'vault-image-overrides.json'))
 def test_ordered_phases_and_changed_context_reject(self):
  self.initialize()
  self.assertEqual(self.call('phase','--work-dir',str(self.work),'--phase','tls_ready','--action','intent',ok=False).returncode,65)
  for phase in ('argocd_apply','argocd_build','tls_ready','vault_apply','vault_build','revoke_complete'):
   self.call('phase','--work-dir',str(self.work),'--phase',phase,'--action','intent');self.call('phase','--work-dir',str(self.work),'--phase',phase,'--action','complete')
  self.assertEqual(self.call('phase','--work-dir',str(self.work),'--phase','revoke_complete','--action','get').stdout.strip(),'complete')
  self.baseline.write_text('{"changed":true}');self.baseline.chmod(0o600)
  self.assertEqual(self.call('phase','--work-dir',str(self.work),'--phase','revoke_complete','--action','get',ok=False).returncode,65)
 def test_unknown_checkpoint_phase_rejects(self):
  self.initialize();path=self.work/'platform-bootstrap-replay/checkpoint.json'
  value=json.loads(path.read_text());value['phases']={'unreviewed_phase':'complete'};path.write_text(json.dumps(value));path.chmod(0o600)
  self.assertEqual(self.call('phase','--work-dir',str(self.work),'--phase','argocd_apply','--action','get',ok=False).returncode,65)
 def test_outside_runtime_baseline_rejects_before_checkpoint_publication(self):
  outside=Path(tempfile.mkdtemp()).resolve()/'baseline.json';outside.write_text('{}');outside.chmod(0o600);self.addCleanup(shutil.rmtree,outside.parent,True)
  result=self.call('initialize','--work-dir',str(self.work),'--account','123456789012','--region','ap-northeast-2','--deployment','test-node','--baseline-config',str(outside),'--session',str(self.session),'--argocd-input',str(self.inputs/'argocd.tfvars.json'),'--vault-input',str(self.inputs/'vault.tfvars.json'),'--vault-overlay',str(self.inputs/'vault-image-overrides.json'),ok=False)
  self.assertEqual(result.returncode,65);self.assertFalse((self.work/'platform-bootstrap-replay/checkpoint.json').exists())
 def test_killed_supervisor_leaves_lock_with_child(self):
  ready=self.temp/'child-ready';release=self.temp/'child-release'
  child='from pathlib import Path\nimport sys, time\nready, release = map(Path, sys.argv[1:])\nready.write_text("ready")\ndeadline = time.monotonic() + 30\nwhile not release.exists() and time.monotonic() < deadline: time.sleep(.01)'
  outer=subprocess.Popen([sys.executable,str(HELPER),'lock','--work-dir',str(self.work),'--',sys.executable,'-c',child,str(ready),str(release)],start_new_session=True)
  try:
   deadline=time.monotonic()+10
   while not ready.exists() and time.monotonic()<deadline:
    time.sleep(.02)
   self.assertTrue(ready.exists(), 'child did not confirm readiness')
   outer.kill();outer.wait(timeout=3)
   # POSIX flock remains held through the inherited child descriptor.
   self.assertEqual(self.call('lock','--work-dir',str(self.work),'--',sys.executable,'-c','pass',ok=False).returncode,65)
   release.write_text('release')
   deadline=time.monotonic()+10
   while time.monotonic()<deadline:
    if self.call('lock','--work-dir',str(self.work),'--',sys.executable,'-c','pass',ok=False).returncode == 0: break
    time.sleep(.02)
   else:self.fail('child did not release inherited lock')
  finally:
   release.touch()
   try: os.killpg(outer.pid,signal.SIGKILL)
   except ProcessLookupError: pass
   if outer.poll() is None:outer.kill();outer.wait(timeout=3)
 def test_tmp_work_directory_is_accepted(self):
  work=Path('/tmp')/f'platform-bootstrap-replay-{os.getpid()}'
  work.mkdir(mode=0o700);self.addCleanup(shutil.rmtree,work,True)
  self.call('lock','--work-dir',str(work),'--',sys.executable,'-c','pass')
if __name__=='__main__':unittest.main()
