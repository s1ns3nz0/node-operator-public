#!/usr/bin/env python3
# Check objective: Validate the platform bootstrap build process.
from __future__ import annotations
import fcntl, importlib.util, json, os, shutil, stat, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/"scripts/release"))
spec=importlib.util.spec_from_file_location("build",ROOT/"scripts/release/platform_bootstrap_build.py"); assert spec and spec.loader
build=importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
A="123456789012"; R="ap-northeast-2"; P="argocd-project"; ID="argocd-project:abc123"
def item(status="SUCCEEDED", arn=True): return {"id":ID,"arn":f"arn:aws:codebuild:{R}:{A}:build/{P}:abc123" if arn else "arn:aws:codebuild:bad","projectName":P,"buildStatus":status,"buildComplete":status in build.TERMINAL}
class T(unittest.TestCase):
 def setUp(self): self.d=Path(tempfile.mkdtemp()).resolve();self.addCleanup(shutil.rmtree,self.d,True);self.w=self.d/'work';self.w.mkdir(mode=0o700)
 def invoke(self,timeout=0): build.run(self.w,"argocd",A,R,P,"chosen",timeout)
 def test_start_then_resume_reuses_exact_handle(self):
  calls=[]
  def aws(profile,region,args):
   calls.append(args); return A if args[0]=="sts" else item("IN_PROGRESS") if args[1]=="start-build" else [item()]
  with patch.object(build,"_aws",aws): self.invoke();self.invoke()
  self.assertEqual(sum(x[1]=="start-build" for x in calls),1);self.assertEqual(sum(x[1]=="batch-get-builds" for x in calls),2)
  v=json.loads((self.w/'platform-bootstrap-builds/argocd.json').read_text());self.assertEqual(v["state"],"SUCCEEDED");self.assertEqual(v["build_id"],ID)
 def test_bad_identity_never_starts_second_build(self):
  calls=[]
  def aws(profile,region,args): calls.append(args);return A if args[0]=="sts" else item("IN_PROGRESS") if args[1]=="start-build" else [item(arn=False)]
  with patch.object(build,"_aws",aws):
   with self.assertRaises(build.BuildError): self.invoke()
   with self.assertRaises(build.BuildError): self.invoke()
  self.assertEqual(sum(x[1]=="start-build" for x in calls),1)
 def test_start_failure_leaves_intent_and_retry_is_reconciliation_only(self):
  calls=[]
  def aws(profile,region,args):
   calls.append(args)
   if args[0]=="sts": return A
   raise build.BuildError("transient")
  with patch.object(build,"_aws",aws):
   with self.assertRaises(build.BuildError): self.invoke()
   with self.assertRaises(build.BuildError): self.invoke()
  self.assertEqual(len(calls),2);self.assertEqual(json.loads((self.w/'platform-bootstrap-builds/argocd.json').read_text())["state"],"start-intent")
 def test_terminal_failure_and_timeout_retain_handle(self):
  def failed(profile,region,args): return A if args[0]=="sts" else item("IN_PROGRESS") if args[1]=="start-build" else [item("FAILED")]
  with patch.object(build,"_aws",failed):
   with self.assertRaises(build.BuildError): self.invoke()
  self.assertEqual(json.loads((self.w/'platform-bootstrap-builds/argocd.json').read_text())["state"],"FAILED")
  self.d=Path(tempfile.mkdtemp()).resolve();self.addCleanup(shutil.rmtree,self.d,True);self.w=self.d/'work';self.w.mkdir(mode=0o700)
  def pending(profile,region,args): return A if args[0]=="sts" else item("IN_PROGRESS") if args[1]=="start-build" else [item("IN_PROGRESS")]
  with patch.object(build,"_aws",pending):
   with self.assertRaises(build.BuildError): self.invoke(0)
  self.assertEqual(json.loads((self.w/'platform-bootstrap-builds/argocd.json').read_text())["state"],"running")
 def test_retry_terminal_archives_verified_failure_and_starts_once(self):
  root=self.w/'platform-bootstrap-builds';root.mkdir(mode=0o700);old={"schema_version":1,"account":A,"region":R,"project":P,"phase":"argocd","state":"FAILED","build_id":ID};(root/'argocd.json').write_text(json.dumps(old));(root/'argocd.json').chmod(0o600);calls=[]
  def aws(profile,region,args):
   calls.append(args)
   if args[0]=='sts': return A
   if args[1]=='start-build': return item('IN_PROGRESS')
   return [item('FAILED')] if sum(x[1]=='batch-get-builds' for x in calls)==1 else [item('SUCCEEDED')]
  with patch.object(build,'_aws',aws): build.run(self.w,'argocd',A,R,P,'chosen',0,True)
  archived=list(root.glob('argocd.failed-*.json'));self.assertEqual(len(archived),1);self.assertEqual(json.loads(archived[0].read_text()),old);self.assertEqual(sum(x[1]=='start-build' for x in calls),1);self.assertEqual(json.loads((root/'argocd.json').read_text())['state'],'SUCCEEDED')
 def test_retry_terminal_refuses_unverified_states_without_start(self):
  for status in ('IN_PROGRESS','SUCCEEDED'):
   with self.subTest(status=status):
    work=self.d/status;work.mkdir(mode=0o700);root=work/'platform-bootstrap-builds';root.mkdir(mode=0o700);value={"schema_version":1,"account":A,"region":R,"project":P,"phase":"argocd","state":status,"build_id":ID};(root/'argocd.json').write_text(json.dumps(value));(root/'argocd.json').chmod(0o600);calls=[]
    def aws(profile,region,args): calls.append(args);return [item(status)] if args[0]=='codebuild' else A
    with patch.object(build,'_aws',aws),self.assertRaises(build.BuildError):build.run(work,'argocd',A,R,P,'chosen',0,True)
    self.assertFalse(any(x[1]=='start-build' for x in calls));self.assertEqual(json.loads((root/'argocd.json').read_text()),value)
 def test_retry_terminal_refuses_missing_intent_and_transient_without_start(self):
  for case in ('missing','intent','transient'):
   with self.subTest(case=case):
    work=self.d/('retry-'+case);work.mkdir(mode=0o700);root=work/'platform-bootstrap-builds';root.mkdir(mode=0o700);checkpoint=root/'argocd.json';calls=[]
    if case == 'intent': value={"schema_version":1,"account":A,"region":R,"project":P,"phase":"argocd","state":"start-intent"}
    elif case == 'transient': value={"schema_version":1,"account":A,"region":R,"project":P,"phase":"argocd","state":"FAILED","build_id":ID}
    else: value=None
    if value is not None: checkpoint.write_text(json.dumps(value));checkpoint.chmod(0o600)
    def aws(profile,region,args):
     calls.append(args)
     if case == 'transient': raise build.BuildError('transient')
     raise AssertionError('retry should reject before AWS')
    with patch.object(build,'_aws',aws),self.assertRaises(build.BuildError):build.run(work,'argocd',A,R,P,'chosen',0,True)
    self.assertFalse(any(len(x)>1 and x[1]=='start-build' for x in calls));self.assertEqual(checkpoint.exists(),value is not None)
    if value is not None:self.assertEqual(json.loads(checkpoint.read_text()),value)
 def test_ambiguous_retry_start_retains_intent_and_never_duplicates(self):
  root=self.w/'platform-bootstrap-builds';root.mkdir(mode=0o700);old={"schema_version":1,"account":A,"region":R,"project":P,"phase":"argocd","state":"FAILED","build_id":ID};checkpoint=root/'argocd.json';checkpoint.write_text(json.dumps(old));checkpoint.chmod(0o600);calls=[]
  def uncertain(profile,region,args):
   calls.append(args)
   if args[0]=='sts': return A
   if args[1]=='batch-get-builds': return [item('FAILED')]
   raise build.BuildError('ambiguous start')
  with patch.object(build,'_aws',uncertain):
   with self.assertRaises(build.BuildError): build.run(self.w,'argocd',A,R,P,'chosen',0,True)
   self.assertEqual(json.loads(checkpoint.read_text())['state'],'start-intent')
   with self.assertRaises(build.BuildError): build.run(self.w,'argocd',A,R,P,'chosen',0)
   with self.assertRaises(build.BuildError): build.run(self.w,'argocd',A,R,P,'chosen',0,True)
  self.assertEqual(sum(len(x)>1 and x[1]=='start-build' for x in calls),1)
 def test_unsafe_checkpoint_and_lock_reject_without_aws(self):
  root=self.w/'platform-bootstrap-builds';root.mkdir(mode=0o700);(root/'argocd.json').write_text(json.dumps({"schema_version":1,"account":"999999999999","region":R,"project":P,"phase":"argocd","state":"running","build_id":ID}));(root/'argocd.json').chmod(0o600)
  with patch.object(build,"_aws") as aws:
   with self.assertRaises(build.BuildError):self.invoke()
  aws.assert_not_called();(root/'argocd.json').write_text('{"schema_version":1,"schema_version":1}');(root/'argocd.json').chmod(0o600)
  with patch.object(build,"_aws") as aws:
   with self.assertRaises(build.BuildError):self.invoke()
  aws.assert_not_called();(root/'argocd.json').write_bytes(b'{' + b' '*(64*1024));(root/'argocd.json').chmod(0o600)
  with patch.object(build,"_aws") as aws:
   with self.assertRaises(build.BuildError):self.invoke()
  aws.assert_not_called();(root/'argocd.json').unlink();fd=os.open(root/'.argocd.lock',os.O_CREAT|os.O_RDWR,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  with patch.object(build,"_aws") as aws:
   with self.assertRaises(build.BuildError):self.invoke()
  aws.assert_not_called();fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
  os.unlink(root/'.argocd.lock');os.mkfifo(root/'.argocd.lock',0o600)
  with patch.object(build,"_aws") as aws:
   with self.assertRaises(build.BuildError):self.invoke()
  aws.assert_not_called()
 def test_wrong_sts_account_creates_no_intent_or_build(self):
  calls=[]
  def aws(profile,region,args): calls.append(args); return "999999999999"
  with patch.object(build,"_aws",aws):
   with self.assertRaises(build.BuildError): self.invoke()
  self.assertEqual(calls,[["sts","get-caller-identity","--query","Account"]]);self.assertFalse((self.w/'platform-bootstrap-builds/argocd.json').exists())
 def test_start_projection_requires_complete_identity_and_status(self):
  cases={
   'missing-project': lambda v: v.pop('projectName'),
   'wrong-project': lambda v: v.__setitem__('projectName','other-project'),
   'unknown-status': lambda v: v.__setitem__('buildStatus','UNKNOWN'),
   'inconsistent-complete': lambda v: v.__setitem__('buildComplete',True),
  }
  for name,mutate in cases.items():
   with self.subTest(name=name):
    work=self.d/name;work.mkdir(mode=0o700);start=item('IN_PROGRESS');mutate(start);calls=[]
    def aws(profile,region,args):
     calls.append(args);return A if args[0]=='sts' else start
    with patch.object(build,'_aws',aws):
     with self.assertRaises(build.BuildError): build.run(work,'argocd',A,R,P,'chosen',0)
    self.assertEqual(len(calls),2)
    self.assertEqual(json.loads((work/'platform-bootstrap-builds/argocd.json').read_text())['state'],'start-intent')
 def test_cli_uses_projected_metadata_and_reuses_handle(self):
  bindir=self.d/'bin';bindir.mkdir();log=self.d/'aws.log';aws=bindir/'aws'
  aws.write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$BUILD_LOG"
case "$*" in
  *'sts get-caller-identity --query Account'*) printf '"123456789012"\\n' ;;
  *'codebuild start-build'*) printf '%s\\n' '{"id":"argocd-project:abc123","arn":"arn:aws:codebuild:ap-northeast-2:123456789012:build/argocd-project:abc123","projectName":"argocd-project","buildStatus":"IN_PROGRESS","buildComplete":false}' ;;
  *'codebuild batch-get-builds'*) printf '%s\\n' '[{"id":"argocd-project:abc123","arn":"arn:aws:codebuild:ap-northeast-2:123456789012:build/argocd-project:abc123","projectName":"argocd-project","buildStatus":"SUCCEEDED","buildComplete":true}]' ;;
  *) exit 99 ;;
esac
''');aws.chmod(0o700)
  args=[sys.executable,str(ROOT/'scripts/release/platform_bootstrap_build.py'),'--work-dir',str(self.w),'--phase','argocd','--account',A,'--region',R,'--project',P,'--profile','chosen','--timeout-seconds','0']
  env={**os.environ,'PATH':str(bindir)+os.pathsep+os.environ['PATH'],'BUILD_LOG':str(log)}
  self.assertEqual(subprocess.run(args,env=env,capture_output=True,text=True,timeout=10).returncode,0)
  self.assertEqual(subprocess.run(args,env=env,capture_output=True,text=True,timeout=10).returncode,0)
  calls=log.read_text().splitlines();self.assertEqual(sum('codebuild start-build' in c for c in calls),1);self.assertTrue(all('--profile chosen --region ap-northeast-2 --no-cli-pager' in c for c in calls));self.assertTrue(any('builds[].{id:id,arn:arn,projectName:projectName,buildStatus:buildStatus,buildComplete:buildComplete}' in c for c in calls))
 def test_sigkill_releases_kernel_lock(self):
  root=self.w/'platform-bootstrap-builds';root.mkdir(mode=0o700);lock=root/'.argocd.lock'
  child=subprocess.Popen([sys.executable,'-c',"import fcntl,os,sys,time; fd=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR,0o600); fcntl.flock(fd,fcntl.LOCK_EX); print('ready',flush=True); time.sleep(60)",str(lock)],stdout=subprocess.PIPE,text=True)
  try:
   self.assertEqual(child.stdout.readline().strip(),'ready')
   with patch.object(build,"_aws") as aws:
    with self.assertRaises(build.BuildError):self.invoke()
   aws.assert_not_called();child.kill();self.assertEqual(child.wait(timeout=5),-9)
   def ok(profile,region,args): return A if args[0]=='sts' else item('IN_PROGRESS') if args[1]=='start-build' else [item()]
   with patch.object(build,"_aws",ok): self.invoke()
  finally:
   if child.poll() is None: child.kill();child.wait(timeout=5)
   if child.stdout is not None: child.stdout.close()
 def test_linux_tmp_uses_normal_directory_ancestry(self):
  work=Path('/tmp')/f'platform-bootstrap-build-linux-{os.getpid()}'
  work.mkdir(mode=0o700)
  self.addCleanup(shutil.rmtree,work,True)
  original_lstat=Path.lstat;original_is_symlink=Path.is_symlink
  def lstat(path):
   if path == Path('/tmp'): return os.stat_result((stat.S_IFDIR|0o1777,0,0,1,0,0,0,0,0,0))
   return original_lstat(path)
  def is_symlink(path): return False if path == Path('/tmp') else original_is_symlink(path)
  with patch.object(build.sys,'platform','linux'),patch.object(Path,'lstat',lstat),patch.object(Path,'is_symlink',is_symlink):
   self.assertEqual(build._safe_work(work),work/'platform-bootstrap-builds')
 def test_macos_system_aliases_are_the_only_alias_exception(self):
  original_lstat=Path.lstat;original_resolve=Path.resolve;original_is_symlink=Path.is_symlink
  for alias,target,relative in ((Path('/tmp'),Path('/private/tmp'),Path('')), (Path('/var'),Path('/private/var'),Path('tmp'))):
   with self.subTest(alias=alias):
    work=alias/relative/f'platform-bootstrap-build-darwin-{os.getpid()}'
    work.mkdir(mode=0o700)
    self.addCleanup(shutil.rmtree,work,True)
    def lstat(path,alias=alias):
     if path == alias: return os.stat_result((stat.S_IFLNK|0o777,0,0,1,0,0,0,0,0,0))
     return original_lstat(path)
    def resolve(path,*args,alias=alias,target=target,**kwargs):
     if path == alias: return target
     return original_resolve(path,*args,**kwargs)
    def is_symlink(path,alias=alias): return True if path == alias else original_is_symlink(path)
    with patch.object(build.sys,'platform','darwin'),patch.object(Path,'lstat',lstat),patch.object(Path,'resolve',resolve),patch.object(Path,'is_symlink',is_symlink):
     self.assertEqual(build._safe_work(work),work/'platform-bootstrap-builds')
 def test_wrong_macos_alias_and_untrusted_symlink_ancestry_reject(self):
  work=Path('/tmp')/f'platform-bootstrap-build-wrong-alias-{os.getpid()}'
  work.mkdir(mode=0o700)
  self.addCleanup(shutil.rmtree,work,True)
  original_lstat=Path.lstat;original_resolve=Path.resolve;original_is_symlink=Path.is_symlink
  def lstat(path):
   if path == Path('/tmp'): return os.stat_result((stat.S_IFLNK|0o777,0,0,1,0,0,0,0,0,0))
   return original_lstat(path)
  def resolve(path,*args,**kwargs):
   if path == Path('/tmp'): return Path('/untrusted/tmp')
   return original_resolve(path,*args,**kwargs)
  def is_symlink(path): return True if path == Path('/tmp') else original_is_symlink(path)
  with patch.object(build.sys,'platform','darwin'),patch.object(Path,'lstat',lstat),patch.object(Path,'resolve',resolve),patch.object(Path,'is_symlink',is_symlink):
   with self.assertRaises(build.BuildError): build._safe_work(work)
  link=self.d/'untrusted-parent';link.symlink_to(self.d,target_is_directory=True);linked_work=link/'linked-work';linked_work.mkdir(mode=0o700)
  with self.assertRaises(build.BuildError): build._safe_work(linked_work)
 def test_work_mode_remains_private(self):
  self.w.chmod(0o755)
  with self.assertRaises(build.BuildError): build._safe_work(self.w)
if __name__=="__main__": unittest.main()
