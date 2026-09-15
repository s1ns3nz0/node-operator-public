#!/usr/bin/env python3
"""Durably start or observe one selected platform CodeBuild project.

The local checkpoint prevents a retry from silently creating a second build
after an ambiguous start.  It is not a claim that CodeBuild completed.
"""
from __future__ import annotations

import argparse, fcntl, hashlib, json, os, re, signal, stat, subprocess, sys, tempfile, time
from pathlib import Path

ACCOUNT = re.compile(r"[0-9]{12}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z0-9-]+-[0-9]+\Z")
PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,254}\Z")
BUILD = re.compile(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+\Z")
TERMINAL = {"SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"}
NONTERMINAL = {"IN_PROGRESS"}

class BuildError(RuntimeError): pass

def _private(path: Path, directory: bool) -> None:
    try: info = path.lstat()
    except OSError as e: raise BuildError("Platform build checkpoint path is unavailable or unsafe.") from e
    expected_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if path.is_symlink() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600) or not expected_type:
        raise BuildError("Platform build checkpoint path is unavailable or unsafe.")

def _safe_work(work: Path) -> Path:
    if not work.is_absolute() or Path(os.path.normpath(str(work))) != work: raise BuildError("Platform work directory must be normalized and absolute.")
    _private(work, True)
    macos_aliases={Path('/private'):Path('/private'),Path('/var'):Path('/private/var'),Path('/tmp'):Path('/private/tmp')}
    for parent in work.parents:
        # /tmp and /var are macOS system aliases.  Do not apply their Darwin
        # resolution targets on Linux, where /tmp is an ordinary directory.
        if sys.platform == "darwin" and parent in macos_aliases:
            try:
                info = parent.lstat()
                if parent.resolve() != macos_aliases[parent]: raise BuildError("Platform work directory ancestry is unsafe.")
                if parent == Path('/private'):
                    if parent.is_symlink() or not stat.S_ISDIR(info.st_mode): raise BuildError("Platform work directory ancestry is unsafe.")
                elif not parent.is_symlink():
                    raise BuildError("Platform work directory ancestry is unsafe.")
            except OSError as e: raise BuildError("Platform work directory ancestry is unsafe.") from e
            continue
        try: info = parent.lstat()
        except OSError as e: raise BuildError("Platform work directory ancestry is unsafe.") from e
        if parent.is_symlink() or not stat.S_ISDIR(info.st_mode): raise BuildError("Platform work directory ancestry is unsafe.")
    root = work / "platform-bootstrap-builds"
    if root.exists() or root.is_symlink(): _private(root, True)
    else: root.mkdir(mode=0o700)
    return root

def _read(path: Path) -> dict:
    _private(path, False)
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>64*1024: raise OSError("unsafe")
        with os.fdopen(fd,"rb") as f: raw=f.read(64*1024+1); fd=None
        if len(raw)>64*1024: raise OSError("unsafe")
        value=json.loads(raw,object_pairs_hook=lambda pairs: _unique(pairs))
    except (OSError, ValueError) as e: raise BuildError("Platform build checkpoint is malformed.") from e
    finally:
        if fd is not None:
            try: os.close(fd)
            except OSError: pass
    if not isinstance(value, dict): raise BuildError("Platform build checkpoint is malformed.")
    return value

def _unique(pairs: list[tuple[str, object]]) -> dict:
    value={}
    for key,item in pairs:
        if key in value: raise ValueError("duplicate key")
        value[key]=item
    return value

def _write_new(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink(): raise BuildError("Platform build checkpoint already exists.")
    fd, raw = tempfile.mkstemp(prefix=".build-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f: json.dump(value, f, sort_keys=True, separators=(",", ":")); f.flush(); os.fsync(f.fileno())
        os.link(raw, path)
    except OSError as e: raise BuildError("Platform build checkpoint could not be persisted.") from e
    finally:
        try: os.unlink(raw)
        except FileNotFoundError: pass

def _replace(path: Path, value: dict) -> None:
    _private(path, False)
    fd, raw = tempfile.mkstemp(prefix=".build-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f: json.dump(value, f, sort_keys=True, separators=(",", ":")); f.flush(); os.fsync(f.fileno())
        os.replace(raw, path)
    except OSError as e:
        raise BuildError("Platform build checkpoint could not be persisted.") from e
    finally:
        try: os.unlink(raw)
        except FileNotFoundError: pass

def _aws(profile: str, region: str, args: list[str]) -> object:
    env=os.environ.copy()
    for key in ("AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN","AWS_SECURITY_TOKEN","AWS_ACCESS_KEY","AWS_SECRET_KEY","AWS_DEFAULT_PROFILE","AWS_WEB_IDENTITY_TOKEN_FILE","AWS_ROLE_ARN","AWS_ROLE_SESSION_NAME","AWS_CONTAINER_CREDENTIALS_RELATIVE_URI","AWS_CONTAINER_CREDENTIALS_FULL_URI","AWS_CONTAINER_AUTHORIZATION_TOKEN","AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"):
        env.pop(key,None)
    env.update(AWS_PROFILE=profile,AWS_EC2_METADATA_DISABLED="true",AWS_PAGER="",AWS_CLI_AUTO_PROMPT="off")
    try: p=subprocess.run(["aws","--profile",profile,"--region",region,"--no-cli-pager",*args,"--output","json"],env=env,stdin=subprocess.DEVNULL,text=True,capture_output=True,timeout=45)
    except (OSError,subprocess.TimeoutExpired) as e: raise BuildError("CodeBuild read or start could not be completed; the durable handle was retained.") from e
    if p.returncode: raise BuildError("CodeBuild read or start failed; the durable handle was retained.")
    try: return json.loads(p.stdout)
    except ValueError as e: raise BuildError("CodeBuild returned malformed metadata; the durable handle was retained.") from e

def _check_build(value: object, account: str, region: str, project: str, build_id: str) -> str:
    builds=value if isinstance(value,list) else value.get("builds") if isinstance(value,dict) else None
    if not (isinstance(builds,list) and len(builds)==1 and isinstance(builds[0],dict)): raise BuildError("CodeBuild metadata does not identify the selected build.")
    build=builds[0]; status=build.get("buildStatus")
    expected_arn=f"arn:aws:codebuild:{region}:{account}:build/{build_id}"
    if not (build.get("id")==build_id and build_id.startswith(project+":") and build.get("projectName")==project and build.get("arn")==expected_arn and isinstance(status,str) and status in TERMINAL|NONTERMINAL and type(build.get("buildComplete")) is bool and build["buildComplete"] == (status in TERMINAL)):
        raise BuildError("CodeBuild metadata does not bind the selected account, Region, project, and build.")
    return status

def run(work: Path, phase: str, account: str, region: str, project: str, profile: str, timeout: int=1800, retry_terminal: bool=False) -> None:
    if not (ACCOUNT.fullmatch(account) and REGION.fullmatch(region) and PROJECT.fullmatch(project) and re.fullmatch(r"[a-z][a-z0-9-]{1,32}",phase) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",profile) and timeout >= 0): raise BuildError("Platform build arguments are invalid.")
    root=_safe_work(work); checkpoint=root/(phase+".json"); lock=root/("."+phase+".lock")
    try:
        fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600: raise BuildError("Platform build lock is unsafe.")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except (OSError,BuildError) as e:
        try: os.close(fd)
        except (OSError,UnboundLocalError): pass
        raise BuildError("Another platform build monitor holds this phase lock.") from e
    old_term = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(BuildError("Platform build monitor interrupted; durable handle retained.")))
    try:
        expected={"schema_version":1,"account":account,"region":region,"project":project,"phase":phase}
        existed = checkpoint.exists() or checkpoint.is_symlink()
        if existed: value=_read(checkpoint)
        else: value={**expected,"state":"start-intent"}
        if any(value.get(k)!=v for k,v in expected.items()): raise BuildError("Platform build checkpoint does not bind this selected phase.")
        state=value.get("state"); intentional_new_start=False
        keys=set(value)
        if keys != set(expected)|{"state"} and keys != set(expected)|{"state","build_id"}:
            raise BuildError("Platform build checkpoint is malformed.")
        if retry_terminal:
            if state not in TERMINAL or state == "SUCCEEDED" or not isinstance(value.get("build_id"),str): raise BuildError("Terminal retry requires a recorded failed terminal build.")
            build_id=value["build_id"]
            status=_check_build(_aws(profile,region,["codebuild","batch-get-builds","--ids",build_id,"--query","builds[].{id:id,arn:arn,projectName:projectName,buildStatus:buildStatus,buildComplete:buildComplete}"]),account,region,project,build_id)
            if status not in {"FAILED","FAULT","STOPPED","TIMED_OUT"}: raise BuildError("Terminal retry requires an authoritative failed terminal build.")
            if _aws(profile,region,["sts","get-caller-identity","--query","Account"]) != account: raise BuildError("Current AWS identity does not match the selected account; no CodeBuild start was requested.")
            archived=root/(phase+".failed-"+hashlib.sha256(build_id.encode()).hexdigest()+".json")
            if archived.exists() or archived.is_symlink():
                if _read(archived) != value: raise BuildError("Terminal retry archive differs from the recorded failed build.")
            else: _write_new(archived,value)
            value={**expected,"state":"start-intent"}; _replace(checkpoint,value); state="start-intent"; intentional_new_start=True; existed=True
        if state=="start-intent":
            if "build_id" in value: raise BuildError("Platform build checkpoint is malformed.")
            if existed and not intentional_new_start: raise BuildError("CodeBuild start outcome is uncertain; reconcile the durable intent before retrying.")
            identity=_aws(profile,region,["sts","get-caller-identity","--query","Account"])
            if identity != account: raise BuildError("Current AWS identity does not match the selected account; no CodeBuild start was requested.")
            if not intentional_new_start: _write_new(checkpoint,value)
            result=_aws(profile,region,["codebuild","start-build","--project-name",project,"--query","build.{id:id,arn:arn,projectName:projectName,buildStatus:buildStatus,buildComplete:buildComplete}"])
            build_id=result.get("id") if isinstance(result,dict) else None
            if not (isinstance(build_id,str) and BUILD.fullmatch(build_id)):
                raise BuildError("CodeBuild start did not return the selected build identity; reconcile the durable intent before retrying.")
            # StartBuild uses a projected object while BatchGetBuilds returns a list.
            # Validate the same complete identity/status contract before recording it.
            _check_build([result], account, region, project, build_id)
            value={**expected,"state":"running","build_id":build_id}; _replace(checkpoint,value); state="running"
        elif state not in ("running",*TERMINAL): raise BuildError("Platform build checkpoint is malformed.")
        if state=="start-intent": raise BuildError("CodeBuild start outcome is uncertain; reconcile the durable intent before retrying.")
        build_id=value.get("build_id")
        if not (isinstance(build_id,str) and BUILD.fullmatch(build_id)): raise BuildError("Platform build checkpoint is malformed.")
        deadline=time.monotonic()+timeout
        reported=None
        while True:
            status=_check_build(_aws(profile,region,["codebuild","batch-get-builds","--ids",build_id,"--query","builds[].{id:id,arn:arn,projectName:projectName,buildStatus:buildStatus,buildComplete:buildComplete}"]),account,region,project,build_id)
            if status != reported:
                print(f"CodeBuild phase {phase} build {build_id} status {status}", file=sys.stderr, flush=True); reported=status
            if status in TERMINAL:
                value={**expected,"state":status,"build_id":build_id}; _replace(checkpoint,value)
                if status=="SUCCEEDED": return
                raise BuildError("CodeBuild ended unsuccessfully; the durable handle was retained and will not be restarted.")
            if time.monotonic()>=deadline: raise BuildError("CodeBuild is still nonterminal; durable handle retained for a later poll.")
            time.sleep(min(10,max(0,deadline-time.monotonic())))
    finally:
        signal.signal(signal.SIGTERM, old_term)
        try: fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
        except OSError: pass

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--work-dir",type=Path,required=True); p.add_argument("--phase",required=True); p.add_argument("--account",required=True); p.add_argument("--region",required=True); p.add_argument("--project",required=True); p.add_argument("--profile",required=True); p.add_argument("--timeout-seconds",type=int,default=1800); p.add_argument("--retry-terminal",action="store_true"); a=p.parse_args()
    try: run(a.work_dir,a.phase,a.account,a.region,a.project,a.profile,a.timeout_seconds,a.retry_terminal)
    except BuildError as e: print(str(e),file=sys.stderr); return 70
    return 0
if __name__=="__main__": raise SystemExit(main())
