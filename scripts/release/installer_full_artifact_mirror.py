"""Fail-closed pre-EKS mirror for non-Vault installer OCI artifacts.

Vault is deliberately delegated to ``verify_pre_eks_vault_mirror``; this
module neither replaces nor rewrites the Vault receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from installer_artifact_inventory import InventoryError, build_inventory
from installer_artifact_mirror import MirrorError, _mirror_env, verify_pre_eks_vault_mirror
from installer_artifact_prerequisites import PrerequisiteError, load_projection
from installer_artifact_receipt import NAMES as VAULT_NAMES
from installer_registry_auth import RegistryAuthError, write_ecr_auth

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$")
TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
TIMEOUT = 30
DOCKER_TIMEOUT = 900
PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class FullMirrorError(RuntimeError):
    pass


def _read(path: Path) -> bytes:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024:
            raise FullMirrorError("mirror record is unsafe")
        return path.read_bytes()
    except OSError as error:
        raise FullMirrorError("mirror record is unavailable") from error


def _write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink() or path.parent.is_symlink() or not path.parent.is_dir():
        raise FullMirrorError("mirror outcome path is unsafe or already exists")
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".full-mirror-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        fd = -1
        os.link(temporary, path)
    except OSError as error:
        raise FullMirrorError("could not atomically publish mirror outcome") from error
    finally:
        if fd != -1: os.close(fd)
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def _run(command: list[str], env: dict[str, str], runner: Any, *, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        timeout = DOCKER_TIMEOUT if command[:2] in (["docker", "pull"], ["docker", "run"]) else TIMEOUT
        return runner(command, check=check, capture_output=True, text=True, input=input, env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
        raise FullMirrorError("artifact mirror command failed") from error


def _describe(account: str, region: str, repository: str, tag: str, digest: str, env: dict[str, str], runner: Any, *, absent_ok: bool) -> bool:
    command = ["aws", "ecr", "describe-images", "--registry-id", account, "--region", region,
               "--repository-name", repository, "--image-ids", f"imageTag={tag}",
               "--cli-connect-timeout", "10", "--cli-read-timeout", "20", "--output", "json"]
    result = _run(command, env, runner, check=False)
    if result.returncode:
        if absent_ok and "ImageNotFoundException" in (result.stderr or ""):
            return False
        raise FullMirrorError("ECR destination verification failed")
    try: value = json.loads(result.stdout)
    except json.JSONDecodeError as error: raise FullMirrorError("ECR destination response is malformed") from error
    rows = value.get("imageDetails") if isinstance(value, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise FullMirrorError("ECR destination response is ambiguous")
    row = rows[0]
    tags = row.get("imageTags")
    if row.get("registryId") != account or row.get("repositoryName") != repository or row.get("imageDigest") != digest or not isinstance(tags, list) or any(not isinstance(x, str) for x in tags) or tags.count(tag) != 1:
        raise FullMirrorError("ECR destination identity differs from target")
    return True


def _ecr_registry(source: str) -> tuple[str, str, str] | None:
    # Private ECR in the standard AWS partition; authorization still requires
    # the selected profile to have source-registry permissions separately.
    registry = source.split("/", 1)[0]
    match = re.fullmatch(r"([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com", registry)
    return (match.group(1), match.group(2), registry) if match else None


def _plan(bundle_root: Path, work_dir: Path, inputs_dir: Path, discovery: dict[str, str], release_sha: str) -> tuple[dict[str, Any], list[dict[str, str]], str]:
    try:
        authority = work_dir / "local-artifact-authority.json"
        inventory = build_inventory(bundle_root, release_sha, discovery["aws_account_id"], discovery["aws_region"], discovery["deployment_name"], require_signer_probe=True,
                                    local_artifact_authority=authority if authority.exists() or authority.is_symlink() else None)
    except InventoryError as error:
        raise FullMirrorError("artifact authority inventory is invalid") from error
    if inventory.get("complete") is not True:
        raise FullMirrorError("artifact authority inventory is incomplete")
    try:
        projection = load_projection(work_dir / "artifact-prerequisites.json", work_dir=work_dir, bundle_root=bundle_root, discovery=discovery, inputs_dir=inputs_dir)
    except (PrerequisiteError, OSError, ValueError) as error:
        raise FullMirrorError("artifact prerequisite projection is unavailable") from error
    rows = projection.get("repositories")
    if not isinstance(rows, dict): raise FullMirrorError("artifact prerequisite projection is invalid")
    tool = next((x for x in inventory.get("artifacts", []) if isinstance(x, dict) and x.get("component") == "gitops-oci-mirror"), None)
    tool_ref = tool.get("source") if isinstance(tool, dict) else None
    if not isinstance(tool_ref, str) or not re.fullmatch(r"ghcr\.io/[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*/gitops-oci-mirror@sha256:[a-f0-9]{64}", tool_ref):
        raise FullMirrorError("pinned OCI mirror tool is unavailable")
    planned: list[dict[str, str]] = []
    for item in inventory.get("artifacts", []):
        if not isinstance(item, dict) or item.get("required") is not True or not isinstance(item.get("component"), str):
            raise FullMirrorError("artifact authority inventory is malformed")
        component = item["component"]
        if component == "gitops-oci-mirror" or component in VAULT_NAMES: continue
        source, destination = item.get("source"), item.get("destination")
        if not isinstance(source, str) or not IMAGE.fullmatch(source) or not isinstance(destination, str):
            raise FullMirrorError("non-Vault artifact has no immutable source")
        registry = f"{discovery['aws_account_id']}.dkr.ecr.{discovery['aws_region']}.amazonaws.com/"
        if not destination.startswith(registry) or destination.count("@") != 1: raise FullMirrorError("artifact destination is invalid")
        repository, digest = destination[len(registry):].rsplit("@", 1)
        if not DIGEST.fullmatch(digest) or source.rsplit("@", 1)[1] != digest: raise FullMirrorError("artifact source and destination digest differ")
        row = rows.get(repository)
        if not isinstance(row, dict) or row.get("url") != registry + repository: raise FullMirrorError("artifact destination is not in prerequisite projection")
        tag = item.get("destination_tag", digest.removeprefix("sha256:"))
        if not isinstance(tag, str) or not TAG.fullmatch(tag): raise FullMirrorError("artifact destination tag is invalid")
        planned.append({"component": component, "source": source, "destination": destination, "repository": repository, "digest": digest, "tag": tag})
    if not planned or len({x["component"] for x in planned}) != len(planned): raise FullMirrorError("non-Vault mirror plan is empty or ambiguous")
    return projection, sorted(planned, key=lambda x: x["component"]), tool_ref


def mirror(state_dir: Path, bundle_root: Path, discovery: dict[str, str], profile: str, release_sha: str, *, work_dir: Path, inputs_dir: Path, runner: Any = subprocess.run, resume: bool = False, payload_dir: Path | None = None, authenticated_bundle_manifest_sha256: str | None = None) -> Path:
    from installer_oci_binding import payload_context
    with payload_context(bundle_root, release_sha, discovery, state_dir, payload_dir, authenticated_bundle_manifest_sha256) as layouts:
        return _mirror(state_dir, bundle_root, discovery, profile, release_sha, work_dir=work_dir,
                       inputs_dir=inputs_dir, runner=runner, resume=resume, layouts=layouts)


def _mirror(state_dir: Path, bundle_root: Path, discovery: dict[str, str], profile: str, release_sha: str, *, work_dir: Path, inputs_dir: Path, runner: Any, resume: bool, layouts: Path | None) -> Path:
    _context(state_dir, work_dir, profile, release_sha)
    projection, plan, tool = _plan(bundle_root, work_dir, inputs_dir, discovery, release_sha)
    projection_bytes = _read(work_dir / "artifact-prerequisites.json")
    receipt = state_dir / "full-artifact-mirror-receipt.json"; marker = state_dir / "full-artifact-mirror-uncertain.json"; lock = state_dir / ".full-artifact-mirror.lock"
    local_binding = {"schema_version":1,"status":"started",**discovery,"release_revision":release_sha,"input_fingerprint":projection.get("input_fingerprint"),"projection_sha256":hashlib.sha256(projection_bytes).hexdigest(),"plan_sha256":hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest()}
    if receipt.exists() or receipt.is_symlink():
        if not resume or receipt.is_symlink() or marker.is_symlink(): raise FullMirrorError("prior full mirror receipt requires read-only reconciliation")
        try: os.mkdir(lock,0o700)
        except FileExistsError as error: raise FullMirrorError("another full mirror operation holds the local lock") from error
        try:
            # Recheck only after acquiring the lock: no concurrent copier may
            # race a receipt reconciliation into an overwrite.
            if not receipt.exists() or receipt.is_symlink() or marker.is_symlink(): raise FullMirrorError("full mirror outcome changed during reconciliation")
            verify(state_dir,bundle_root,discovery,profile,release_sha,work_dir=work_dir,inputs_dir=inputs_dir,runner=runner)
            return receipt
        finally:
            try: lock.rmdir()
            except OSError: pass
    if marker.exists() or marker.is_symlink():
        if not resume or marker.is_symlink(): raise FullMirrorError("prior full mirror outcome requires reconciliation")
        try: prior=json.loads(_read(marker))
        except json.JSONDecodeError as error: raise FullMirrorError("prior full mirror marker is invalid") from error
        if not isinstance(prior,dict) or any(prior.get(k)!=v for k,v in local_binding.items()) or set(prior) != set(local_binding)|{"vault_binding_sha256"}:
            raise FullMirrorError("prior full mirror marker is not bound to this attempt")
    elif resume:
        raise FullMirrorError("no prior full mirror marker is available to resume")
    try: os.mkdir(lock,0o700)
    except FileExistsError as error: raise FullMirrorError("another full mirror operation holds the local lock") from error
    # This is an independent re-read of the existing Vault subset, never a replacement receipt.
    try: vault = verify_pre_eks_vault_mirror(state_dir, bundle_root, discovery, profile, release_sha, inputs_dir, work_dir=work_dir)
    except Exception as error:
        lock.rmdir(); raise FullMirrorError("Vault subset is not verified") from error
    marker_binding={**local_binding,"vault_binding_sha256":hashlib.sha256(json.dumps(vault,sort_keys=True).encode()).hexdigest()}
    try: same_marker = not marker.exists() or json.loads(_read(marker)) == marker_binding
    except (OSError, json.JSONDecodeError): same_marker = False
    if not same_marker:
        lock.rmdir(); raise FullMirrorError("prior full mirror Vault binding differs")
    env = _mirror_env(profile, discovery["aws_region"]); account = discovery["aws_account_id"]; region = discovery["aws_region"]
    try:
        identity = _run(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], env, runner)
        if identity.stdout.strip() != account: raise FullMirrorError("selected AWS profile is not the selected account")
    except FullMirrorError:
        lock.rmdir(); raise
    try:
        work = Path(tempfile.mkdtemp(prefix=".full-artifact-mirror-", dir=state_dir)); os.chmod(work, 0o700); auth = work / "auth"; auth.mkdir(mode=0o700)
    except OSError as error:
        lock.rmdir(); raise FullMirrorError("private mirror workspace could not be created") from error
    registry = f"{account}.dkr.ecr.{region}.amazonaws.com"
    try:
        if not marker.exists(): _write_new(marker, marker_binding)
        _run(["docker", "pull", tool], env, runner)
        authenticated: set[str] = set()
        def login(login_region: str, login_registry: str) -> None:
            # Keep portable auths-only credentials in one private, short-lived
            # file: Docker credential helpers are unavailable in mirror containers.
            if login_registry in authenticated: return
            password = _run(["aws", "ecr", "get-login-password", "--region", login_region], env, runner).stdout
            try:
                write_ecr_auth(auth, login_registry, password, authenticated)
            except RegistryAuthError as error:
                raise FullMirrorError("could not create portable registry auth") from error
        verified: list[dict[str, str]] = []
        for item in plan:
            exists = _describe(account, region, item["repository"], item["tag"], item["digest"], env, runner, absent_ok=True)
            if not exists:
                source_ecr = _ecr_registry(item["source"]) if layouts is None else None
                if source_ecr is not None: login(source_ecr[1], source_ecr[2])
                login(region, registry)
                mount = ["--volume", f"{layouts}:/payload:ro"] if layouts is not None else []
                source = ("oci:/payload/" + item["component"] + ":root-" + item["digest"][7:19]
                          if layouts is not None else "docker://" + item["source"])
                _run(["docker", "run", "--rm", "--env", "REGISTRY_AUTH_FILE=/auth/config.json", "--volume", f"{auth}:/auth:ro", *mount, tool, "copy", "--all", "--preserve-digests", source, "docker://" + registry + "/" + item["repository"] + ":" + item["tag"]], env, runner)
                _describe(account, region, item["repository"], item["tag"], item["digest"], env, runner, absent_ok=False)
            verified.append({"component": item["component"], "image_ref": item["destination"], "tag": item["tag"], "manifest_digest": item["digest"]})
        if _read(work_dir / "artifact-prerequisites.json") != projection_bytes: raise FullMirrorError("artifact prerequisite projection changed during mirror")
        value = {"schema_version": 1, "status": "verified", "scope": "non-Vault OCI artifacts", "release_revision": release_sha, **discovery, "input_fingerprint": projection.get("input_fingerprint"), "projection_sha256": hashlib.sha256(projection_bytes).hexdigest(), "plan_sha256": hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest(), "vault_binding_sha256": hashlib.sha256(json.dumps(vault, sort_keys=True).encode()).hexdigest(), "artifacts": verified}
        _write_new(receipt, value)
        verify(state_dir,bundle_root,discovery,profile,release_sha,work_dir=work_dir,inputs_dir=inputs_dir,runner=runner)
        marker.unlink(); return receipt
    finally:
        shutil.rmtree(work, ignore_errors=True)
        try: lock.rmdir()
        except OSError: pass


def verify(state_dir: Path, bundle_root: Path, discovery: dict[str, str], profile: str, release_sha: str, *, work_dir: Path, inputs_dir: Path, runner: Any = subprocess.run) -> dict[str, Any]:
    """Read-only reconciliation: prove a prior receipt and all current ECR tags."""
    _context(state_dir, work_dir, profile, release_sha)
    receipt = state_dir / "full-artifact-mirror-receipt.json"
    if state_dir.is_symlink() or not receipt.exists() or receipt.is_symlink(): raise FullMirrorError("no reconciliable full mirror receipt")
    projection, plan, _ = _plan(bundle_root, work_dir, inputs_dir, discovery, release_sha)
    try: value = json.loads(_read(receipt))
    except json.JSONDecodeError as error: raise FullMirrorError("full mirror receipt is invalid") from error
    expected = {"schema_version":1,"status":"verified","scope":"non-Vault OCI artifacts","release_revision":release_sha,**discovery,"input_fingerprint":projection.get("input_fingerprint"),"projection_sha256":hashlib.sha256(_read(work_dir / "artifact-prerequisites.json")).hexdigest(),"plan_sha256":hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest()}
    if not isinstance(value,dict) or any(value.get(k)!=v for k,v in expected.items()): raise FullMirrorError("full mirror receipt binding is invalid")
    try: vault = verify_pre_eks_vault_mirror(state_dir,bundle_root,discovery,profile,release_sha,inputs_dir,work_dir=work_dir)
    except MirrorError as error: raise FullMirrorError("Vault subset is not verified") from error
    expected["vault_binding_sha256"] = hashlib.sha256(json.dumps(vault, sort_keys=True).encode()).hexdigest()
    expected["artifacts"] = [{"component": x["component"], "image_ref": x["destination"], "tag": x["tag"], "manifest_digest": x["digest"]} for x in plan]
    expected_keys = set(expected)
    if set(value) != expected_keys or value != expected: raise FullMirrorError("full mirror receipt binding is invalid")
    env=_mirror_env(profile,discovery["aws_region"])
    for item in plan: _describe(discovery["aws_account_id"],discovery["aws_region"],item["repository"],item["tag"],item["digest"],env,runner,absent_ok=False)
    return value


def _context(state_dir: Path, work_dir: Path, profile: str, release_sha: str) -> None:
    if not state_dir.is_absolute() or state_dir.is_symlink() or not state_dir.is_dir() or stat.S_IMODE(state_dir.stat().st_mode) != 0o700 or not SHA.fullmatch(release_sha) or not PROFILE.fullmatch(profile):
        raise FullMirrorError("mirror context is invalid")
    try:
        resolved_state = state_dir.resolve(strict=True); resolved_work = work_dir.resolve(strict=True)
        resolved_work.relative_to(resolved_state)
    except (OSError, ValueError) as error:
        raise FullMirrorError("mirror work directory is unsafe") from error
    if work_dir.is_symlink() or not work_dir.is_dir() or stat.S_IMODE(work_dir.stat().st_mode) != 0o700:
        raise FullMirrorError("mirror work directory is unsafe")
