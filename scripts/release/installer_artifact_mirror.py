"""Mirror the release-bound Vault prerequisites into existing private ECR repositories."""
from __future__ import annotations
import base64, hashlib, json, os, re, stat, subprocess, tempfile, shutil
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$"); DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
class MirrorError(RuntimeError): pass
NAMES = {"vault-bootstrap","vault-audit-relay","gitops-oci-mirror","vault-server","vault-injector","cert-manager-controller","cert-manager-webhook","cert-manager-cainjector","cert-manager-startupapicheck","vault-chart","cert-manager-chart"}
AWS_TIMEOUT=30
DOCKER_TIMEOUT=900
OCI_MANIFEST_MEDIA_TYPE="application/vnd.oci.image.manifest.v1+json"
HELM_CONFIG_MEDIA_TYPE="application/vnd.cncf.helm.config.v1+json"
HELM_LAYER_MEDIA_TYPE="application/vnd.cncf.helm.chart.content.v1.tar+gzip"

def _read(path: Path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4*1024*1024: raise MirrorError("artifact input is unsafe")
    try: return json.loads(path.read_text())
    except Exception as e: raise MirrorError("artifact input is invalid") from e

def _write(path: Path, value: dict):
    if not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700 or path.exists() or path.is_symlink(): raise MirrorError("mirror output path is unsafe")
    fd, tmp = tempfile.mkstemp(prefix=".mirror-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write((json.dumps(value, sort_keys=True)+"\n").encode())
            handle.flush(); os.fsync(handle.fileno())
        fd = -1
        os.link(tmp, path)
    except Exception as e: raise MirrorError("could not atomically publish mirror output") from e
    finally:
        if fd != -1:
            os.close(fd)
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def _chart_fixture(name: str, item: dict) -> tuple[bytes, bytes, list[dict]]:
    """Return payload bytes, not a new approval authority.

    The selected release index supplies the approved manifest/archive hashes.
    Source fixtures merely recover those exact bytes; changing them cannot
    authorize another digest. Updates must recover the original config and
    manifest or pass a separate catalog approval, never accept a fresh push's
    timestamp. The bound manifest also fixes whether provenance is required.
    """
    # ``__file__`` is under ``source/scripts/release`` in a candidate bundle,
    # so this binds to the candidate's included fixture without mutating the
    # separately verified bundle root.
    fixture_name=name.removesuffix("-chart")+".json"
    fixture=_read(Path(__file__).resolve().parents[2]/".ci/gitops/helm-oci"/fixture_name)
    if not isinstance(fixture,dict) or set(fixture)!={"schema_version","manifest_base64","config_base64"} or fixture.get("schema_version")!=1 or any(not isinstance(fixture.get(key),str) for key in ("manifest_base64","config_base64")):
        raise MirrorError("approved chart OCI fixture is invalid")
    try:
        manifest=base64.b64decode(fixture["manifest_base64"],validate=True); config=base64.b64decode(fixture["config_base64"],validate=True)
        value=json.loads(manifest)
    except (ValueError, json.JSONDecodeError) as error:
        raise MirrorError("approved chart OCI fixture is invalid") from error
    expected=item.get("expected_oci_manifest_digest")
    if not isinstance(expected,str) or hashlib.sha256(manifest).hexdigest() != expected.removeprefix("sha256:") or not isinstance(value,dict) or value.get("schemaVersion")!=2 or value.get("mediaType") not in (None,OCI_MANIFEST_MEDIA_TYPE):
        raise MirrorError("approved chart OCI manifest digest differs from authority")
    config_descriptor=value.get("config"); layers=value.get("layers")
    if not isinstance(config_descriptor,dict) or set(config_descriptor)!={"mediaType","digest","size"} or config_descriptor.get("mediaType")!=HELM_CONFIG_MEDIA_TYPE or config_descriptor.get("digest")!="sha256:"+hashlib.sha256(config).hexdigest() or config_descriptor.get("size")!=len(config) or not isinstance(layers,list) or not 1 <= len(layers) <= 2:
        raise MirrorError("approved chart OCI config descriptor is invalid")
    expected_types=[HELM_LAYER_MEDIA_TYPE]+(["application/vnd.cncf.helm.chart.provenance.v1.prov"] if len(layers)==2 else [])
    for position,(layer,media_type) in enumerate(zip(layers,expected_types)):
        if not isinstance(layer,dict) or set(layer)!={"mediaType","digest","size"} or layer.get("mediaType")!=media_type or not DIGEST.fullmatch(layer.get("digest", "")) or not isinstance(layer.get("size"),int) or layer["size"] < 1 or (position==0 and layer["digest"]!="sha256:"+item["archive_sha256"]):
            raise MirrorError("approved chart OCI layer descriptor is invalid")
    return manifest,config,layers

def _chart_layout(work: Path, name: str, manifest: bytes, config: bytes, layers: list[dict], archives: list[Path]) -> tuple[Path, str]:
    try:
        if len(layers)!=len(archives): raise MirrorError("approved chart OCI layers are incomplete")
        for layer,archive in zip(layers,archives):
            info=archive.lstat()
            if archive.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size != layer["size"] or hashlib.sha256(archive.read_bytes()).hexdigest() != layer["digest"].removeprefix("sha256:"):
                raise MirrorError("downloaded chart archive differs from approved OCI layer")
        layout=work/"oci"/name; blobs=layout/"blobs/sha256"; blobs.mkdir(parents=True,mode=0o700)
        stage="mirror-"+hashlib.sha256(manifest).hexdigest()
        descriptor={"mediaType":OCI_MANIFEST_MEDIA_TYPE,"digest":"sha256:"+hashlib.sha256(manifest).hexdigest(),"size":len(manifest),"annotations":{"org.opencontainers.image.ref.name":stage}}
        for path,raw in ((layout/"oci-layout",b'{"imageLayoutVersion":"1.0.0"}'),(layout/"index.json",json.dumps({"schemaVersion":2,"manifests":[descriptor]},sort_keys=True,separators=(",",":")).encode()),(blobs/hashlib.sha256(manifest).hexdigest(),manifest),(blobs/hashlib.sha256(config).hexdigest(),config)):
            path.write_bytes(raw); os.chmod(path,0o600)
        for layer,archive in zip(layers,archives):
            destination=blobs/layer["digest"].removeprefix("sha256:"); shutil.copyfile(archive,destination); os.chmod(destination,0o600)
        return layout,stage
    except OSError as error:
        raise MirrorError("could not materialize approved chart OCI layout") from error

def _staged_chart_manifest(account: str, region: str, repository: str, stage: str, expected: bytes, env: dict) -> None:
    command=["aws","ecr","batch-get-image","--registry-id",account,"--region",region,"--repository-name",repository,"--image-ids","imageTag="+stage,"--accepted-media-types",OCI_MANIFEST_MEDIA_TYPE,"--output","json"]
    result=subprocess.run(command,check=True,capture_output=True,text=True,env=env,timeout=AWS_TIMEOUT)
    try:
        value=json.loads(result.stdout); images=value.get("images") if isinstance(value,dict) else None
        raw=images[0].get("imageManifest") if isinstance(images,list) and len(images)==1 and isinstance(images[0],dict) else None
    except json.JSONDecodeError as error:
        raise MirrorError("staged chart manifest response is invalid") from error
    if not isinstance(raw,str) or raw.encode()!=expected or hashlib.sha256(raw.encode()).hexdigest()!=hashlib.sha256(expected).hexdigest():
        raise MirrorError("staged chart manifest differs from approved bytes")

def _mirror_env(profile: str, region: str) -> dict:
    env=dict(os.environ)
    for key in list(env):
        if key in {"AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN","AWS_SECURITY_TOKEN","BASH_ENV"} or key.startswith("TF_VAR_") or key.startswith("AWS_ENDPOINT_URL"):
            env.pop(key, None)
    # Selected local profile/config remains the operator's authentication source,
    # not a sandbox for hostile local credentials files or executable helpers.
    # Endpoint overrides must never redirect identity or destination evidence.
    env.update(AWS_PROFILE=profile, AWS_DEFAULT_PROFILE=profile, AWS_REGION=region,
               AWS_DEFAULT_REGION=region, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    return env

def _describe_digest(account: str, region: str, repository: str, tag: str, digest: str, env: dict, *, absent_ok: bool = False) -> str | None:
    command=["aws","ecr","describe-images","--registry-id",account,"--region",region,"--repository-name",repository,"--image-ids",f"imageTag={tag}","--cli-connect-timeout","10","--cli-read-timeout","20","--output","json"]
    try:
        result=subprocess.run(command,check=False,capture_output=True,text=True,env=env,timeout=AWS_TIMEOUT)
        if getattr(result,"returncode",0):
            if absent_ok and "ImageNotFoundException" in (getattr(result,"stderr","") or ""): return None
            raise MirrorError("ECR destination verification failed")
        raw=result.stdout
        value=json.loads(raw)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as error:
        raise MirrorError("ECR destination verification failed") from error
    rows=value.get("imageDetails") if isinstance(value,dict) else None
    if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict): raise MirrorError("ECR destination response is ambiguous")
    row=rows[0]
    if row.get("registryId")!=account or row.get("repositoryName")!=repository or row.get("imageDigest")!=digest: raise MirrorError("ECR destination identity differs from target")
    tags=row.get("imageTags")
    if not isinstance(tags,list) or any(not isinstance(value,str) for value in tags) or tags.count(tag)!=1:
        raise MirrorError("ECR destination does not bind the requested tag to the approved digest")
    return digest

def _pre_eks_destinations(projection: dict, discovery: dict) -> dict:
    account, region, name = discovery["aws_account_id"], discovery["aws_region"], discovery["deployment_name"]
    if projection.get("aws_account_id") != account or projection.get("aws_region") != region or projection.get("deployment_name") != name:
        raise MirrorError("artifact prerequisite projection deployment differs")
    repositories=projection.get("repositories")
    if not isinstance(repositories,dict): raise MirrorError("artifact prerequisite projection repositories are invalid")
    prefix=f"{name}-baseline-"
    needed={"vault":prefix+"gitops-vault","vault_chart":prefix+"gitops-vault/vault","cert_manager":prefix+"gitops-cert-manager","cert_manager_chart":prefix+"gitops-cert-manager/cert-manager","relay":prefix+"vault-audit-relay"}
    values={}
    expected_prefix=f"{account}.dkr.ecr.{region}.amazonaws.com/"
    for label, repository_name in needed.items():
        row=repositories.get(repository_name)
        if not isinstance(row,dict) or row.get("url") != expected_prefix+repository_name:
            raise MirrorError("artifact prerequisite projection destination is invalid")
        values[label]=row["url"]
    return {"vault-bootstrap":values["vault"],"vault-server":values["vault"],"vault-injector":values["vault"],"cert-manager-controller":values["cert_manager"],"cert-manager-webhook":values["cert_manager"],"cert-manager-cainjector":values["cert_manager"],"cert-manager-startupapicheck":values["cert_manager"],"vault-audit-relay":values["relay"],"vault-chart":values["vault_chart"],"cert-manager-chart":values["cert_manager_chart"]}

def _binding_artifacts(index: dict, destinations: dict) -> dict:
    artifacts={}
    for name,destination in destinations.items():
        item=index["components"][name]
        digest=item.get("expected_oci_manifest_digest") if name.endswith("chart") else item.get("manifest_digest")
        if not isinstance(digest,str) or not DIGEST.fullmatch(digest): raise MirrorError("artifact authority digest is invalid")
        artifacts[name]={"image_ref":destination+"@"+digest,"manifest_digest":digest}
        if name.endswith("chart"): artifacts[name]["version"]=item["version"]
    return artifacts

def _strict_pre_eks_index(index: dict, index_bytes: bytes) -> None:
    # Reuse the shared release-index schema validator, not a mirror-local copy.
    from installer_artifact_receipt import _validate_index, _validate_raw_index, ReceiptError
    try:
        _validate_raw_index(index, index_bytes); _validate_index(index)
    except ReceiptError as error: raise MirrorError("artifact index is not strict shared authority") from error

def _pre_eks_work_dir(state_dir: Path, work_dir: Path | None) -> Path:
    candidate=(work_dir or state_dir/"terraform-work")
    try:
        resolved_state=state_dir.resolve(strict=True); resolved=candidate.resolve(strict=True)
        resolved.relative_to(resolved_state)
    except (OSError, ValueError) as error: raise MirrorError("pre-EKS work directory is unsafe") from error
    if not resolved.is_dir() or resolved.is_symlink(): raise MirrorError("pre-EKS work directory is unsafe")
    return resolved

def mirror(state_dir: Path, bundle_root: Path, discovery: dict, profile: str, release_sha: str, *, prerequisites_path: Path | None = None, inputs_dir: Path | None = None, work_dir: Path | None = None, resume: bool = False, layouts: Path | None = None) -> Path:
    index_path = bundle_root / "rendered/installer-artifact-index.json"; index = _read(index_path)
    index_bytes=index_path.read_bytes()
    if not SHA.fullmatch(release_sha) or set(index) != {"schema_version","release_revision","components"} or index["schema_version"] != 1 or index["release_revision"] != release_sha or set(index["components"]) != NAMES: raise MirrorError("artifact index is not the exact selected release index")
    account, region = discovery["aws_account_id"], discovery["aws_region"]; prefix=f"{account}.dkr.ecr.{region}.amazonaws.com/"
    pre_eks = prerequisites_path is not None
    projection = None
    if pre_eks:
        from installer_artifact_prerequisites import load_projection, PrerequisiteError
        prerequisite_work_dir=_pre_eks_work_dir(state_dir,work_dir)
        prerequisites_path=prerequisites_path or prerequisite_work_dir/"artifact-prerequisites.json"
        effective_inputs=inputs_dir
        try:
            projection=load_projection(prerequisites_path, work_dir=prerequisite_work_dir, bundle_root=bundle_root, discovery=discovery, inputs_dir=effective_inputs)
        except (PrerequisiteError, OSError, ValueError) as error: raise MirrorError("artifact prerequisite projection is unavailable or unsafe") from error
        destinations=_pre_eks_destinations(projection, discovery)
        projection_bytes=prerequisites_path.read_bytes()
        _strict_pre_eks_index(index, index_path.read_bytes())
        repos={"vault":destinations["vault-server"],"vault_chart":destinations["vault-chart"],"cert_manager":destinations["cert-manager-controller"],"cert_manager_chart":destinations["cert-manager-chart"]}; relay=destinations["vault-audit-relay"]
        marker=state_dir/"vault-pre-eks-artifact-mirror-uncertain.json"; manifest=state_dir/"vault-artifact-manifest.json"; receipt=state_dir/"vault-artifact-mirror-receipt.json"
    else:
        baseline = _read(state_dir / "terraform-work/baseline-output.json")
        def value(name):
            item=baseline.get(name)
            if not isinstance(item,dict) or item.get("sensitive") is not False: raise MirrorError("baseline output is unavailable")
            return item.get("value")
        repos=value("private_gitops_ecr_repository_urls"); relay=value("vault_audit_relay_ecr_repository_url")
        if not isinstance(repos,dict) or set(repos) < {"vault","vault_chart","cert_manager","cert_manager_chart"} or not isinstance(relay,str) or any(not isinstance(x,str) or not x.startswith(prefix) for x in [repos["vault"],repos["vault_chart"],repos["cert_manager"],repos["cert_manager_chart"],relay]): raise MirrorError("baseline does not bind all existing private destinations")
        marker=state_dir/"vault-artifact-mirror-uncertain.json"; manifest=state_dir/"vault-artifact-manifest.json"; receipt=state_dir/"vault-artifact-mirror-receipt.json"
    if not pre_eks and resume: raise MirrorError("automatic resume is limited to pre-EKS Vault mirroring")
    if pre_eks:
        outputs=(manifest,receipt,state_dir/"vault-pre-eks-artifact-mirror-binding.json",state_dir/"vault-pre-eks-artifact-mirror-verified.json")
        if any(path.is_symlink() for path in outputs) or marker.is_symlink(): raise MirrorError("mirror output already exists; reconcile instead of overwriting")
        if all(path.exists() for path in outputs):
            if not resume: raise MirrorError("mirror output already exists; reconcile instead of overwriting")
            lock=state_dir/".vault-pre-eks-artifact-mirror.lock"
            try: os.mkdir(lock,0o700)
            except FileExistsError as error: raise MirrorError("another pre-EKS Vault mirror operation holds the local lock") from error
            try:
                if not all(path.exists() and not path.is_symlink() for path in outputs): raise MirrorError("pre-EKS mirror outputs changed while awaiting lock")
                verify_pre_eks_vault_mirror(state_dir,bundle_root,discovery,profile,release_sha,inputs_dir,work_dir=prerequisite_work_dir)
                return manifest
            finally:
                try: lock.rmdir()
                except OSError: pass
        if any(path.exists() for path in outputs) and not resume: raise MirrorError("mirror output already exists; reconcile instead of overwriting")
    if not pre_eks:
        if marker.exists(): raise MirrorError("prior mirror outcome is uncertain; reconcile before retry")
        if manifest.exists() or receipt.exists(): raise MirrorError("mirror output already exists; reconcile instead of overwriting")
    image_names={"vault-bootstrap","vault-audit-relay","gitops-oci-mirror","vault-server","vault-injector","cert-manager-controller","cert-manager-webhook","cert-manager-cainjector","cert-manager-startupapicheck"}
    for component in image_names:
        item=index["components"][component]
        if not isinstance(item,dict) or not isinstance(item.get("image_ref"),str) or not DIGEST.fullmatch(item.get("manifest_digest","")) or not item["image_ref"].endswith("@"+item["manifest_digest"]):
            raise MirrorError("artifact index image component schema is invalid")
    chart_oci={}
    for component in ("vault-chart","cert-manager-chart"):
        item=index["components"][component]
        if not isinstance(item,dict) or not isinstance(item.get("approved_url"),str) or not item["approved_url"].startswith("https://") or not re.fullmatch(r"[a-f0-9]{64}",item.get("archive_sha256","")) or not DIGEST.fullmatch(item.get("expected_oci_manifest_digest","")) or not re.fullmatch(r"[A-Za-z0-9._-]+",item.get("tag","")):
            raise MirrorError("artifact index chart component schema is invalid")
        from installer_artifact_receipt import ReceiptError, validate_chart_version
        try:
            validate_chart_version(component, item.get("version"))
        except ReceiptError as error:
            raise MirrorError("artifact index chart component schema is invalid") from error
        chart_oci[component]=_chart_fixture(component,item)
    image_dest={"vault-bootstrap":repos["vault"],"vault-server":repos["vault"],"vault-injector":repos["vault"],"cert-manager-controller":repos["cert_manager"],"cert-manager-webhook":repos["cert_manager"],"cert-manager-cainjector":repos["cert_manager"],"cert-manager-startupapicheck":repos["cert_manager"],"vault-audit-relay":relay}
    image_plan={}
    for name,destination in image_dest.items():
        item=index["components"][name]; digest=item["manifest_digest"]; tag=item.get("tag",digest.removeprefix("sha256:"))
        if not isinstance(tag,str) or not re.fullmatch(r"[A-Za-z0-9._-]+",tag): raise MirrorError("image destination tag is invalid")
        image_plan[name]=(destination,tag)
    marker_value=None
    if pre_eks:
        marker_value={"schema_version":1,"status":"started","aws_account_id":account,"aws_region":region,"deployment_name":discovery["deployment_name"],"release_revision":release_sha,"index_sha256":hashlib.sha256(index_bytes).hexdigest(),"projection_sha256":hashlib.sha256(projection_bytes).hexdigest(),"input_fingerprint":projection["input_fingerprint"]}
        if marker.exists() or marker.is_symlink():
            if not resume or marker.is_symlink(): raise MirrorError("prior mirror outcome is uncertain; reconcile before retry")
            if _read(marker) != marker_value: raise MirrorError("prior pre-EKS mirror marker is not bound to this attempt")
        elif resume: raise MirrorError("no pre-EKS mirror marker is available to resume")
        expected_artifacts=_binding_artifacts(index,destinations)
        expected_receipt={"schema_version":1,"status":"verified","aws_account_id":account,"aws_region":region,"deployment_name":discovery["deployment_name"],"release_revision":release_sha,"index_sha256":hashlib.sha256(index_bytes).hexdigest(),"artifacts":expected_artifacts}
        expected_binding={"schema_version":1,"status":"verified","aws_account_id":account,"aws_region":region,"deployment_name":discovery["deployment_name"],"release_revision":release_sha,"index_sha256":expected_receipt["index_sha256"],"projection_sha256":hashlib.sha256(projection_bytes).hexdigest(),"input_fingerprint":projection["input_fingerprint"],"receipt_sha256":hashlib.sha256((json.dumps(expected_receipt,sort_keys=True)+"\n").encode()).hexdigest()}
        expected_consumer={"schema_version":1,"aws_account_id":account,"aws_region":region,"deployment_name":discovery["deployment_name"],"images":{"bootstrap":expected_artifacts["vault-bootstrap"]["image_ref"],"server":expected_artifacts["vault-server"]["image_ref"],"agent":expected_artifacts["vault-server"]["image_ref"],"injector":expected_artifacts["vault-injector"]["image_ref"],"audit_relay":expected_artifacts["vault-audit-relay"]["image_ref"]},"chart":{"version":index["components"]["vault-chart"]["version"],"digest":expected_artifacts["vault-chart"]["manifest_digest"]}}
        for path,value in ((manifest,expected_consumer),(receipt,expected_receipt),(state_dir/"vault-pre-eks-artifact-mirror-binding.json",expected_binding),(state_dir/"vault-pre-eks-artifact-mirror-verified.json",expected_binding)):
            if path.exists() and _read(path) != value: raise MirrorError("partial pre-EKS mirror output differs from this attempt")
    tool=index["components"]["gitops-oci-mirror"].get("image_ref",""); chart_tool=index["components"]["vault-bootstrap"].get("image_ref","")
    if not isinstance(tool,str) or not re.fullmatch(r"ghcr\.io/[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*/gitops-oci-mirror@sha256:[a-f0-9]{64}", tool) or not isinstance(chart_tool,str) or "@sha256:" not in chart_tool: raise MirrorError("pinned mirror tooling is invalid")
    lock=None
    if pre_eks:
        lock=state_dir/".vault-pre-eks-artifact-mirror.lock"
        try: os.mkdir(lock,0o700)
        except FileExistsError as error: raise MirrorError("another pre-EKS Vault mirror operation holds the local lock") from error
        try:
            if marker.exists() and _read(marker) != marker_value: raise MirrorError("pre-EKS mirror marker changed while awaiting lock")
        except Exception:
            try: lock.rmdir()
            except OSError: pass
            raise
    env=_mirror_env(profile, region)
    try:
     identity=subprocess.run(["aws","sts","get-caller-identity","--query","Account","--output","text"],check=True,capture_output=True,text=True,env=env,timeout=AWS_TIMEOUT)
     if identity.stdout.strip() != account: raise MirrorError("selected AWS profile is not the selected account")
    except Exception:
     if lock: lock.rmdir()
     raise
    try:
        tools = (tool, chart_tool) if layouts is None else (tool,)
        for image in tools:
            subprocess.run(["docker","pull",image],check=True,capture_output=True,text=True,env=env,timeout=DOCKER_TIMEOUT)
        for command in (["docker","image","inspect",image] for image in tools):
            subprocess.run(command,check=True,capture_output=True,text=True,env=env,timeout=AWS_TIMEOUT)
        work=Path(tempfile.mkdtemp(prefix=".vault-artifact-mirror-",dir=state_dir)); os.chmod(work,0o700)
        auth=work/"auth"; auth.mkdir(mode=0o700)
    except Exception:
        if lock: lock.rmdir()
        raise
    registry=f"{account}.dkr.ecr.{region}.amazonaws.com"
    try:
        password=subprocess.run(["aws","ecr","get-login-password","--region",region],check=True,capture_output=True,text=True,env=env,timeout=AWS_TIMEOUT).stdout
        from installer_registry_auth import RegistryAuthError, write_ecr_auth
        try:
            write_ecr_auth(auth, registry, password, set())
        except RegistryAuthError as error:
            raise MirrorError("could not create portable registry auth") from error
        # Every payload, destination and tool was checked before this point.
        if not marker.exists(): _write(marker, marker_value or {"schema_version":1,"status":"started","release_revision":index["release_revision"],"index_sha256":hashlib.sha256(index_path.read_bytes()).hexdigest()})
        verified={}
        for name,(destination,tag) in image_plan.items():
            item=index["components"][name]; source=item.get("image_ref"); digest=item.get("manifest_digest")
            got=_describe_digest(account,region,destination.split('/',1)[1],tag,digest,env,absent_ok=True) if pre_eks else None
            if got is None:
                mount = ["--volume", f"{layouts}:/payload:ro"] if layouts is not None else []
                transport = "oci:/payload/"+name+":root-"+digest[7:19] if layouts is not None else "docker://"+source
                subprocess.run(["docker","run","--rm","--env","REGISTRY_AUTH_FILE=/auth/config.json","--volume",f"{auth}:/auth:ro",*mount,tool,"copy","--all","--preserve-digests",transport,"docker://"+destination+":"+tag],check=True,env=env,timeout=DOCKER_TIMEOUT)
                got=_describe_digest(account,region,destination.split('/',1)[1],tag,digest,env)
            verified[name]={"image_ref":destination+"@"+got,"manifest_digest":got}
        for name,key in (("vault-chart","vault_chart"),("cert-manager-chart","cert_manager_chart")):
            item=index["components"][name]; url=item.get("approved_url"); sha=item.get("archive_sha256"); digest=item.get("expected_oci_manifest_digest"); tag=item.get("tag")
            if not isinstance(url,str) or not url.startswith("https://") or not re.fullmatch(r"[a-f0-9]{64}",sha or "") or not DIGEST.fullmatch(digest or ""): raise MirrorError("chart authority is invalid")
            chart_manifest_bytes,config,layers=chart_oci[name]; archive=work/(name+".tgz"); archives=[archive]
            command='set -eu; curl --fail --location --silent --show-error --output "$1" "$2"; printf "%s  %s\\n" "$3" "$1" | sha256sum --check --status'
            got=_describe_digest(account,region,repos[key].split('/',1)[1],tag,digest,env,absent_ok=True) if pre_eks else None
            if got is None and layouts is not None:
                subprocess.run(["docker","run","--rm","--env","REGISTRY_AUTH_FILE=/auth/config.json","--volume",f"{auth}:/auth:ro","--volume",f"{layouts}:/payload:ro",tool,"copy","--all","--preserve-digests","oci:/payload/"+name+":root-"+digest[7:19],"docker://"+repos[key]+":"+tag],check=True,env=env,timeout=DOCKER_TIMEOUT)
                got=_describe_digest(account,region,repos[key].split('/',1)[1],tag,digest,env)
            if got is None:
                subprocess.run(["docker","run","--rm","--volume",f"{work}:/work","--entrypoint","sh",chart_tool,"-c",command,"--","/work/"+archive.name,url,sha],check=True,env=env,timeout=DOCKER_TIMEOUT)
                if len(layers)==2:
                    provenance=work/(name+".tgz.prov"); provenance_sha=layers[1]["digest"].removeprefix("sha256:")
                    subprocess.run(["docker","run","--rm","--volume",f"{work}:/work","--entrypoint","sh",chart_tool,"-c",command,"--","/work/"+provenance.name,url+".prov",provenance_sha],check=True,env=env,timeout=DOCKER_TIMEOUT)
                    archives.append(provenance)
                layout,stage=_chart_layout(work,name,chart_manifest_bytes,config,layers,archives)
                repository=repos[key].split('/',1)[1]
                subprocess.run(["docker","run","--rm","--env","REGISTRY_AUTH_FILE=/auth/config.json","--volume",f"{auth}:/auth:ro","--volume",f"{work}:/work","--entrypoint","skopeo",tool,"copy","--all","--preserve-digests","oci:/work/oci/"+name+":"+stage,"docker://"+repos[key]+":"+stage],check=True,env=env,timeout=DOCKER_TIMEOUT)
                _staged_chart_manifest(account,region,repository,stage,chart_manifest_bytes,env)
                # Pinned skopeo has uploaded every hash-checked blob to this
                # same repository. ECR put-image attaches the final tag to the
                # exact manifest; it does not rebuild or repackage any layer.
                manifest_path=layout/"blobs/sha256"/hashlib.sha256(chart_manifest_bytes).hexdigest()
                subprocess.run(["aws","ecr","put-image","--registry-id",account,"--region",region,"--repository-name",repository,"--image-tag",tag,"--image-manifest","file://"+str(manifest_path),"--image-manifest-media-type",OCI_MANIFEST_MEDIA_TYPE,"--output","json"],check=True,capture_output=True,text=True,env=env,timeout=AWS_TIMEOUT)
                got=_describe_digest(account,region,repos[key].split('/',1)[1],tag,digest,env)
            verified[name]={"image_ref":repos[key]+"@"+got,"manifest_digest":got,"version":item["version"]}
        binding={"schema_version":1,"aws_account_id":account,"aws_region":region,"deployment_name":discovery["deployment_name"],"release_revision":index["release_revision"],"index_sha256":hashlib.sha256(index_path.read_bytes()).hexdigest(),"artifacts":verified}
        vault_chart=index["components"]["vault-chart"]
        consumer={"schema_version":1,"aws_account_id":account,"aws_region":region,"deployment_name":discovery["deployment_name"],
                  "images":{"bootstrap":verified["vault-bootstrap"]["image_ref"],"server":verified["vault-server"]["image_ref"],"agent":verified["vault-server"]["image_ref"],"injector":verified["vault-injector"]["image_ref"],"audit_relay":verified["vault-audit-relay"]["image_ref"]},
                  "chart":{"version":vault_chart["version"],"digest":verified["vault-chart"]["manifest_digest"]}}
        if pre_eks:
            if index_path.read_bytes()!=index_bytes or prerequisites_path.read_bytes()!=projection_bytes: raise MirrorError("pre-EKS artifact authority changed during mirror")
            canonical_receipt={**binding,"status":"verified"}
            pre_eks_binding={"schema_version":1,"status":"verified","aws_account_id":account,"aws_region":region,"deployment_name":discovery["deployment_name"],"release_revision":index["release_revision"],"index_sha256":canonical_receipt["index_sha256"],"projection_sha256":hashlib.sha256(prerequisites_path.read_bytes()).hexdigest(),"input_fingerprint":projection["input_fingerprint"],"receipt_sha256":hashlib.sha256((json.dumps(canonical_receipt,sort_keys=True)+"\n").encode()).hexdigest()}
            for path,value in ((manifest,consumer),(receipt,canonical_receipt),(state_dir/"vault-pre-eks-artifact-mirror-binding.json",pre_eks_binding),(state_dir/"vault-pre-eks-artifact-mirror-verified.json",pre_eks_binding)):
                if path.exists():
                    if _read(path) != value: raise MirrorError("partial pre-EKS mirror output differs from this attempt")
                else: _write(path,value)
        else:
            _write(manifest,consumer); _write(receipt,{**binding,"status":"verified"}); _write(state_dir/"vault-artifact-mirror-verified.json",{**binding,"status":"verified"})
        if pre_eks: marker.unlink()
        return manifest
    finally:
        shutil.rmtree(work,ignore_errors=True)
        if lock:
            try: lock.rmdir()
            except OSError: pass

def verify_pre_eks_vault_mirror(state_dir: Path, bundle_root: Path, discovery: dict, profile: str, release_sha: str, inputs_dir: Path | None = None, *, work_dir: Path | None = None, return_manifest: bool = False) -> dict:
    """Re-read the projection, binding, and all ten ECR digests without Docker."""
    from installer_artifact_prerequisites import load_projection, PrerequisiteError
    prerequisite_work_dir=_pre_eks_work_dir(state_dir,work_dir)
    projection_path=prerequisite_work_dir/"artifact-prerequisites.json"
    binding_path=state_dir/"vault-pre-eks-artifact-mirror-binding.json"; receipt_path=state_dir/"vault-artifact-mirror-receipt.json"
    effective_inputs=inputs_dir
    try:
        projection=load_projection(projection_path, work_dir=prerequisite_work_dir, bundle_root=bundle_root, discovery=discovery, inputs_dir=effective_inputs)
    except (PrerequisiteError, OSError, ValueError) as error: raise MirrorError("artifact prerequisite projection is unavailable or unsafe") from error
    index_path=bundle_root/"rendered/installer-artifact-index.json"; index=_read(index_path); index_bytes=index_path.read_bytes()
    if not SHA.fullmatch(release_sha) or index.get("release_revision") != release_sha: raise MirrorError("selected release index is invalid")
    _strict_pre_eks_index(index,index_bytes)
    binding=_read(binding_path); receipt=_read(receipt_path); destinations=_pre_eks_destinations(projection,discovery); artifacts=_binding_artifacts(index,destinations)
    expected_receipt={"schema_version":1,"status":"verified","aws_account_id":discovery["aws_account_id"],"aws_region":discovery["aws_region"],"deployment_name":discovery["deployment_name"],"release_revision":release_sha,"index_sha256":hashlib.sha256(index_bytes).hexdigest(),"artifacts":artifacts}
    expected={"schema_version":1,"status":"verified","aws_account_id":discovery["aws_account_id"],"aws_region":discovery["aws_region"],"deployment_name":discovery["deployment_name"],"release_revision":release_sha,"index_sha256":expected_receipt["index_sha256"],"projection_sha256":hashlib.sha256(projection_path.read_bytes()).hexdigest(),"input_fingerprint":projection["input_fingerprint"],"receipt_sha256":hashlib.sha256((json.dumps(expected_receipt,sort_keys=True)+"\n").encode()).hexdigest()}
    if receipt != expected_receipt or binding != expected: raise MirrorError("pre-EKS Vault mirror binding is invalid")
    vault_chart=index["components"]["vault-chart"]
    expected_manifest={"schema_version":1,"aws_account_id":discovery["aws_account_id"],"aws_region":discovery["aws_region"],"deployment_name":discovery["deployment_name"],"images":{"bootstrap":artifacts["vault-bootstrap"]["image_ref"],"server":artifacts["vault-server"]["image_ref"],"agent":artifacts["vault-server"]["image_ref"],"injector":artifacts["vault-injector"]["image_ref"],"audit_relay":artifacts["vault-audit-relay"]["image_ref"]},"chart":{"version":vault_chart["version"],"digest":artifacts["vault-chart"]["manifest_digest"]}}
    if _read(state_dir/"vault-artifact-manifest.json") != expected_manifest or _read(state_dir/"vault-pre-eks-artifact-mirror-verified.json") != expected:
        raise MirrorError("pre-EKS Vault mirror outputs are invalid")
    env=_mirror_env(profile,discovery["aws_region"])
    identity=subprocess.run(["aws","sts","get-caller-identity","--query","Account","--output","text"],check=True,capture_output=True,text=True,env=env,timeout=AWS_TIMEOUT)
    if identity.stdout.strip() != discovery["aws_account_id"]: raise MirrorError("selected AWS profile is not the selected account")
    for name,destination in destinations.items():
        item=index["components"][name]; digest=artifacts[name]["manifest_digest"]
        tag=item.get("tag",digest.removeprefix("sha256:"))
        _describe_digest(discovery["aws_account_id"],discovery["aws_region"],destination.split('/',1)[1],tag,digest,env)
    return {"binding":binding,"manifest":expected_manifest} if return_manifest else binding

_mirror_impl = mirror
def mirror(state_dir: Path, bundle_root: Path, discovery: dict, profile: str, release_sha: str, *, prerequisites_path: Path | None = None, inputs_dir: Path | None = None, work_dir: Path | None = None, resume: bool = False, payload_dir: Path | None = None, authenticated_bundle_manifest_sha256: str | None = None) -> Path:
    from installer_oci_binding import payload_context
    try:
        with payload_context(bundle_root, release_sha, discovery, state_dir, payload_dir, authenticated_bundle_manifest_sha256) as layouts:
            return _mirror_impl(state_dir, bundle_root, discovery, profile, release_sha,
                prerequisites_path=prerequisites_path, inputs_dir=inputs_dir, work_dir=work_dir,
                resume=resume, layouts=layouts)
    except subprocess.CalledProcessError as error:
        raise MirrorError("artifact mirror command failed; the outcome requires reconciliation") from error
