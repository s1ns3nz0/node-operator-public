#!/usr/bin/env python3
"""Local consistency validation for a release-bound GitOps client-chart record.

Callers must authenticate the release bundle and independently retrieve the
exact trusted GitHub run/artifact named by the authorization.  This parser does
not verify DSSE signatures, contact GitHub/ECR, mirror a chart, or activate it.
"""
from __future__ import annotations
import base64, binascii, hashlib, json, re, stat
from pathlib import Path
from typing import Any

SHA40=re.compile(r"^[0-9a-f]{40}$"); SHA256=re.compile(r"^[0-9a-f]{64}$"); DIGEST=re.compile(r"^sha256:[0-9a-f]{64}$"); RUN=re.compile(r"^[1-9][0-9]*$")
AUTH_PATH="source/release/client-chart-publication-authorization.json"; RECORD_DIR="rendered/client-chart-publication-records"
NAMES=("gitops-chart-subject.json","gitops-chart-sbom.json","gitops-chart-grype.json","gitops-chart-provenance-predicate.json","gitops-chart-provenance-verified.json")
REPOSITORY="s1ns3nz0/node-operator-gitops"; WORKFLOW="publish-oci.yml"; BUILDER="https://github.com/s1ns3nz0/node-operator-gitops/.github/workflows/publish-oci.yml@refs/heads/main"
DEPLOYMENT=r"[a-z][a-z0-9-]{1,18}[a-z0-9]"
IMAGE_RE=re.compile(rf"^123456789012\.dkr\.ecr\.ap-northeast-2\.amazonaws\.com/{DEPLOYMENT}-baseline-gitops-client/node-operator-client@sha256:[0-9a-f]{{64}}$")
MAX=4*1024*1024
class ClientChartAuthorizationError(ValueError): pass
def _dups(items:list[tuple[str,Any]])->dict[str,Any]:
 out={}
 for k,v in items:
  if k in out: raise ClientChartAuthorizationError("duplicate JSON key")
  out[k]=v
 return out
def _read(path:Path)->tuple[Any,bytes]:
 try:
  s=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_size>MAX: raise ClientChartAuthorizationError("unsafe JSON input")
  raw=path.read_bytes(); return json.loads(raw.decode(),object_pairs_hook=_dups),raw
 except (OSError,UnicodeDecodeError,json.JSONDecodeError) as e: raise ClientChartAuthorizationError("invalid JSON input") from e
def _obj(v:Any, keys:set[str], label:str)->dict[str,Any]:
 if not isinstance(v,dict) or set(v)!=keys: raise ClientChartAuthorizationError(label+" schema is invalid")
 return v
def _str(v:Any, pat:re.Pattern[str], label:str)->str:
 if not isinstance(v,str) or not pat.fullmatch(v): raise ClientChartAuthorizationError(label+" is invalid")
 return v
def _canonical(v:Any)->bytes:return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _manifest(v:Any, release:str)->dict[str,str]:
 v=_obj(v,{"schema_version","artifact","source_revision","entries"},"manifest")
 if v["schema_version"]!="v1" or v["source_revision"]!=release or not isinstance(v["entries"],list):raise ClientChartAuthorizationError("manifest release is invalid")
 out={}
 for e in v["entries"]:
  e=_obj(e,{"path","sha256","size"},"manifest entry")
  if not isinstance(e["path"],str) or e["path"] in out or type(e["size"]) is not int or e["size"]<0:raise ClientChartAuthorizationError("manifest entry invalid")
  out[e["path"]]=_str(e["sha256"],SHA256,"manifest hash")
 return out
def _severity(item:Any)->str:
 if isinstance(item,dict) and isinstance(item.get("match"),dict):item=item["match"]
 if not isinstance(item,dict) or not isinstance(item.get("vulnerability"),dict) or not isinstance(item["vulnerability"].get("severity"),str):raise ClientChartAuthorizationError("Grype match is invalid")
 severity=item["vulnerability"]["severity"].lower()
 if severity not in {"critical","high","medium","low","negligible","unknown"}:raise ClientChartAuthorizationError("Grype severity is invalid")
 return severity
def _evidence(values:dict[str,Any], target:dict[str,Any], revision:str)->None:
 subject=_obj(values[NAMES[0]],{"schema_version","oci_digest","chart_archive_digest","chart_version"},"chart subject")
 if subject["schema_version"]!="v1" or _str(subject["oci_digest"],DIGEST,"subject digest")!=target["manifest_digest"] or _str(subject["chart_archive_digest"],DIGEST,"archive digest")!=target["chart_archive_digest"] or subject["chart_version"]!=target["chart_version"]:raise ClientChartAuthorizationError("chart subject differs from target")
 sbom=values[NAMES[1]]
 if not isinstance(sbom,dict) or not isinstance(sbom.get("metadata"),dict):raise ClientChartAuthorizationError("chart SBOM is invalid")
 meta=sbom["metadata"]; component=meta.get("component"); tools=meta.get("tools")
 if sbom.get("bomFormat")!="CycloneDX" or not isinstance(component,dict) or component.get("name")!=f"node-operator-client-{target['chart_version']}.tgz" or component.get("version")!=target["chart_archive_digest"] or not isinstance(tools,dict) or not isinstance(tools.get("components"),list) or not any(isinstance(x,dict) and x.get("name")=="syft" for x in tools["components"]):raise ClientChartAuthorizationError("chart SBOM is invalid")
 scan=values[NAMES[2]]
 if not isinstance(scan,dict) or not isinstance(scan.get("descriptor"),dict) or not isinstance(scan.get("source"),dict):raise ClientChartAuthorizationError("Grype scan is invalid")
 desc=scan["descriptor"]; db=desc.get("db"); conf=desc.get("configuration"); source=scan["source"]
 if not isinstance(db,dict) or not isinstance(db.get("status"),dict) or not isinstance(conf,dict):raise ClientChartAuthorizationError("Grype scan is invalid")
 status=db["status"]
 ignored=scan.get("ignoredMatches",[])
 if desc.get("name")!="grype" or not isinstance(desc.get("version"),str) or not desc["version"] or status.get("valid") is not True or not isinstance(conf.get("ignore"),list) or conf.get("exclude")!=[] or conf.get("only-fixed") is not False or conf.get("only-notfixed") is not False or conf.get("show-suppressed") is not True or source.get("type")!="file" or source.get("target")!=f"node-operator-client-{target['chart_version']}.tgz" or not isinstance(scan.get("matches"),list) or not isinstance(ignored,list):raise ClientChartAuthorizationError("Grype scan is invalid")
 if any(_severity(x) in {"critical","high","unknown"} for x in scan["matches"]+ignored):raise ClientChartAuthorizationError("Grype scan contains blocked severity")
 predicate=values[NAMES[3]]; verified=_obj(values[NAMES[4]],{"payloadType","payload","signatures"},"DSSE verification")
 if verified["payloadType"] not in {"application/vnd.in-toto+json","application/vnd.in-toto+json;v=0.1"} or not isinstance(verified["payload"],str) or not isinstance(verified["signatures"],list) or not verified["signatures"]:raise ClientChartAuthorizationError("DSSE verification is invalid")
 try: statement=json.loads(base64.b64decode(verified["payload"],validate=True).decode(),object_pairs_hook=_dups)
 except (binascii.Error,UnicodeDecodeError,json.JSONDecodeError) as e:raise ClientChartAuthorizationError("DSSE payload is invalid") from e
 statement=_obj(statement,{"_type","subject","predicateType","predicate"},"in-toto statement")
 if statement["_type"] not in {"https://in-toto.io/Statement/v0.1","https://in-toto.io/Statement/v1"} or statement["predicateType"]!="https://slsa.dev/provenance/v1" or not isinstance(statement["subject"],list) or len(statement["subject"])!=1 or _canonical(statement["predicate"])!=_canonical(predicate):raise ClientChartAuthorizationError("provenance statement is invalid")
 sub=_obj(statement["subject"][0],{"name","digest"},"provenance subject"); dig=_obj(sub["digest"],{"sha256"},"provenance digest")
 if sub["name"]!=target["image_ref"].rsplit("@",1)[0] or dig["sha256"]!=target["manifest_digest"].split(":",1)[1]:raise ClientChartAuthorizationError("provenance subject is invalid")
 if not isinstance(predicate,dict) or not isinstance(predicate.get("buildDefinition"),dict) or not isinstance(predicate.get("runDetails"),dict):raise ClientChartAuthorizationError("provenance source is invalid")
 build=predicate["buildDefinition"]; run=predicate["runDetails"]
 if build.get("buildType")!="https://node-operator.example/gitops-chart/v1" or build.get("resolvedDependencies")!=[{"uri":"git+https://github.com/s1ns3nz0/node-operator-gitops","digest":{"gitCommit":revision}}] or not isinstance(run.get("builder"),dict) or run["builder"].get("id")!=BUILDER:raise ClientChartAuthorizationError("provenance source is invalid")
def validate_authorization(auth:Any,required_use:str="stage")->dict[str,Any]:
 if required_use not in {"stage","activation"}:raise ClientChartAuthorizationError("required use is invalid")
 auth=_obj(auth,{"schema_version","source_revision","publication","target","evidence_sha256","approvals"},"chart authorization")
 publication=_obj(auth["publication"],{"repository","workflow","run_id","artifact_id","artifact_name","run_number"},"publication"); target=_obj(auth["target"],{"image_ref","manifest_digest","chart_archive_digest","chart_version"},"target"); hashes=_obj(auth["evidence_sha256"],set(NAMES),"evidence hashes"); approvals=_obj(auth["approvals"],{"stage_approved","activation_approved"},"approvals")
 revision=_str(auth["source_revision"],SHA40,"source revision"); _str(target["chart_archive_digest"],DIGEST,"archive digest")
 if type(auth["schema_version"]) is not int or auth["schema_version"]!=1 or publication["repository"]!=REPOSITORY or publication["workflow"]!=WORKFLOW or not isinstance(publication["artifact_name"],str) or not re.fullmatch(r"gitops-chart-evidence-[A-Za-z0-9_.-]+",publication["artifact_name"]) or any(not isinstance(publication[x],str) or not RUN.fullmatch(publication[x]) for x in ("run_id","artifact_id","run_number")) or not isinstance(target["image_ref"],str) or not IMAGE_RE.fullmatch(target["image_ref"]) or _str(target["manifest_digest"],DIGEST,"manifest digest")!=target["image_ref"].rsplit("@",1)[1] or target["chart_version"]!="0.1."+publication["run_number"] or any(_str(hashes[n],SHA256,"evidence hash") is None for n in NAMES) or any(type(x)is not bool for x in approvals.values()) or approvals["stage_approved"] is not True or (required_use=="activation" and approvals["activation_approved"] is not True):raise ClientChartAuthorizationError("chart authorization is invalid")
 return {"source_revision":revision,"publication":publication,"target":target,"evidence_sha256":hashes,"required_use":required_use}
def validate_candidate_authorization(auth:Any,evidence:dict[str,bytes],required_use:str="stage")->dict[str,Any]:
 if required_use not in {"stage","activation"} or not isinstance(evidence,dict) or set(evidence)!=set(NAMES):raise ClientChartAuthorizationError("authorization inputs are invalid")
 parsed={}
 for n,raw in evidence.items():
  if not isinstance(raw,bytes) or len(raw)>MAX:raise ClientChartAuthorizationError("evidence bytes are invalid")
  try:parsed[n]=json.loads(raw.decode(),object_pairs_hook=_dups)
  except (UnicodeDecodeError,json.JSONDecodeError) as e:raise ClientChartAuthorizationError("evidence JSON is invalid") from e
 validated=validate_authorization(auth,required_use); revision=validated["source_revision"]; publication=validated["publication"]; target=validated["target"]; hashes=validated["evidence_sha256"]
 if any(hashes[n]!=hashlib.sha256(evidence[n]).hexdigest() for n in NAMES):raise ClientChartAuthorizationError("chart evidence hash is invalid")
 _evidence(parsed,target,revision); return {"source_revision":revision,"publication":publication,"target":target,"evidence":parsed,"required_use":required_use}
def validate_release_authorization(bundle_root:Path,release_revision:str,required_use:str)->dict[str,Any]:
 if not bundle_root.is_absolute() or bundle_root.is_symlink() or not bundle_root.is_dir() or not SHA40.fullmatch(release_revision):raise ClientChartAuthorizationError("bundle arguments are invalid")
 source=bundle_root/'source'; release=source/'release'; rendered=bundle_root/'rendered'; records=rendered/'client-chart-publication-records'
 for directory in (source,release,rendered,records):
  try:s=directory.lstat()
  except OSError as e:raise ClientChartAuthorizationError("bundle layout is invalid") from e
  if directory.is_symlink() or not stat.S_ISDIR(s.st_mode):raise ClientChartAuthorizationError("bundle layout is unsafe")
 try: members={item.name for item in records.iterdir()}
 except OSError as e:raise ClientChartAuthorizationError("chart evidence directory is invalid") from e
 if members!=set(NAMES):raise ClientChartAuthorizationError("chart evidence directory is incomplete or has extra files")
 manifest, _=_read(bundle_root/"bundle-manifest.json"); entries=_manifest(manifest,release_revision); auth,raw=_read(bundle_root/AUTH_PATH); evidence={}
 for n in NAMES:
  _,data=_read(bundle_root/RECORD_DIR/n); evidence[n]=data
 if entries.get(AUTH_PATH)!=hashlib.sha256(raw).hexdigest() or any(entries.get(f"{RECORD_DIR}/{n}")!=hashlib.sha256(evidence[n]).hexdigest() for n in NAMES):raise ClientChartAuthorizationError("manifest does not bind chart evidence")
 return {"release_revision":release_revision,**validate_candidate_authorization(auth,evidence,required_use)}
