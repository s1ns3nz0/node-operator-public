#!/usr/bin/env python3
"""Produce or reverify the narrowly approved Kyverno residual-risk decision."""
from __future__ import annotations
import hashlib, json, re, stat, sys
from datetime import datetime, timezone
from pathlib import Path

SHA256=re.compile(r"^[a-f0-9]{64}$"); DIGEST=re.compile(r"^sha256:[a-f0-9]{64}$")
POLICY=".ci/kyverno-cli/risk-acceptance.json"
EXPECTED_KEYS={"schema_version","component","decision","decision_record","scope","source_commit","reviewed_build_inputs_sha256","expires_at","accepted_findings","required_counts"}

def fail(message): raise ValueError(message)
def load(path):
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 4*1024*1024: fail("unsafe JSON input")
    def pairs(items):
        value={}
        for key,item in items:
            if key in value: fail("duplicate JSON key")
            value[key]=item
        return value
    return json.loads(path.read_text(),object_pairs_hook=pairs)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def policy(root):
    value=load(root/POLICY)
    if not isinstance(value,dict) or set(value)!=EXPECTED_KEYS or value.get("schema_version")!="v1" or value.get("component")!="kyverno-cli" or value.get("decision")!="accepted-residual-risk" or value.get("decision_record")!="docs/decisions/2026-09-15-kyverno-cli-risk-acceptance.md" or value.get("scope")!="main-publisher-migration-build-only" or not re.fullmatch(r"[a-f0-9]{40}",str(value.get("source_commit"))) or not SHA256.fullmatch(str(value.get("reviewed_build_inputs_sha256"))): fail("risk policy identity is invalid")
    try: expiry=datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"))
    except (TypeError,ValueError): fail("risk policy expiry is invalid")
    if expiry.tzinfo is None or datetime.now(timezone.utc)>=expiry: fail("risk acceptance has expired")
    findings=value.get("accepted_findings")
    if not isinstance(findings,list) or len(findings)!=2 or findings != [{"id":"GO-2026-6225","package":"github.com/chrismellard/docker-credential-acr-env","version":"v0.0.0-20230304212654-82a0ddb27589"},{"id":"GO-2026-5932","package":"golang.org/x/crypto","version":"v0.56.0"}]: fail("accepted findings are not exact")
    if value.get("required_counts")!={"critical":0,"high":0,"unknown":2}: fail("risk policy counts are invalid")
    return value
def assess(root,evidence,input_sha):
    p=policy(root); lock=load(root/".ci/kyverno-cli/source-lock.json")
    if lock.get("source",{}).get("commit") != p["source_commit"]: fail("source commit differs from accepted build")
    h=hashlib.sha256()
    for relative in (".ci/kyverno-cli/Dockerfile", ".ci/kyverno-cli/source-lock.json", ".ci/kyverno-cli/scripts/update-etcd.sh"): h.update(relative.encode()+b"\0"+hashlib.sha256((root/relative).read_bytes()).digest())
    if h.hexdigest()!=p["reviewed_build_inputs_sha256"]: fail("reviewed build inputs differ from accepted build")
    if not SHA256.fullmatch(input_sha): fail("build input hash is invalid")
    bound=hashlib.sha256()
    for relative in (".ci/kyverno-cli/Dockerfile", ".ci/kyverno-cli/source-lock.json", ".ci/kyverno-cli/scripts/update-etcd.sh", ".ci/kyverno-cli/risk-acceptance.json", "scripts/ci/assess-kyverno-cli-risk-acceptance.py"):
        bound.update(relative.encode()+b"\0"+hashlib.sha256((root/relative).read_bytes()).digest())
    if input_sha != bound.hexdigest(): fail("input hash does not bind reviewed acceptance inputs")
    sbom=evidence/"sbom.json"; raw=evidence/"grype.json"
    s=load(sbom); g=load(raw)
    digest=s.get("metadata",{}).get("component",{}).get("version")
    if s.get("bomFormat")!="CycloneDX" or not isinstance(digest,str) or not DIGEST.fullmatch(digest): fail("SBOM does not bind a digest")
    if g.get("source",{}).get("target",{}).get("manifestDigest") != digest: fail("raw Grype scan does not bind SBOM digest")
    d=g.get("descriptor",{}); db=d.get("db",{}).get("status",{}); cfg=d.get("configuration",{})
    if d.get("name")!="grype" or d.get("version")!="0.118.0" or db.get("valid") is not True or not db.get("built") or cfg.get("exclude")!=[] or cfg.get("only-fixed") is not False or cfg.get("only-notfixed") is not False or g.get("ignoredMatches") not in (None,[]): fail("raw Grype scan is filtered or invalid")
    matches=g.get("matches")
    if not isinstance(matches,list): fail("raw Grype matches are invalid")
    counts={k:0 for k in ("critical","high","medium","low","unknown")}; observed=[]
    for match in matches:
        v=match.get("vulnerability",{}); a=match.get("artifact",{}); severity=v.get("severity")
        if not isinstance(severity,str) or not severity: fail("finding severity is invalid")
        severity=severity.lower(); counts[severity if severity in counts else "unknown"]+=1
        if severity in ("critical","high","unknown"): observed.append({"id":v.get("id"),"package":a.get("name"),"version":a.get("version"),"severity":severity})
    expected=[dict(item,severity="unknown") for item in p["accepted_findings"]]
    if counts["critical"]!=0 or counts["high"]!=0 or counts["unknown"]!=2 or sorted(observed,key=lambda x:x["id"] or "") != sorted(expected,key=lambda x:x["id"]): fail("raw Grype findings exceed or differ from accepted residual risk")
    summary=load(evidence/"scan.json")
    if summary.get("artifact_digest")!=digest or summary.get("sbom_sha256")!=sha(sbom) or summary.get("status")!="blocked" or summary.get("findings")!=counts: fail("scan summary differs from raw findings or subject")
    return {"schema_version":"v1","component":"kyverno-cli","decision":"accepted-residual-risk","status":"accepted-with-residual-risk","scope":p["scope"],"subject":digest,"source_commit":p["source_commit"],"input_sha256":input_sha,"policy_sha256":sha(root/POLICY),"reviewed_build_inputs_sha256":p["reviewed_build_inputs_sha256"],"sbom_sha256":sha(sbom),"raw_grype_sha256":sha(raw),"raw_scan_summary":{"findings":counts,"status":"blocked"},"accepted_findings":p["accepted_findings"],"expires_at":p["expires_at"]}
def main(args):
    if len(args) not in (3,5): fail("usage: ASSESSOR ROOT EVIDENCE INPUT_SHA256 [--verify DECISION]")
    root=Path(args[0]).resolve(); result=assess(root,Path(args[1]),args[2])
    if len(args)==5:
        if args[3]!="--verify" or load(Path(args[4]))!=result: fail("risk decision does not reverify current evidence")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    try: main(sys.argv[1:])
    except (OSError,TypeError,KeyError,ValueError,json.JSONDecodeError) as error: print("risk acceptance blocked: "+str(error),file=sys.stderr); sys.exit(1)
