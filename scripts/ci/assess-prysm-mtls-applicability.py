#!/usr/bin/env python3
"""Fail-closed, exact Prysm non-applicability assessment for GO-2026-5932."""
import hashlib, importlib.util, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("summary", ROOT / "scripts/ci/summarize-vault-runtime-scan.py")
summary = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(summary)
ADVISORY = "GO-2026-5932"; MODULE = ("golang.org/x/crypto", "v0.56.0"); PREFIX = "golang.org/x/crypto/openpgp"
SHA = re.compile(r"^[a-f0-9]{64}$"); DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
def bad(message): raise ValueError(message)
def load(path):
    try:
        if path.is_symlink() or not path.is_file(): bad("missing or unsafe evidence " + path.name)
        def unique(pairs):
            out={}
            for key,value in pairs:
                if key in out: bad("duplicate JSON key")
                out[key]=value
            return out
        return json.loads(path.read_text(), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError): bad("invalid JSON " + path.name)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def utc(value):
    if not isinstance(value,str) or not value.endswith("Z"): bad("invalid review time")
    try: return datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError: bad("invalid review time")
def exact_advisory(manifest, pinned, current, now):
    if set(manifest) != {"schema_version","advisory_id","advisory_url","affected_package_prefix","reviewed_at","expires_at"} or manifest.get("schema_version") != "v1" or manifest.get("advisory_id") != ADVISORY or manifest.get("advisory_url") != "https://pkg.go.dev/vuln/GO-2026-5932" or manifest.get("affected_package_prefix") != PREFIX: bad("unexpected advisory manifest")
    reviewed, expires = utc(manifest["reviewed_at"]), utc(manifest["expires_at"])
    if reviewed > now or expires <= now or expires <= reviewed or expires-reviewed > __import__('datetime').timedelta(days=7): bad("review is expired, future, or exceeds seven days")
    if current != pinned or pinned.get("id") != ADVISORY: bad("current advisory differs")
    affected = pinned.get("affected")
    if not isinstance(affected,list) or not affected: bad("malformed advisory")
    for item in affected:
        if not isinstance(item,dict) or item.get("package",{}).get("name") != MODULE[0]: bad("unexpected advisory module")
        imports=item.get("ecosystem_specific",{}).get("imports")
        if not isinstance(imports,list) or not imports: bad("malformed advisory scope")
        for imported in imports:
            path=imported.get("path") if isinstance(imported,dict) else None
            if not isinstance(path,str) or not (path==PREFIX or path.startswith(PREFIX+"/")): bad("advisory affects other package")
def assess(evidence, *, root=ROOT, now=None):
    evidence=Path(evidence); root=Path(root); now=now or datetime.now(timezone.utc)
    if now.tzinfo is None: bad("timezone-aware clock required")
    manifest=load(root/".ci/prysm-mtls-applicability.json"); pin=root/".ci/prysm-mtls-applicability"/(ADVISORY+".json")
    pinned=load(pin); current_path=evidence/"advisory-current.json"; current=load(current_path); exact_advisory(manifest,pinned,current,now.astimezone(timezone.utc))
    # Git text files may end with one newline; the official JSON endpoint does
    # not. All other bytes and all parsed advisory fields must still match.
    if current_path.read_bytes().removesuffix(b"\n") != pin.read_bytes().removesuffix(b"\n"): bad("current advisory bytes differ")
    required=("sbom.json","grype.json","runtime-identity.json","binary.sha256","dependencies.txt","advisory-current.json")
    if any(not (evidence/x).is_file() or (evidence/x).is_symlink() for x in required): bad("required evidence missing")
    sbom_path=evidence/"sbom.json"; raw_path=evidence/"grype.json"; sbom=sbom_path.read_bytes(); raw=load(raw_path)
    identity=load(evidence/"runtime-identity.json"); subject=identity.get("subject")
    if not isinstance(subject,str) or not re.fullmatch(r"[a-z0-9][a-z0-9./_-]*@sha256:[a-f0-9]{64}",subject): bad("invalid image subject")
    digest=subject.rsplit("@",1)[1]
    if identity.get("Os")!="linux" or identity.get("Architecture")!="amd64" or identity.get("user") != "1000:1000" or identity.get("entrypoint") != ["/validator"] or identity.get("RepoDigests") != [subject]: bad("runtime identity differs")
    if not isinstance(load(sbom_path).get("metadata",{}).get("component",{}).get("version"),str) or load(sbom_path)["metadata"]["component"]["version"] != digest: bad("SBOM does not bind image")
    if raw.get("source",{}).get("target",{}).get("manifestDigest") != digest: bad("raw scan does not bind image")
    if raw.get("ignoredMatches") not in ([],None) or raw.get("descriptor",{}).get("name") != "grype" or not raw.get("descriptor",{}).get("db",{}).get("status",{}).get("valid"): bad("scanner evidence is unsafe")
    matches=raw.get("matches");
    if not isinstance(matches,list): bad("malformed matches")
    sev=lambda m: str(m.get("vulnerability",{}).get("severity","")).lower()
    if any(sev(m) in ("critical","high") for m in matches): bad("critical or high raw finding")
    unknown=[m for m in matches if sev(m)=="unknown"]
    if len(unknown)!=1: bad("exactly one unknown required")
    m=unknown[0]
    if m.get("vulnerability",{}).get("id")!=ADVISORY or (m.get("artifact",{}).get("name"),m.get("artifact",{}).get("version"))!=MODULE: bad("unknown is not approved advisory")
    if any(sev(m) not in ("critical","high","medium","low","unknown") for m in matches): bad("nonstandard severity")
    binary=(evidence/"binary.sha256").read_text()
    if not re.fullmatch(r"[a-f0-9]{64}  /validator\n",binary): bad("invalid validator hash")
    deps=(evidence/"dependencies.txt").read_bytes()
    lines=deps.splitlines()
    package=re.compile(rb"^[A-Za-z0-9._~+/-]+$")
    if not deps or not deps.endswith(b"\n") or b"github.com/OffchainLabs/prysm/v7/cmd/validator" not in lines or any(not x or not package.fullmatch(x) or x == PREFIX.encode() or x.startswith((PREFIX+"/").encode()) for x in lines): bad("unsafe or affected dependency closure")
    raw_summary=summary.summarize(sbom,raw,digest)
    if raw_summary.get("status") != "blocked" or raw_summary.get("findings",{}).get("unknown") != 1: bad("raw scan must remain blocked")
    return {"schema_version":"v2","component":"prysm-mtls","status":"passed-with-non-applicability","raw_scan_status":"blocked","applicability":"not_affected","advisory_id":ADVISORY,"subject":subject,"sbom_sha256":sha(sbom_path),"raw_grype_sha256":sha(raw_path),"raw_scan_summary":raw_summary,"advisory_sha256":sha(pin),"reviewed_at":manifest["reviewed_at"],"expires_at":manifest["expires_at"],"validator_sha256":binary[:64],"dependency_closure_sha256":hashlib.sha256(deps).hexdigest(),"dependency_closure_count":len(deps.splitlines()),"deployment_authorized":False}
def main(argv):
    if len(argv) not in (1,3): bad("usage: assessor EVIDENCE [--verify ASSESSMENT]")
    result=assess(argv[0])
    if len(argv)==3:
        observed=load(Path(argv[2]))
        if isinstance(observed,dict) and isinstance(observed.get("raw_scan_summary"),dict): observed["raw_scan_summary"].pop("scanned_at",None)
        if isinstance(result.get("raw_scan_summary"),dict): result["raw_scan_summary"].pop("scanned_at",None)
        if argv[1]!="--verify" or observed != result: bad("assessment does not reverify current evidence")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    try: main(sys.argv[1:])
    except (ValueError,OSError,KeyError,TypeError,AttributeError) as e: print("assessment blocked: "+str(e),file=sys.stderr); sys.exit(1)
