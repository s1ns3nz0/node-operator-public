#!/usr/bin/env python3
"""Synthetic boundary tests for the Prysm-only applicability exception."""
import copy, hashlib, importlib.util, json, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
SCRIPT=Path(__file__).with_name("assess-prysm-mtls-applicability.py")
spec=importlib.util.spec_from_file_location("assessor",SCRIPT); a=importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
D="sha256:"+"a"*64; S="registry.test/prysm@"+D
class Tests(unittest.TestCase):
 def fixture(self):
  t=tempfile.TemporaryDirectory(); r=Path(t.name); e=r/"e"; e.mkdir(); (r/".ci/prysm-mtls-applicability").mkdir(parents=True)
  m={"schema_version":"v1","advisory_id":a.ADVISORY,"advisory_url":"https://pkg.go.dev/vuln/GO-2026-5932","affected_package_prefix":a.PREFIX,"reviewed_at":"2026-09-14T00:00:00Z","expires_at":"2026-09-21T00:00:00Z"}
  ad={"id":a.ADVISORY,"affected":[{"package":{"name":"golang.org/x/crypto"},"ecosystem_specific":{"imports":[{"path":a.PREFIX}]}}]}
  (r/".ci/prysm-mtls-applicability.json").write_text(json.dumps(m)); (r/".ci/prysm-mtls-applicability"/(a.ADVISORY+".json")).write_text(json.dumps(ad)); (e/"advisory-current.json").write_text(json.dumps(ad))
  (e/"sbom.json").write_text(json.dumps({"bomFormat":"CycloneDX","metadata":{"component":{"version":D}},"components":[{}]}))
  raw={"matches":[{"vulnerability":{"id":a.ADVISORY,"severity":"Unknown"},"artifact":{"name":"golang.org/x/crypto","version":"v0.56.0"}}],"ignoredMatches":[],"descriptor":{"name":"grype","version":"x","db":{"status":{"valid":True,"built":"2026","schemaVersion":1}},"configuration":{"exclude":[],"only-fixed":False,"only-notfixed":False,"show-suppressed":True}},"source":{"target":{"manifestDigest":D}}}
  (e/"grype.json").write_text(json.dumps(raw)); (e/"runtime-identity.json").write_text(json.dumps({"subject":S,"RepoDigests":[S],"Os":"linux","Architecture":"amd64","user":"1000:1000","entrypoint":["/validator"]})); (e/"binary.sha256").write_text("b"*64+"  /validator\n"); (e/"dependencies.txt").write_bytes(b"github.com/OffchainLabs/prysm/v7/cmd/validator\ngithub.com/x/y\n")
  return t,r,e
 def assess(self,r,e): return a.assess(e,root=r,now=datetime(2026,9,15,tzinfo=timezone.utc))
 def test_exact_unknown_is_explicitly_not_clean(self):
  t,r,e=self.fixture()
  with t:
   x=self.assess(r,e); self.assertEqual(x["raw_scan_status"],"blocked"); self.assertEqual(x["applicability"],"not_affected"); self.assertFalse(x["deployment_authorized"])
 def test_official_complete_pin_and_terminal_newline(self):
  pin=SCRIPT.parents[2]/".ci/prysm-mtls-applicability/GO-2026-5932.json"
  official=json.loads(pin.read_text())
  self.assertTrue(official["details"].startswith("The golang.org/x/crypto/openpgp package"))
  self.assertIn({"type":"REPORT","url":"https://go.dev/issue/44226"},official["references"])
  t,r,e=self.fixture()
  with t:
   target=r/".ci/prysm-mtls-applicability"/(a.ADVISORY+".json")
   target.write_bytes(pin.read_bytes())
   (e/"advisory-current.json").write_bytes(pin.read_bytes().removesuffix(b"\n"))
   self.assess(r,e)
   tampered=dict(official); tampered.pop("details")
   (e/"advisory-current.json").write_text(json.dumps(tampered))
   with self.assertRaises(ValueError): self.assess(r,e)
 def test_negative_cases_fail_closed(self):
  cases={
   "critical":lambda e,r: self.raw(e,lambda x:x["matches"].append({"vulnerability":{"severity":"High"}})),
   "additional_unknown":lambda e,r: self.raw(e,lambda x:x["matches"].append({"vulnerability":{"id":"x","severity":"Unknown"},"artifact":{}})),
   "wrong_module":lambda e,r: self.raw(e,lambda x:x["matches"][0]["artifact"].update(name="x")),
   "wrong_version":lambda e,r: self.raw(e,lambda x:x["matches"][0]["artifact"].update(version="v0")),
   "suppressed":lambda e,r: self.raw(e,lambda x:x.update(ignoredMatches=[{}])),
   "affected_closure":lambda e,r:(e/"dependencies.txt").write_bytes(b"golang.org/x/crypto/openpgp\n"),
   "wrong_digest":lambda e,r:self.raw(e,lambda x:x["source"]["target"].update(manifestDigest="sha256:"+"c"*64)),
   "root":lambda e,r:self.ident(e, user="0:0"), "bad_binary":lambda e,r:(e/"binary.sha256").write_text("not-a-hash  /validator\n"),
   "root_name":lambda e,r:self.ident(e, user="root"), "root_group":lambda e,r:self.ident(e, user="0:123"), "incomplete_closure":lambda e,r:(e/"dependencies.txt").write_bytes(b"hello\n"),
   "expired":lambda e,r:self.manifest(r,expires_at="2026-09-15T00:00:00Z"), "future_review":lambda e,r:self.manifest(r,reviewed_at="2026-09-16T00:00:00Z"),
   "advisory_drift":lambda e,r:(e/"advisory-current.json").write_text("{}"), }
  for n,f in cases.items():
   with self.subTest(n=n):
    t,r,e=self.fixture()
    with t:
     f(e,r)
     with self.assertRaises(ValueError): self.assess(r,e)
 def raw(self,e,f): x=json.loads((e/"grype.json").read_text()); f(x); (e/"grype.json").write_text(json.dumps(x))
 def ident(self,e,**k): x=json.loads((e/"runtime-identity.json").read_text()); x.update(k); (e/"runtime-identity.json").write_text(json.dumps(x))
 def manifest(self,r,**k): x=json.loads((r/".ci/prysm-mtls-applicability.json").read_text()); x.update(k); (r/".ci/prysm-mtls-applicability.json").write_text(json.dumps(x))
if __name__=="__main__": unittest.main()
