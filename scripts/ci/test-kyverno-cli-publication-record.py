#!/usr/bin/env python3
import importlib.util, json, shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; spec=importlib.util.spec_from_file_location("record",ROOT/"scripts/release/kyverno_cli_publication_record.py"); record=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(record)
REV="a"*40; DIGEST="sha256:"+"b"*64; IMAGE="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@"+DIGEST
class Tests(unittest.TestCase):
 def test_record_and_proposed_catalog_row_are_digest_bound(self):
  value=record.create_record(ROOT,release_revision=REV,image_ref=IMAGE,manifest_digest=DIGEST,run_id="42")
  self.assertEqual(value["component"],"kyverno-cli")
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/"record.json"; path.write_text(json.dumps(value))
   result=subprocess.run(["python3",str(ROOT/"scripts/release/generate-kyverno-cli-manifest-approval.py"),"--source-root",str(ROOT),"--record",str(path)],text=True,capture_output=True)
   self.assertEqual(result.returncode,0,result.stderr); row=json.loads(result.stdout); self.assertEqual(row["source"],IMAGE); self.assertEqual(row["ecrTag"],DIGEST[7:])
 def test_wrong_target_is_rejected(self):
  with self.assertRaises(record.KyvernoPublicationRecordError): record.create_record(ROOT,release_revision=REV,image_ref=IMAGE.replace("nodes","charts"),manifest_digest=DIGEST,run_id="42")
 def test_manifest_renderer_rejects_forged_workflow_run_and_digest(self):
  value=record.create_record(ROOT,release_revision=REV,image_ref=IMAGE,manifest_digest=DIGEST,run_id="42")
  for path, replacement in ((["publication","workflow"],"other.yml"),(["publication","run_id"],"0"),(["target","manifest_digest"],"sha256:"+"c"*64)):
   forged=json.loads(json.dumps(value)); target=forged
   for key in path[:-1]: target=target[key]
   target[path[-1]]=replacement
   with tempfile.TemporaryDirectory() as temporary:
    output=Path(temporary)/"record.json"; output.write_text(json.dumps(forged))
    result=subprocess.run(["python3",str(ROOT/"scripts/release/generate-kyverno-cli-manifest-approval.py"),"--source-root",str(ROOT),"--record",str(output)],text=True,capture_output=True)
    self.assertNotEqual(result.returncode,0,path)
 def test_publisher_binds_the_upstream_commit_separately_from_release_revision(self):
  publisher=(ROOT/"scripts/release/publish-kyverno-cli-image.sh").read_text()
  self.assertIn("source_commit=",publisher)
  self.assertIn('git+https://github.com/kyverno/kyverno",digest:{gitCommit:$source_commit}',publisher)
  self.assertIn('git+https://github.com/s1ns3nz0/node-operator",digest:{gitCommit:$revision}',publisher)
 def test_publisher_build_context_resolves_dockerfile_copy_sources(self):
  publisher=(ROOT/"scripts/release/publish-kyverno-cli-image.sh").read_text()
  build=next(line for line in publisher.splitlines() if line.startswith("docker build "))
  context=ROOT/build.split()[-1]
  dockerfile=ROOT/".ci/kyverno-cli/Dockerfile"
  for line in dockerfile.read_text().splitlines():
   if line.startswith("COPY ") and "--from=" not in line:
    source=line.split()[1]
    self.assertTrue((context/source).is_file(),f"COPY source {source} is absent from build context {context}")
 def test_source_lock_must_match_dockerfile_defaults(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary); directory=root/".ci/kyverno-cli"; directory.mkdir(parents=True)
   for name in ("Dockerfile", "source-lock.json"): shutil.copy2(ROOT/".ci/kyverno-cli"/name,directory/name)
   self.assertEqual(record.source(root)["commit"], "40ec788d48bb28d83dbf85538e962a59db9d45c6")
   dockerfile=directory/"Dockerfile"
   dockerfile.write_text(dockerfile.read_text().replace("KYVERNO_COMMIT=40ec788d48bb28d83dbf85538e962a59db9d45c6", "KYVERNO_COMMIT="+"c"*40))
   with self.assertRaises(record.KyvernoPublicationRecordError): record.source(root)
if __name__=="__main__": unittest.main()
