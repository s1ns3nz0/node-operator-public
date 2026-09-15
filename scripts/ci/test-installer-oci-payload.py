#!/usr/bin/env python3
# Check objective: Reject corrupt OCI payloads and preserve exact approved root digests across chunked transport.
"""Offline corruption and determinism tests for installer OCI payloads."""
import hashlib, importlib.util, json, os, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]; spec=importlib.util.spec_from_file_location("oci_payload", ROOT/"scripts/release/installer_oci_payload.py"); mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
def dig(data): return "sha256:"+hashlib.sha256(data).hexdigest()
def blob(root,data):
    name=dig(data)[7:]; (root/"blobs/sha256"/name).write_bytes(data); return {"mediaType":"application/octet-stream","digest":"sha256:"+name,"size":len(data)}
class TestPayload(unittest.TestCase):
 def setUp(self): self.tmp=Path(tempfile.mkdtemp()); self.source=self.tmp/"source"; self.layout=self.make_layout(self.source)
 def tearDown(self): shutil.rmtree(self.tmp)
 def make_layout(self,root,conflict=False):
    (root/"blobs/sha256").mkdir(parents=True); (root/"oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    config=blob(root,b'{"config":{"not":"a manifest"},"layers":[]}'); layer=blob(root,b"layer bytes"*700)
    layer2=blob(root,b"second layer"*700)
    layers=[layer,layer2]
    if conflict: layers.append({**config,"size":config["size"]+1})
    manifest=json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":config,"layers":layers},sort_keys=True,separators=(",",":" )).encode(); descriptor=blob(root,manifest); descriptor["mediaType"]="application/vnd.oci.image.manifest.v1+json"; descriptor["annotations"]={"org.opencontainers.image.ref.name":"approved"}
    (root/"index.json").write_text(json.dumps({"schemaVersion":2,"manifests":[descriptor]},sort_keys=True,separators=(",",":"))); return descriptor["digest"]
 def prepare(self,name="payload",limit=10240): return mod.prepare_payload({"app":(self.source,self.layout)},self.tmp/name,chunk_limit=limit)
 def test_deterministic_reconstruct_and_terminal_config(self):
    first=self.prepare("one"); second=self.prepare("two"); self.assertEqual((self.tmp/"one/payload-manifest.json").read_bytes(),(self.tmp/"two/payload-manifest.json").read_bytes()); self.assertEqual(first,mod.verify_payload(self.tmp/"one",expected_roots={"app":self.layout},reconstruct_dir=self.tmp/"rebuilt")); self.assertTrue((self.tmp/"rebuilt/oci/app/index.json").is_file())
 def test_rejects_corrupt_missing_symlink_and_existing_output(self):
    self.prepare(); chunk=next((self.tmp/"payload/chunks").iterdir()); chunk.write_bytes(b"bad")
    with self.assertRaises(mod.OciPayloadError): mod.verify_payload(self.tmp/"payload",expected_roots={"app":self.layout})
    shutil.rmtree(self.tmp/"payload"); (self.source/"blobs/sha256"/self.layout[7:]).unlink()
    with self.assertRaises(mod.OciPayloadError): self.prepare()
    self.source=self.tmp/"other"; self.layout=self.make_layout(self.source); (self.source/"blobs/sha256"/("a"*64)).symlink_to(self.source/"index.json")
    with self.assertRaises(mod.OciPayloadError): self.prepare()
    (self.tmp/"exists").mkdir()
    with self.assertRaises(mod.OciPayloadError): mod.prepare_payload({"app":(self.source,self.layout)},self.tmp/"exists",chunk_limit=10240)
 def test_chunking_and_oversized_metadata_rejected(self):
    self.prepare(limit=10240); self.assertGreater(len(list((self.tmp/"payload/chunks").iterdir())),1)
    (self.source/"index.json").write_bytes(b"{"+b"x"*(mod.MAX_METADATA_BYTES+1))
    with self.assertRaises(mod.OciPayloadError): self.prepare("large")
 def test_minimal_generated_index_and_required_roots(self):
    # An unrelated historical root remains in the source index but is never
    # transported in the generated, one-root OCI layout index.
    extra={"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:"+("b"*64),"size":1}
    index=json.loads((self.source/"index.json").read_text()); index["manifests"].append(extra); (self.source/"index.json").write_text(json.dumps(index))
    self.prepare(); rebuilt=self.tmp/"rebuilt"; mod.verify_payload(self.tmp/"payload",expected_roots={"app":self.layout},reconstruct_dir=rebuilt)
    out=json.loads((rebuilt/"oci/app/index.json").read_text()); self.assertEqual([x["digest"] for x in out["manifests"]],[self.layout]); self.assertRegex(out["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"],r"^root-[0-9a-f]{12}$")
    with self.assertRaises(TypeError): mod.verify_payload(self.tmp/"payload")
 def test_repeated_digest_with_conflicting_descriptor_is_rejected(self):
    bad=self.tmp/"conflict"; digest=self.make_layout(bad,conflict=True)
    with self.assertRaises(mod.OciPayloadError): mod.prepare_payload({"app":(bad,digest)},self.tmp/"bad",chunk_limit=10240)
 def test_rejects_empty_and_traversal_chunk_manifests(self):
    self.prepare(); path=self.tmp/"payload/payload-manifest.json"; value=json.loads(path.read_text())
    value["chunks"]=[]; path.write_text(json.dumps(value))
    with self.assertRaises(mod.OciPayloadError): mod.verify_payload(self.tmp/"payload",expected_roots={"app":self.layout})
    self.prepare("second"); path=self.tmp/"second/payload-manifest.json"; value=json.loads(path.read_text()); value["chunks"][0]["name"]="chunks/../../escape.tar"; path.write_text(json.dumps(value))
    with self.assertRaises(mod.OciPayloadError): mod.verify_payload(self.tmp/"second",expected_roots={"app":self.layout})
 def test_empty_oras_ingest_directory_is_ignored_but_nonempty_is_rejected(self):
    ingest=self.source/"ingest"; ingest.mkdir(); self.prepare()
    self.assertNotIn("ingest", {entry["path"].split("/")[2] for entry in json.loads((self.tmp/"payload/payload-manifest.json").read_text())["entries"]})
    shutil.rmtree(self.tmp/"payload"); (ingest/"unexpected").write_text("x")
    with self.assertRaises(mod.OciPayloadError): self.prepare()
if __name__ == "__main__": unittest.main()
