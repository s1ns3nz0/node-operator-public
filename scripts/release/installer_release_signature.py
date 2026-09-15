#!/usr/bin/env python3
"""Verify a fresh P-256 Vault release without contacting the discarded signer.

The caller must obtain the public-key SHA-256 from a separately authenticated
release trust policy. Downloading a public key and hashing it is not trust.
Legacy releases with other key algorithms are intentionally not accepted here.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import os
import re
import stat
import subprocess
import tarfile
import tempfile

SHA = re.compile(r"[a-f0-9]{64}\Z")
REVISION = re.compile(r"[a-f0-9]{40}\Z")
SIGNATURE = re.compile(r"vault:v([1-9][0-9]*):([A-Za-z0-9+/]+={0,2})\Z")
MAX_METADATA = 4 * 1024 * 1024
EXPECTED_BUILDER = "local://node-operator/scripts/ci/build-release-bundle.sh"
EXPECTED_BUILD_TYPE = "https://node-operator.example/release-bundle/v1"
# SubjectPublicKeyInfo: id-ecPublicKey + prime256v1 + 65-byte uncompressed point.
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


class SignatureError(ValueError):
    pass


def _regular(path: Path, limit: int | None = None) -> Path:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise SignatureError("release input must be a regular file")
    if limit is not None and path.stat().st_size > limit:
        raise SignatureError("release metadata exceeds size limit")
    return path


def _hash(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _json(raw: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SignatureError("duplicate metadata key")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise SignatureError("release metadata must be an object")
    return value


def verify_release(directory: Path, expected_revision: str, *, trusted_public_key: Path,
                   trusted_key_sha256: str) -> dict:
    """Verify cryptography and return a bundle-manifest trust handoff.

    The caller owns private, quiescent inputs. This routine extracts no files,
    executes no downloaded code and does not establish release-tag freshness.
    """
    if not REVISION.fullmatch(expected_revision) or not SHA.fullmatch(trusted_key_sha256):
        raise SignatureError("expected release revision and trusted public-key hash are required")
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise SignatureError("release directory is unsafe")
    _regular(trusted_public_key, 4096)
    key_bytes = trusted_public_key.read_bytes()
    if hashlib.sha256(key_bytes).hexdigest() != trusted_key_sha256:
        raise SignatureError("public key differs from trusted release policy")
    key_match = re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*", key_bytes)
    if key_match is None:
        raise SignatureError("only a P-256 public key is accepted")
    der = base64.b64decode(re.sub(rb"\s", b"", key_match[1]), validate=True)
    if len(der) != 91 or not der.startswith(P256_SPKI_PREFIX):
        raise SignatureError("public key algorithm is not P-256")
    bundle = _regular(directory / "node-operator-release-bundle.tar", 2 * 1024 * 1024 * 1024)
    provenance_path = _regular(directory / "provenance-input.json", MAX_METADATA)
    result_path = _regular(directory / "release-verification.json", MAX_METADATA)
    provenance_bytes = provenance_path.read_bytes()
    provenance = _json(provenance_bytes)
    result = _json(result_path.read_bytes())
    transit = result.get("transit")
    if not isinstance(transit, dict) or transit.get("key") != "node-operator-release":
        raise SignatureError("release signature identity is invalid")
    signature = SIGNATURE.fullmatch(transit.get("signature", ""))
    if signature is None:
        raise SignatureError("Vault signature envelope is invalid")
    raw_signature = base64.b64decode(signature[2], validate=True)
    if not 8 <= len(raw_signature) <= 80:
        raise SignatureError("P-256 signature size is invalid")
    with tempfile.TemporaryDirectory(prefix="node-operator-signature-") as scratch:
        private = Path(scratch)
        (private / "key.pem").write_bytes(key_bytes)
        (private / "signature.der").write_bytes(raw_signature)
        (private / "provenance.json").write_bytes(provenance_bytes)
        try:
            checked = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(private / "key.pem"),
                "-signature", str(private / "signature.der"), str(private / "provenance.json")],
                capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SignatureError("offline signature verifier is unavailable") from error
        if checked.returncode != 0:
            raise SignatureError("release cryptographic signature verification failed")
    digest = _hash(bundle)
    predicate = provenance.get("predicate", {})
    if (provenance.get("_type") != "https://in-toto.io/Statement/v1"
            or provenance.get("predicateType") != "https://slsa.dev/provenance/v1"
            or provenance.get("subject") != [{"name": bundle.name, "digest": {"sha256": digest}}]
            or not isinstance(predicate, dict)):
        raise SignatureError("signed provenance does not bind this bundle")
    definition = predicate.get("buildDefinition")
    details = predicate.get("runDetails")
    if not isinstance(definition, dict) or not isinstance(details, dict) or not isinstance(details.get("builder"), dict) or not isinstance(details["builder"].get("id"), str) or not details["builder"]["id"]:
        raise SignatureError("signed provenance builder metadata is invalid")
    # These are signed format constraints, not independent builder attestation.
    # The caller still must authenticate the signing key and expected revision.
    if details["builder"]["id"] != EXPECTED_BUILDER or definition.get("buildType") != EXPECTED_BUILD_TYPE:
        raise SignatureError("signed provenance is outside the release builder contract")
    dependencies = definition.get("resolvedDependencies", [])
    if not isinstance(dependencies, list) or any(not isinstance(item, dict) or not isinstance(item.get("digest"), dict) for item in dependencies):
        raise SignatureError("signed provenance dependency metadata is invalid")
    revisions = [item.get("digest", {}).get("gitCommit") for item in dependencies
                 if isinstance(item, dict) and item.get("uri") == "git+node-operator"]
    if revisions != [expected_revision]:
        raise SignatureError("signed provenance does not bind the expected source revision")
    if (result.get("schema_version") != "v1"
            or result.get("artifact") != {"name": bundle.name, "digest": "sha256:" + digest}
            or result.get("provenance") != {"sha256": "sha256:" + hashlib.sha256(provenance_bytes).hexdigest(),
                "subject_digest": "sha256:" + digest, "source_revision": expected_revision,
                "builder_id": details["builder"]["id"]}):
        raise SignatureError("release result does not match signed provenance")
    manifest_bytes = None
    with tarfile.open(bundle, "r:") as archive:
        for member in archive:
            if member.name == "bundle-manifest.json":
                if manifest_bytes is not None or not member.isfile() or not 0 < member.size <= MAX_METADATA:
                    raise SignatureError("bundle manifest is duplicate or unsafe")
                handle = archive.extractfile(member)
                if handle is None:
                    raise SignatureError("bundle manifest is unavailable")
                manifest_bytes = handle.read(MAX_METADATA + 1)
    if manifest_bytes is None or _json(manifest_bytes).get("source_revision") != expected_revision:
        raise SignatureError("bundle manifest revision is invalid")
    return {"release_revision": expected_revision, "artifact_sha256": digest,
            "authenticated_bundle_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "public_key_sha256": trusted_key_sha256,
            "scope": "offline P-256 signature and bundle binding; extraction and OCI assets not yet verified"}


def extract_verified_bundle(directory: Path, destination: Path, expected_revision: str, *,
                            trusted_public_key: Path, trusted_key_sha256: str) -> dict:
    """Authenticate first, then atomically expose only hash-bound regular files.

    No release-owned script is executed. Destination must not exist; caller
    keeps its parent private and quiescent until subsequent installer handoff.
    """
    binding = verify_release(directory, expected_revision, trusted_public_key=trusted_public_key,
                             trusted_key_sha256=trusted_key_sha256)
    if (not destination.is_absolute() or destination.exists() or destination.is_symlink()
            or destination.parent.is_symlink() or not destination.parent.is_dir()
            or stat.S_IMODE(destination.parent.stat().st_mode) != 0o700):
        raise SignatureError("new private extraction destination is required")
    bundle = directory / "node-operator-release-bundle.tar"
    # Recheck after signature work and validate member hashes on extraction.
    if _hash(bundle) != binding["artifact_sha256"]:
        raise SignatureError("bundle changed after signature verification")
    with tarfile.open(bundle, "r:") as archive:
        manifest = archive.extractfile("bundle-manifest.json")
        if manifest is None:
            raise SignatureError("bundle manifest is unavailable")
        raw = manifest.read(MAX_METADATA + 1)
        if sha256_bytes(raw) != binding["authenticated_bundle_manifest_sha256"]:
            raise SignatureError("bundle manifest changed")
        value = _json(raw)
        if value.get("schema_version") != "v1" or not isinstance(value.get("entries"), list):
            raise SignatureError("bundle manifest schema is invalid")
        expected = {}
        for entry in value["entries"]:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
                raise SignatureError("bundle entry schema is invalid")
            name = entry["path"]
            if not isinstance(name, str) or not name or "\\" in name:
                raise SignatureError("unsafe bundle member")
            path = PurePosixPath(name)
            if path.is_absolute() or str(path) != name or ".." in path.parts or name == "bundle-manifest.json" or name in expected:
                raise SignatureError("unsafe or duplicate bundle member")
            if not isinstance(entry["sha256"], str) or not SHA.fullmatch(entry["sha256"]) or type(entry["size"]) is not int or not 0 <= entry["size"] <= 256 * 1024 * 1024:
                raise SignatureError("bundle member hash or size is invalid")
            expected[name] = entry
        if len(expected) > 20000 or sum(item["size"] for item in expected.values()) > 1024 * 1024 * 1024:
            raise SignatureError("bundle expanded size exceeds limit")
        expected["bundle-manifest.json"] = {"size": len(raw), "sha256": sha256_bytes(raw)}
        with tempfile.TemporaryDirectory(prefix=".verified-release-", dir=destination.parent) as scratch:
            stage = Path(scratch) / "bundle"
            stage.mkdir(mode=0o700)
            seen = set()
            for member in archive.getmembers():
                if not member.isfile() or member.name not in expected or member.name in seen:
                    raise SignatureError("archive contains unbound, duplicate or non-regular members")
                entry = expected[member.name]
                if member.size != entry["size"]:
                    raise SignatureError("archive member size differs from manifest")
                output = stage / member.name
                output.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                digest = hashlib.sha256()
                if stream is None:
                    raise SignatureError("archive member is unavailable")
                with output.open("xb") as handle:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        handle.write(chunk)
                        digest.update(chunk)
                if digest.hexdigest() != entry["sha256"]:
                    raise SignatureError("archive member digest differs from manifest")
                output.chmod(0o700 if member.mode & 0o111 else 0o600)
                seen.add(member.name)
            if seen != set(expected):
                raise SignatureError("archive is missing bound members")
            os.rename(stage, destination)
    return {**binding, "bundle_root": str(destination), "scope": "authenticated bundle extracted; OCI payload still requires verification"}


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--trusted-key-sha256", required=True)
    parser.add_argument("--extract-to", type=Path)
    args = parser.parse_args()
    kwargs = {"trusted_public_key": args.trusted_public_key, "trusted_key_sha256": args.trusted_key_sha256}
    try:
        result = (extract_verified_bundle(args.release_dir, args.extract_to, args.expected_revision, **kwargs)
                  if args.extract_to is not None else verify_release(args.release_dir, args.expected_revision, **kwargs))
    except (ValueError, OSError, tarfile.TarError, TypeError):
        print("Release authentication failed; no installer code was executed.", file=sys.stderr)
        return 65
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
