#!/usr/bin/env python3
"""Download and authenticate a public release without AWS or GitHub credentials.

The trusted launcher supplies the expected source revision and public-key pin.
No downloaded program executes here. The release tag is a locator, not trust.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import tarfile
import urllib.request
from urllib.parse import urlparse

from installer_release_signature import extract_verified_bundle, MAX_METADATA, _json
from installer_oci_binding import PAYLOAD_MEMBER, verify_bound_payload

REPOSITORY = "s1ns3nz0/node-operator"
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?\Z")
CHUNK = re.compile(r"chunks/(oci-payload-[0-9]{5}\.tar)\Z")


class DownloadError(ValueError):
    pass


class _ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} or parsed.port not in (None, 443) or parsed.username or parsed.password:
            raise DownloadError("release asset redirected outside approved HTTPS hosts")
        return super().redirect_request(request, response, code, message, headers, newurl)


def _download(url: str, destination: Path, maximum: int) -> None:
    """Stream a bounded public asset; never attach ambient GitHub tokens."""
    opener = urllib.request.build_opener(_ReleaseRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "node-operator-release-installer", "Accept-Encoding": "identity"})
    with opener.open(request, timeout=60) as response, destination.open("xb") as output:
        if response.status != 200:
            raise DownloadError("release asset download failed")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > maximum):
            raise DownloadError("release asset exceeds size limit")
        received = 0
        while True:
            block = response.read(min(1024 * 1024, maximum - received + 1))
            if not block:
                break
            received += len(block)
            if received > maximum:
                raise DownloadError("release asset exceeds size limit")
            output.write(block)
        if length is not None and received != int(length):
            raise DownloadError("release asset download was truncated")
    destination.chmod(0o600)


def prepare_release(tag: str, destination: Path, expected_revision: str, *,
                    trusted_public_key: Path, trusted_key_sha256: str) -> dict:
    """Expose the bundle and OCI assets only after complete authentication.

    Canonical inventory uses neutral offline destination values. They neither
    select an AWS account nor authorize deployment. Inputs must stay quiescent.
    """
    if not TAG.fullmatch(tag):
        raise DownloadError("release tag is invalid")
    if (not destination.is_absolute() or destination.exists() or destination.is_symlink()
            or destination.parent.is_symlink() or not destination.parent.is_dir()
            or stat.S_IMODE(destination.parent.stat().st_mode) != 0o700):
        raise DownloadError("new destination below a private directory is required")
    base = f"https://github.com/{REPOSITORY}/releases/download/{tag}/"
    with tempfile.TemporaryDirectory(prefix=".release-download-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "release"
        stage.mkdir(mode=0o700)
        assets = stage / "assets"
        assets.mkdir(mode=0o700)
        for name, limit in (("node-operator-release-bundle.tar", 2 * 1024**3),
                            ("provenance-input.json", MAX_METADATA), ("release-verification.json", MAX_METADATA)):
            _download(base + name, assets / name, limit)
        binding = extract_verified_bundle(assets, stage / "bundle", expected_revision,
            trusted_public_key=trusted_public_key, trusted_key_sha256=trusted_key_sha256)
        payload_manifest = stage / "bundle" / PAYLOAD_MEMBER
        if not payload_manifest.is_file() or payload_manifest.is_symlink():
            raise DownloadError("release has no bound OCI asset manifest")
        raw = payload_manifest.read_bytes()
        manifest = _json(raw)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("chunks"), list) or not 0 < len(manifest["chunks"]) <= 996:
            raise DownloadError("release chunk inventory is invalid")
        payload = stage / "oci-payload"
        (payload / "chunks").mkdir(parents=True, mode=0o700)
        (payload / "payload-manifest.json").write_bytes(raw)
        names = set()
        total = 0
        for chunk in manifest["chunks"]:
            if not isinstance(chunk, dict) or not isinstance(chunk.get("name"), str):
                raise DownloadError("release chunk is invalid")
            name = CHUNK.fullmatch(chunk["name"])
            size = chunk.get("size")
            digest = chunk.get("sha256")
            if name is None or chunk["name"] in names or type(size) is not int or not 0 < size < 2 * 1024**3 or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise DownloadError("release chunk bounds are invalid")
            names.add(chunk["name"])
            total += size
            if total > 32 * 1024**3:
                raise DownloadError("release OCI payload exceeds installer size limit")
            target = payload / chunk["name"]
            _download(base + name[1], target, size)
            computed = hashlib.sha256()
            with target.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    computed.update(block)
            if target.stat().st_size != size or computed.hexdigest() != digest:
                raise DownloadError("downloaded release chunk differs from signed manifest")
        verified = verify_bound_payload(stage / "bundle", expected_revision, payload,
            expected_bundle_manifest_sha256=binding["authenticated_bundle_manifest_sha256"],
            account="000000000000", region="ap-northeast-2", deployment_name="release-check")
        result = {"schema_version": 1, "release_tag": tag, "release_revision": expected_revision,
            "authenticated_bundle_manifest_sha256": binding["authenticated_bundle_manifest_sha256"],
            "public_key_sha256": trusted_key_sha256, "verified_roots": verified["verified_roots"],
            "bundle_root": str(destination / "bundle"), "oci_payload_dir": str(destination / "oci-payload"),
            "scope": "authenticated downloaded release; no AWS resources created"}
        (stage / "authenticated-release.json").write_text(json.dumps(result, sort_keys=True) + "\n")
        os.rename(stage, destination)
    return result


def main() -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--trusted-key-sha256", required=True)
    parser.add_argument("--launch", action="store_true", help="Run the authenticated single interactive installer after all verification passes")
    args = parser.parse_args()
    try:
        result = prepare_release(args.tag, args.destination, args.expected_revision,
            trusted_public_key=args.trusted_public_key, trusted_key_sha256=args.trusted_key_sha256)
    except (ValueError, OSError, TypeError, tarfile.TarError):
        print("Release download or authentication failed; no installer code was executed.", file=sys.stderr)
        return 65
    if args.launch:
        try:
            launch_installer(result)
        except (ValueError, OSError):
            print("Release authenticated, but installer launch failed. Verified files remain at --destination; inspect the entrypoint and retry without downloading again.", file=sys.stderr)
            return 69
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


def launch_installer(verified: dict) -> None:
    """Process-local handoff from prepare_release, not an imported JSON receipt.

    Only call with the result produced in this process after verification.
    Preserve the operator environment, including GITHUB_TOKEN.
    """
    script = Path(verified["bundle_root"]) / "source/scripts/release/node-operator-install.sh"
    if script.is_symlink() or not script.is_file() or not os.access(script, os.X_OK):
        raise DownloadError("verified release has no executable installer entrypoint")
    environment = dict(os.environ)
    environment.update(NODE_OPERATOR_OCI_PAYLOAD_DIR=verified["oci_payload_dir"],
        NODE_OPERATOR_AUTHENTICATED_BUNDLE_MANIFEST_SHA256=verified["authenticated_bundle_manifest_sha256"],
        PYTHONDONTWRITEBYTECODE="1")
    os.execve(script, [str(script)], environment)


if __name__ == "__main__":
    raise SystemExit(main())
