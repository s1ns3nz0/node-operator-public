#!/usr/bin/env python3
"""Require complete, byte-exact repository renderer output with bounded inputs."""
import argparse
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
IMAGE = r"[0-9]{12}\.dkr\.ecr\.ap-northeast-[12]\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}"
DEPLOYMENT = r"[a-z][a-z0-9-]{1,38}[a-z0-9]"


def validate(runtime, client, validator_set, public_key, expected_images):
    if not re.fullmatch(r"hoodi-[a-z0-9][a-z0-9-]{0,35}", validator_set):
        raise ValueError("invalid validator set")
    if not re.fullmatch(r"0x[0-9a-fA-F]{96}", public_key):
        raise ValueError("invalid public key")
    try:
        fence_image = expected_images["SIGNING_FENCE_IMAGE"]
    except KeyError as error:
        raise ValueError("missing expected signing fence image") from error
    fence_match = re.fullmatch(
        rf"[0-9]{{12}}\.dkr\.ecr\.ap-northeast-[12]\.amazonaws\.com/"
        rf"(?P<deployment>{DEPLOYMENT})-baseline-validator-fence@sha256:[0-9a-f]{{64}}",
        fence_image,
    )
    if fence_match is None:
        raise ValueError("invalid expected signing fence image")
    deployment_identity = fence_match.group("deployment")
    bindings = {"VALIDATOR_SET": re.escape(validator_set),
                "VALIDATOR_PUBLIC_KEY": re.escape(public_key),
                "WEB3SIGNER_IMAGE": IMAGE, "POSTGRES_IMAGE": IMAGE,
                "PRYSM_VALIDATOR_IMAGE": IMAGE, "SIGNING_FENCE_IMAGE": IMAGE,
                "KUBERNETES_API_CIDR": r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/32",
                "DEPLOYMENT_IDENTITY": re.escape(deployment_identity),
                "RELEASE_IDENTITY": r"[0-9a-f]{40}"}
    templates = ROOT / "deploy/validator"
    expected = [(templates / "runtime-template.yaml").read_text(),
                (templates / "client-lease-fence-template.yaml").read_text() + "---\n" +
                (templates / "client-template.yaml").read_text()]
    values = {}
    identity_modes = []
    for content, template in zip((runtime, client), expected):
        has_deployment_identity = "node-operator.io/deployment-name:" in content
        has_release_identity = "node-operator.io/release-revision:" in content
        if has_deployment_identity != has_release_identity:
            raise ValueError("manifest has incomplete deployment identity binding")
        identity_modes.append(has_deployment_identity)
        if not has_deployment_identity:
            template = re.sub(r"^.*node-operator\.io/(?:deployment-name|release-revision):.*\n", "", template, flags=re.M)
        seen = set()
        fragments = []
        position = 0
        for match in re.finditer(r"REPLACE_WITH_([A-Z0-9_]+)", template):
            key = match.group(1)
            if key not in bindings:
                raise ValueError(f"unknown template placeholder: {key}")
            fragments.append(re.escape(template[position:match.start()]))
            fragments.append(f"(?P={key})" if key in seen else f"(?P<{key}>{bindings[key]})")
            seen.add(key)
            position = match.end()
        fragments.append(re.escape(template[position:]))
        result = re.fullmatch("".join(fragments), content)
        if result is None:
            raise ValueError("manifest differs from canonical renderer output")
        for key, value in result.groupdict().items():
            if key in values and values[key] != value:
                raise ValueError(f"manifest values differ for {key}")
            values[key] = value
    if len(set(identity_modes)) != 1:
        raise ValueError("runtime and client identity binding modes differ")
    ipaddress.IPv4Network(values["KUBERNETES_API_CIDR"])
    images = [value for key, value in values.items() if key.endswith("_IMAGE")]
    if len({image.split("/")[0] for image in images}) != 1:
        raise ValueError("images must share one account and region")
    if f"/{deployment_identity}-baseline-validator-fence@" not in values["SIGNING_FENCE_IMAGE"]:
        raise ValueError("invalid fence image repository")
    for key in ("WEB3SIGNER_IMAGE", "POSTGRES_IMAGE", "SIGNING_FENCE_IMAGE"):
        if values[key] != expected_images[key]:
            raise ValueError("Vault cutover must retain the current runtime image digests")
    approved = json.loads((ROOT / ".ci/validator/approved-client-images.json").read_text())
    if not any(item.get("private_image") == values["PRYSM_VALIDATOR_IMAGE"] and
               item.get("stage_approved") is True and
               item.get("release_channel") in ("upstream-mirror", "manual-native-mtls")
               for item in approved["images"]):
        raise ValueError("Prysm validator image is not stage approved")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for option in ("runtime", "client", "validator-set", "public-key", "web3signer-image", "postgres-image", "signing-fence-image"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    try:
        validate(Path(args.runtime).read_text(), Path(args.client).read_text(),
                 args.validator_set, args.public_key,
                 {"WEB3SIGNER_IMAGE": args.web3signer_image, "POSTGRES_IMAGE": args.postgres_image,
                  "SIGNING_FENCE_IMAGE": args.signing_fence_image})
    except (ValueError, OSError, KeyError):
        parser.exit(65, "FAIL: cutover manifests are not canonical, bounded renderer output.\n")
    print("PASS: complete runtime/client/fence manifests match repository renderer contracts.")
