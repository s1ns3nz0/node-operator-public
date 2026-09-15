#!/usr/bin/env python3
"""Check actual offline plan tags and execute the bootstrap digest shell block.

Input is a Terraform show -json plan produced with offline synthetic inputs.
No AWS commands from the plan are executed; only the digest loop runs with
mocked commands and disposable files.
"""

import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile


def verify(plan):
    count = 0
    dynamic_tags = set()
    for change in plan.get("resource_changes", []):
        if change.get("mode") != "managed":
            continue
        after = change.get("change", {}).get("after") or {}
        if "tags_all" not in after:
            continue
        tags = after["tags_all"] or {}
        expected = {
            "Project": "node-operator",
            "Deployment": "node-operator",
            "DeploymentRegion": "ap-northeast-2",
            "ManagedBy": "terraform",
        }
        assert all(tags.get(k) == v for k, v in expected.items()), (
            change["address"],
            tags,
        )
        if change["address"] == "aws_eks_addon.ebs_csi":
            config = json.loads(after["configuration_values"])
            assert all(
                config["controller"]["extraVolumeTags"].get(k) == v
                for k, v in expected.items()
            )
            dynamic_tags.add("volumes")
        if change["address"] == "aws_eks_addon.vpc_cni":
            config = json.loads(after["configuration_values"])
            eni_tags = json.loads(config["env"]["ADDITIONAL_ENI_TAGS"])
            assert all(eni_tags.get(k) == v for k, v in expected.items())
            assert config["enableNetworkPolicy"] == "true"
            dynamic_tags.add("interfaces")
        count += 1
    assert count > 20, "Expected a baseline plan, not a narrow fixture"
    assert dynamic_tags == {
        "volumes",
        "interfaces",
    }, "CSI/CNI-created resources need explicit tags"
    # The full buildspec remains unknown at plan time because it embeds newly
    # allocated AWS IDs. Execute the source loop with only HCL references
    # replaced by fixture values; do not claim this is a rendered buildspec.
    source = Path(__file__).resolve().parents[2] / "infra/terraform/argocd-bootstrap.tf"
    buildspec = source.read_text()
    start = buildspec.index("for image_tag in ")
    end = buildspec.index("\n", buildspec.index("done", start))
    block = re.sub(r"\$\{[^}]+\}", "fixture", buildspec[start:end])
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        values = root / "values.yaml"
        tags = block.split("for image_tag in ", 1)[1].split("; do", 1)[0].split()
        values.write_text("\n".join("digest: sha256:" + t for t in tags))
        # Mock AWS validates the expanded image tag; $$ expands to a process ID
        # in bash and must be rejected even when Terraform validate succeeds.
        aws = root / "aws"
        aws.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            f"tags={tags!r}\n"
            "tag=next(x.split('=',1)[1] for x in sys.argv if x.startswith('imageTag='))\n"
            "assert tag in tags, tag\nprint('sha256:'+'a'*64)\n"
        )
        sed = root / "sed"
        sed.write_text(
            "#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
            "_,before,after,_=sys.argv[2].split('#')\n"
            "p=Path(sys.argv[3]); p.write_text(p.read_text().replace(before,after))\n"
        )
        aws.chmod(0o700)
        sed.chmod(0o700)
        block = block.replace(
            "/opt/node-operator/cert-manager-values.yaml", str(values)
        )
        subprocess.run(
            ["bash", "-eu", "-c", block],
            check=True,
            env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"]},
        )
        assert values.read_text().count("sha256:" + "a" * 64) == 4
    print(
        f"PASS: {count} planned taggable resources carry deployment ownership; digest shell expands correctly."
    )


if __name__ == "__main__":
    verify(json.loads(Path(sys.argv[1]).read_text()))
