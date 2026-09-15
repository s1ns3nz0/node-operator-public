#!/usr/bin/env python3
# Check objective: Enforce the disabled Vault runtime verifier IAM role source contract.
"""Strict source contract for the disabled Vault runtime verifier IAM role."""
import re
from pathlib import Path


def block(source, kind, name):
    labels = rf'"{name}"' if kind in {"variable", "output"} else rf'"[^"]+" "{name}"'
    match = re.search(rf'{kind} {labels} \{{\n(.*?)\n\}}', source, re.S)
    assert match, f"{name} {kind} block missing"
    return match[1]


def validate(source, signer_source):
    variable = block(source, "variable", "enable_vault_runtime_ci_verifier")
    assert re.search(r"type\s*=\s*bool", variable)
    assert re.search(r"default\s*=\s*false", variable)

    trust = block(source, "data", "github_vault_runtime_verifier_assume_role")
    assert 'count = var.enable_vault_runtime_ci_verifier ? 1 : 0' in trust
    assert '"sts:AssumeRoleWithWebIdentity"' in trust
    assert trust.count("statement {") == 1 and trust.count("condition {") == 3
    assert 'arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com' in trust
    for expected in (
        '"token.actions.githubusercontent.com:aud"',
        '"sts.amazonaws.com"',
        '"token.actions.githubusercontent.com:repository"',
        '[var.github_repository]',
        '"token.actions.githubusercontent.com:sub"',
        '"${local.github_destination_oidc_subject_prefix}:ref:refs/heads/main"',
    ):
        assert expected in trust, f"OIDC trust condition missing: {expected}"

    role = block(source, "resource", "github_vault_runtime_verifier")
    assert 'count              = var.enable_vault_runtime_ci_verifier ? 1 : 0' in role
    assert 'var.enable_vault_runtime_ecr && var.enable_node_runtime_ecr' in role

    policy = block(source, "data", "github_vault_runtime_verifier")
    statements = re.findall(
        r"statement \{\s*actions\s*=\s*\[([^\]]+)\]\s*resources\s*=\s*([^\n]+)\s*\}",
        policy,
        re.S,
    )
    assert len(statements) == 2 and policy.count("statement {") == 2
    token_actions = re.findall(r'"([^"]+)"', statements[0][0])
    assert token_actions == ["ecr:GetAuthorizationToken"]
    assert statements[0][1].strip() == '["*"]'

    read_actions = set(re.findall(r'"([^"]+)"', statements[1][0]))
    assert read_actions == {
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:DescribeImages",
        "ecr:GetDownloadUrlForLayer",
    }
    assert statements[1][1].strip() == "values(aws_ecr_repository.vault_runtime)[*].arn"

    runtime_repositories = (
        Path(__file__).resolve().parents[2] / "infra/terraform/vault-runtime-ecr.tf"
    ).read_text()
    assert 'toset(["server", "agent", "injector"])' in runtime_repositories, (
        "verifier scope must resolve to exactly the three Vault runtime repositories"
    )

    output = block(source, "output", "github_vault_runtime_ci_verifier_role_arn")
    assert "try(aws_iam_role.github_vault_runtime_verifier[0].arn, null)" in output

    # Every publisher, including the release signer, derives its trust from
    # the explicit operator repository and immutable numeric IDs.
    for expected in (
        'github_destination_oidc_subject_prefix    = "repo:${split("/", var.github_repository)[0]}@${var.github_owner_id}/${split("/", var.github_repository)[1]}@${var.github_repository_id}"',
        'github_destination_identity_is_explicit   = var.github_repository != "" && var.github_owner_id != "" && var.github_repository_id != ""',
        'release_signer_source_oidc_subject_prefix = local.github_destination_oidc_subject_prefix',
    ):
        assert expected in signer_source, f"destination identity derivation missing: {expected}"
    assert "s1ns3nz0/node-operator" not in signer_source


root = Path(__file__).resolve().parents[2]
source = (root / "infra/terraform/vault-runtime-verifier.tf").read_text()
signer_source = (root / "infra/terraform/vault-signer.tf").read_text()
validate(source, signer_source)
for bad_source, bad_signer_source in (
    (source.replace('"ecr:DescribeImages", ', '"ecr:PutImage", '), signer_source),
    (source.replace('values(aws_ecr_repository.vault_runtime)[*].arn', '["*"]'), signer_source),
    (source.replace('var.enable_vault_runtime_ecr && var.enable_node_runtime_ecr', 'true'), signer_source),
    (source.replace('local.github_destination_oidc_subject_prefix', '"*"'), signer_source),
    (source.replace('local.github_destination_oidc_subject_prefix', 'var.github_oidc_subject_prefix'), signer_source),
    (source.replace(':ref:refs/heads/main', ':environment:vault-runtime-verify'), signer_source),
    (source.replace(':ref:refs/heads/main', ':ref:refs/heads/release'), signer_source),
    (source.replace(':ref:refs/heads/main', ':ref:refs/tags/v1.0.0'), signer_source),
    (source.replace(':ref:refs/heads/main', ':pull_request'), signer_source),
):
    try:
        validate(bad_source, bad_signer_source)
    except AssertionError:
        continue
    raise AssertionError("unsafe verifier policy or trust mutation passed")

for bad_signer_source in (
    signer_source.replace('var.github_owner_id}', '"*"}'),
    signer_source.replace('local.github_destination_oidc_subject_prefix', '"*"'),
):
    try:
        validate(source, bad_signer_source)
    except AssertionError:
        continue
    raise AssertionError("unsafe destination identity derivation mutation passed")
print("PASS: Vault runtime verifier is disabled, prerequisite-bound, main-only, and read-only")
