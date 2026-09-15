"""Rebind only the release-owned collector image in the existing Kyverno policy.

The caller must verify the release and the full artifact-mirror receipt first.
This pure function is not image approval. It preserves the reviewed digest,
binds the existing registry patterns to the selected registry, and preserves
all other controls; it never adds wildcard or namespace-wide exceptions.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any

IMAGE = re.compile(r"[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z0-9-]+-[0-9]+\.amazonaws\.com/[a-z][a-z0-9-]*-baseline-validator-fluent-bit@sha256:[0-9a-f]{64}\Z")
HOST_KEY = "{{ (request.object.spec.containers || `[]`)[?name == 'fluent-bit'].image }}"
ROOT_PREFIX = "{{ not_null(element.securityContext.runAsNonRoot, request.object.spec.securityContext.runAsNonRoot, `false`) || (request.namespace == 'validator-observability' && (request.object.spec.serviceAccountName || '') == 'validator-log-collector' && element.name == 'fluent-bit' && element.image == '"
ROOT_SUFFIX = "') }}"


class CollectorPolicyError(ValueError):
    pass


def render(policy: dict[str, Any], approved_image: str) -> dict[str, Any]:
    """Return a copy bound to one verified mirror of the same reviewed digest."""
    if not isinstance(approved_image, str) or IMAGE.fullmatch(approved_image) is None:
        raise CollectorPolicyError("collector mirror image must be an exact private ECR digest")
    try:
        if (policy["apiVersion"] != "kyverno.io/v1" or policy["kind"] != "ClusterPolicy"
                or policy["metadata"]["name"] != "node-operator-project-workload-baseline"
                or policy["spec"]["validationFailureAction"] != "Enforce"
                or policy["spec"]["background"] is not True):
            raise CollectorPolicyError("release collector policy identity or enforcement is invalid")
        result = copy.deepcopy(policy)
        rules = result["spec"]["rules"]
        if not isinstance(rules, list) or any(not isinstance(rule, dict) or not isinstance(rule.get("name"), str) for rule in rules):
            raise CollectorPolicyError("collector policy rules are invalid")
        by_name = {rule["name"]: rule for rule in rules}
        if len(by_name) != len(rules):
            raise CollectorPolicyError("collector policy rule names are ambiguous")
        host_conditions = by_name["restrict-validator-log-collector-hostpath"]["validate"]["deny"]["conditions"]["any"]
        if not isinstance(host_conditions, list):
            raise CollectorPolicyError("collector hostPath conditions are invalid")
        image_conditions = [row for row in host_conditions if isinstance(row, dict) and row.get("key") == HOST_KEY]
        if len(image_conditions) != 1:
            raise CollectorPolicyError("collector hostPath image exception is ambiguous")
        host = image_conditions[0]
        if set(host) != {"key", "operator", "value"} or host["operator"] != "AnyNotIn" or not isinstance(host["value"], list) or len(host["value"]) != 1:
            raise CollectorPolicyError("collector hostPath image exception is not exact")
        original = host["value"][0]
        if not isinstance(original, str) or IMAGE.fullmatch(original) is None or original.rsplit("@", 1)[1] != approved_image.rsplit("@", 1)[1]:
            raise CollectorPolicyError("collector policy and verified image digests differ")
        loops = by_name["require-effective-restricted-runtime-security-context"]["validate"]["foreach"]
        if not isinstance(loops, list):
            raise CollectorPolicyError("collector root conditions are invalid")
        expected = {"key": ROOT_PREFIX + original + ROOT_SUFFIX, "operator": "NotEquals", "value": True}
        matches = []
        for loop in loops:
            if not isinstance(loop, dict) or loop.get("list") != "request.object.spec.containers[]":
                continue
            conditions = loop.get("deny", {}).get("conditions", {}).get("all", [])
            if (isinstance(conditions, list) and len(conditions) == 1
                    and isinstance(conditions[0], dict) and conditions[0].get("value") is True
                    and conditions[0] == expected):
                matches.append(conditions[0])
        # Count both occurrences over the whole source policy so an additional
        # location cannot remain bound to the previous deployment accidentally.
        if len(matches) != 1 or json.dumps(result, sort_keys=True).count(original) != 2:
            raise CollectorPolicyError("collector policy has an unexpected image exception layout")
        # The generic project rule must use the same selected registry too;
        # changing only the collector exceptions still denies a new Region.
        old_registry = original.split("/", 1)[0]
        new_registry = approved_image.split("/", 1)[0]
        registry_rule = by_name["require-private-ecr-image-digest"]["validate"]
        registry_loops = registry_rule["foreach"]
        suffix = "/*@sha256:" + "?" * 64
        expected_loops = [
            {"list": "request.object.spec.containers[]", "pattern": {"image": old_registry + suffix}},
            {"list": "request.object.spec.initContainers || `[]`", "pattern": {"image": old_registry + suffix}},
        ]
        if registry_loops != expected_loops:
            raise CollectorPolicyError("project registry restriction is not the reviewed exact pattern")
        for loop in registry_loops:
            loop["pattern"]["image"] = new_registry + suffix
        registry_rule["message"] = f"Containers must use a private {new_registry.split('.')[3]} ECR image pinned to a SHA-256 digest."
        host["value"] = [approved_image]
        matches[0]["key"] = ROOT_PREFIX + approved_image + ROOT_SUFFIX
        return result
    except (KeyError, TypeError, AttributeError) as error:
        raise CollectorPolicyError("collector policy structure is invalid") from error
