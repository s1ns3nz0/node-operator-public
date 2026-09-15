#!/usr/bin/env python3
"""Pure renderer for the release-owned private Fluent Bit DaemonSet.

The caller supplies the reviewed Fluent Bit ConfigMap data and a verified image
reference.  Image approval and receipt verification remain caller authority.
This module performs no filesystem, AWS, Kubernetes, or network operation.
"""
from __future__ import annotations
import hashlib, ipaddress, json, re
from typing import Any

ACCOUNT = re.compile(r"[0-9]{12}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z0-9-]+-[1-9][0-9]*\Z")
NAME = re.compile(r"[a-z][a-z0-9-]{1,38}[a-z0-9]\Z")
SET = re.compile(r"hoodi-[a-z0-9][a-z0-9-]*\Z")
IMAGE = re.compile(r"([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/([a-z0-9][a-z0-9._/-]*)@(sha256:[0-9a-f]{64})\Z")
LOG_GROUP = re.compile(r"/aws/eks/[^/\s]+/(validator-(?:workloads|metrics|security))\Z")
OUTPUT_HEADER = re.compile(r"\s*\[OUTPUT\]\s*\Z")
SECTION_HEADER = re.compile(r"\s*\[[^]]+\]\s*\Z")
DIRECTIVE_LINE = re.compile(r"(?P<prefix>\s*)(?P<key>[A-Za-z][A-Za-z0-9_-]*)\s+(?P<value>\S(?:.*\S)?)(?P<suffix>\s*)\Z")
REQUIRED_LOG_GROUPS = {"validator-workloads", "validator-metrics", "validator-security"}

class CollectorError(ValueError): pass
def _ip(value: Any) -> str:
    if not isinstance(value, str): raise CollectorError("endpoint IP is invalid")
    try: parsed = ipaddress.ip_address(value)
    except ValueError as error: raise CollectorError("endpoint IP is invalid") from error
    if parsed.version != 4 or not parsed.is_private: raise CollectorError("endpoint IP must be private IPv4")
    return str(parsed)
def _config(data: Any, region: str, deployment: str) -> tuple[dict[str,str], str]:
    if not isinstance(data, dict) or set(data) != {"fluent-bit.conf", "parsers.conf"} or not all(isinstance(v, str) and 0 < len(v.encode()) <= 512*1024 for v in data.values()):
        raise CollectorError("authoritative Fluent Bit config data is invalid")
    main = data["fluent-bit.conf"]
    lines = main.splitlines(keepends=True)
    output_ranges: list[tuple[int, int]] = []
    start = None
    for index, line in enumerate(lines):
        if OUTPUT_HEADER.fullmatch(line.rstrip("\r\n")):
            if start is not None:
                output_ranges.append((start, index))
            start = index
        elif start is not None and SECTION_HEADER.fullmatch(line.rstrip("\r\n")):
            output_ranges.append((start, index))
            start = None
    if start is not None:
        output_ranges.append((start, len(lines)))

    # The reviewed source may use a different deployment or region, but it
    # must contain exactly the three supported CloudWatch destinations.  This
    # prevents an injected output from escaping the release-owned log groups.
    seen_groups: set[str] = set()
    replacements: dict[int, str] = {}
    for start, end in output_ranges:
        directives: dict[str, list[tuple[int, re.Match[str]]]] = {"name": [], "region": [], "log_group_name": []}
        for index in range(start + 1, end):
            directive = DIRECTIVE_LINE.fullmatch(lines[index].rstrip("\r\n"))
            if directive is not None:
                key = directive.group("key").casefold()
                if key in directives:
                    directives[key].append((index, directive))
        if any(len(directives[key]) != 1 for key in directives):
            raise CollectorError("authoritative Fluent Bit outputs must each have one Name, region, and log_group_name directive")
        _, name_match = directives["name"][0]
        if name_match.group("value") != "cloudwatch_logs":
            raise CollectorError("authoritative Fluent Bit outputs must use the cloudwatch_logs plugin")
        region_index, region_match = directives["region"][0]
        group_index, group_match = directives["log_group_name"][0]
        group_value = group_match.group("value")
        supported_group = LOG_GROUP.fullmatch(group_value)
        if supported_group is None:
            raise CollectorError("authoritative Fluent Bit outputs contain an unsupported log group")
        group = supported_group.group(1)
        if group in seen_groups:
            raise CollectorError("authoritative Fluent Bit outputs contain duplicate release log groups")
        seen_groups.add(group)
        newline = "\r\n" if lines[region_index].endswith("\r\n") else "\n" if lines[region_index].endswith("\n") else ""
        replacements[region_index] = f"{region_match.group('prefix')}{region_match.group('key')} {region}{region_match.group('suffix')}{newline}"
        newline = "\r\n" if lines[group_index].endswith("\r\n") else "\n" if lines[group_index].endswith("\n") else ""
        replacements[group_index] = f"{group_match.group('prefix')}{group_match.group('key')} /aws/eks/{deployment}/{group}{group_match.group('suffix')}{newline}"
    if seen_groups != REQUIRED_LOG_GROUPS:
        raise CollectorError("authoritative Fluent Bit outputs are not exactly the three release log groups")
    for index, line in replacements.items():
        lines[index] = line
    # Change only release environment values; CRI parsing, filters and routing
    # remain exactly the supplied reviewed source configuration.
    main = "".join(lines)
    rendered = {"fluent-bit.conf":main, "parsers.conf":data["parsers.conf"]}
    digest = hashlib.sha256(json.dumps(rendered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return rendered, digest
def render(*, account: str, region: str, deployment: str, validator_set: str, image_ref: str,
           logs_endpoint_ipv4s: list[str], kubernetes_api_service_ipv4: str, fluent_bit_config: dict[str,str]) -> dict[str,Any]:
    if not ACCOUNT.fullmatch(account) or not REGION.fullmatch(region) or not NAME.fullmatch(deployment) or not SET.fullmatch(validator_set): raise CollectorError("release identity is invalid")
    image = IMAGE.fullmatch(image_ref)
    if image is None or image.group(1) != account or image.group(2) != region: raise CollectorError("image must be a selected-account private ECR digest")
    if not isinstance(logs_endpoint_ipv4s, list) or not 1 <= len(logs_endpoint_ipv4s) <= 8: raise CollectorError("one to eight Logs endpoints are required")
    logs = [_ip(x) for x in logs_endpoint_ipv4s]
    if len(set(logs)) != len(logs): raise CollectorError("Logs endpoints must be unique")
    api = _ip(kubernetes_api_service_ipv4)
    data, config_sha = _config(fluent_bit_config, region, deployment)
    config_name = "validator-log-collector-config-" + config_sha[:12]
    labels = {"app.kubernetes.io/component":"validator-log-collector", "node-operator.io/deployment-name":deployment, "node-operator.io/validator-set":validator_set}
    config = {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":config_name,"namespace":"validator-observability","labels":labels,"annotations":{"node-operator.io/config-sha256":config_sha}},"immutable":True,"data":data}
    daemon = {"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"validator-log-collector","namespace":"validator-observability","labels":labels,"annotations":{"node-operator.io/config-sha256":config_sha}},"spec":{"selector":{"matchLabels":{"app.kubernetes.io/component":"validator-log-collector"}},"template":{"metadata":{"labels":labels,"annotations":{"node-operator.io/config-sha256":config_sha}},"spec":{"serviceAccountName":"validator-log-collector","automountServiceAccountToken":True,"terminationGracePeriodSeconds":30,"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"tolerations":[{"operator":"Exists"}],"containers":[{"name":"fluent-bit","image":image_ref,"args":["-c","/fluent-bit/etc/fluent-bit.conf"],"resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"500m","memory":"512Mi"}},"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"varlog","mountPath":"/var/log","readOnly":True},{"name":"config","mountPath":"/fluent-bit/etc","readOnly":True},{"name":"buffers","mountPath":"/buffers"}]}],"volumes":[{"name":"varlog","hostPath":{"path":"/var/log","type":"Directory"}},{"name":"config","configMap":{"name":config_name}},{"name":"buffers","emptyDir":{}}]}}}}
    namespace = {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"validator-observability","labels":{"node-operator.io/security-domain":"validator-observability","pod-security.kubernetes.io/enforce":"privileged","pod-security.kubernetes.io/audit":"privileged","pod-security.kubernetes.io/warn":"privileged"}}}
    service = {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"validator-log-collector","namespace":"validator-observability","labels":{"app.kubernetes.io/component":"validator-log-collector"}},"automountServiceAccountToken":True}
    role = {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"validator-log-collector-metadata"},"rules":[{"apiGroups":[""],"resources":["namespaces","pods"],"verbs":["get","list","watch"]}]}
    binding = {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"validator-log-collector-metadata"},"subjects":[{"kind":"ServiceAccount","name":"validator-log-collector","namespace":"validator-observability"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"validator-log-collector-metadata"}}
    selector = {"matchLabels":{"app.kubernetes.io/component":"validator-log-collector"}}
    dns = {"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}
    blocks = [{"ipBlock":{"cidr":api+"/32"}},{"ipBlock":{"cidr":"169.254.170.23/32"}}] + [{"ipBlock":{"cidr":ip+"/32"}} for ip in logs]
    ports = [[{"protocol":"UDP","port":53},{"protocol":"TCP","port":53}], [{"protocol":"TCP","port":443}], [{"protocol":"TCP","port":80}]] + [[{"protocol":"TCP","port":443}] for _ in logs]
    egress = [{"to":[dns],"ports":ports[0]}] + [{"to":[block],"ports":port} for block,port in zip(blocks,ports[1:])]
    deny = {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"default-deny-ingress-egress","namespace":"validator-observability"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}
    allow = {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"allow-collector-dns-and-private-aws-endpoints","namespace":"validator-observability"},"spec":{"podSelector":selector,"policyTypes":["Egress"],"egress":egress}}
    return {"apiVersion":"v1","kind":"List","items":[namespace,service,role,binding,config,daemon,deny,allow]}
