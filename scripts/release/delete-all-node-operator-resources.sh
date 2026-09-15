#!/usr/bin/env bash
# Tag-safe cleanup. Kept as one executable file intentionally.
exec python3 - "$@" <<'PY'
import argparse, json, re, subprocess, sys, time

PROJECT = "node-operator"
MANAGED = {"terraform", "node-operator-installer"}


def fail(s, c=64):
    print("ERROR: " + s, file=sys.stderr)
    raise SystemExit(c)


def cli():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--deployment")
    g.add_argument("--all-project-deployments", action="store_true")
    r = p.add_mutually_exclusive_group(required=True)
    r.add_argument("--region", action="append")
    r.add_argument("--all-regions", action="store_true")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--account")
    p.add_argument("--wait-seconds", type=int, default=900)
    a = p.parse_args()
    if a.execute and (not a.account or len(a.account) != 12 or not a.account.isdigit()):
        fail("--execute requires exact twelve-digit --account")
    if not 1 <= a.wait_seconds <= 3600:
        fail("--wait-seconds must be 1..3600")
    return a


class AWS:
    def __init__(s, region, res):
        s.r, s.res = region, res

    def run(s, *x, write=False, missing=False):
        q = ["aws", *x] + (["--region", s.r] if s.r else []) + ["--output", "json"]
        p = subprocess.run(q, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode:
            e = (p.stderr or p.stdout).strip()
            code = re.search(r"\(([^)]+)\)", e)
            absent_codes = {
                "ResourceNotFoundException",
                "RepositoryNotFoundException",
                "NotFoundException",
                "NotFound",
                "NoSuchBucket",
                "NoSuchEntity",
                "NoSuchTagSet",
                "404",
                "TrailNotFoundException",
                "InvalidVpcID.NotFound",
                "InvalidNatGatewayID.NotFound",
                "InvalidVpcEndpointId.NotFound",
                "InvalidInstanceID.NotFound",
                "InvalidGroup.NotFound",
                "InvalidSubnetID.NotFound",
                "InvalidRouteTableID.NotFound",
                "InvalidNetworkInterfaceID.NotFound",
                "InvalidAllocationID.NotFound",
                "InvalidInternetGatewayID.NotFound",
                "InvalidVolume.NotFound",
                "InvalidLaunchTemplateId.NotFound",
            }
            if missing and code and code.group(1) in absent_codes:
                return None
            s.res.append(
                {
                    "region": s.r,
                    "command": q[1:],
                    "error": e or "AWS CLI failed",
                    "kind": "mutation" if write else "inventory",
                }
            )
            return False
        try:
            return json.loads(p.stdout or "{}")
        except:
            s.res.append(
                {
                    "region": s.r,
                    "command": q[1:],
                    "error": "non-JSON AWS output",
                    "kind": "inventory",
                }
            )
            return False

    def pages(s, svc, op, key, *args):
        token = None
        while True:
            q = [svc, op, *args] + (["--starting-token", token] if token else [])
            d = s.run(*q)
            if d is False:
                return
            for x in d.get(key, []):
                yield x
            token = d.get("NextToken")
            if not token:
                return


def td(t):
    return (
        t
        if isinstance(t, dict)
        else {
            x.get("Key", x.get("TagKey")): x.get("Value", x.get("TagValue"))
            for x in t or []
        }
    )


def own(t, depl, iam_region=None):
    t = td(t)
    return (
        t.get("Project") == PROJECT
        and t.get("ManagedBy") in MANAGED
        and bool(t.get("Deployment"))
        and (depl is None or t.get("Deployment") == depl)
        and (iam_region is None or t.get("DeploymentRegion") == iam_region)
    )


def foreign(t, depl):
    return bool(td(t)) and not own(t, depl)


class Clean:
    def __init__(s, a, acct, regions, caller_arn=""):
        s.a, s.acct, s.regions, s.caller_arn, s.res, s.items, s.cluster_sgs = (
            a,
            acct,
            regions,
            caller_arn,
            [],
            [],
            set(),
        )

    def add(s, r, k, id, fn):
        s.items.append((r, k, id, fn))

    @property
    def depl(s):
        return None if s.a.all_project_deployments else s.a.deployment

    def inventory(s, r):
        w = AWS(r, s.res)
        # RGTA is supplemental only and paginated; unknown service ARNs remain residual.
        tok = None
        while True:
            q = (
                [
                    "resourcegroupstaggingapi",
                    "get-resources",
                    "--tag-filters",
                    "Key=Project,Values=node-operator",
                    "Key=ManagedBy,Values=terraform,node-operator-installer",
                ]
                + (["Key=Deployment,Values=" + s.depl] if s.depl else [])
                + (["--pagination-token", tok] if tok else [])
            )
            d = w.run(*q)
            if d is False:
                break
            for x in d.get("ResourceTagMappingList", []):
                if not own(x.get("Tags"), s.depl):
                    s.res.append(
                        {
                            "region": r,
                            "resource": x.get("ResourceARN"),
                            "error": "RGTA returned non-target or legacy tags; skipped",
                            "kind": "blocked",
                        }
                    )
                    continue
                arn = x.get("ResourceARN", "")
                # RGTA is regional; no ARN from a different account/region is
                # actionable in this pass (IAM is handled by native inventory).
                parts = arn.split(":", 5)
                if (
                    len(parts) < 6
                    or parts[4] != s.acct
                    or (parts[2] != "iam" and parts[3] != r)
                ):
                    s.res.append(
                        {
                            "region": r,
                            "resource": arn,
                            "error": "RGTA ARN account or region is outside selected context",
                            "kind": "blocked",
                        }
                    )
                    continue
                # These are inventoried by service-specific paths below; treating their
                # RGTA duplicate as unsupported would turn a successful cleanup into a lie.
                # Native inventory owns resources whose child dependencies need ordered
                # teardown.  Do not rediscover their RGTA children after a parent is gone.
                native = (":eks:", ":ecr:", ":s3:", ":dynamodb:", ":iam::")
                # Native inventory below handles EC2 children without duplicate
                # RGTA deletion attempts, including resources in external VPCs.
                if any(z in arn for z in native) or any(
                    prefix in arn
                    for prefix in (
                        ":vpc/",
                        ":instance/",
                        ":subnet/",
                        ":security-group/",
                        ":route-table/",
                        ":network-interface/",
                        ":network-acl/",
                        ":vpc-endpoint/",
                        ":natgateway/",
                        ":internet-gateway/",
                        ":elastic-ip/",
                    )
                ):
                    continue
                kind = s.tagged_kind(arn)
                if kind is None:
                    s.res.append(
                        {
                            "region": r,
                            "resource": arn,
                            "error": "unsupported tagged resource type; no deletion is planned",
                            "kind": "blocked",
                        }
                    )
                else:
                    s.add(r, kind, arn, s.unsupported)
            tok = d.get("PaginationToken")
            if not tok:
                break
        for n in w.pages("eks", "list-clusters", "clusters"):
            arn = f"arn:aws:eks:{r}:{s.acct}:cluster/{n}"
            d = w.run("eks", "list-tags-for-resource", "--resource-arn", arn)
            if d is not False and own(d.get("tags"), s.depl):
                s.add(r, "eks", n, s.eks)
        for x in w.pages("ecr", "describe-repositories", "repositories"):
            d = w.run(
                "ecr", "list-tags-for-resource", "--resource-arn", x["repositoryArn"]
            )
            if d is not False and own(d.get("tags"), s.depl):
                s.add(r, "ecr", x["repositoryName"], s.ecr)
        for name in w.pages("dynamodb", "list-tables", "TableNames"):
            d = w.run("dynamodb", "describe-table", "--table-name", name)
            if d is False:
                continue
            arn = d.get("Table", {}).get("TableArn")
            tags = w.run("dynamodb", "list-tags-of-resource", "--resource-arn", arn)
            if tags is not False and own(tags.get("Tags"), s.depl):
                kind = (
                    "backend-dynamodb"
                    if td(tags.get("Tags")).get("Purpose")
                    == "terraform-state-bootstrap"
                    else "dynamodb"
                )
                s.add(r, kind, name, s.ddb)
        d = w.run("ec2", "describe-vpcs")
        owned_vpcs = set()
        if d is not False:
            for x in d.get("Vpcs", []):
                if own(x.get("Tags"), s.depl):
                    owned_vpcs.add(x["VpcId"])
                    s.add(r, "vpc", x["VpcId"], s.vpc)
        # Independently tagged EC2 children must not be hidden merely because their
        # parent VPC is external.  `ec2child` re-reads the exact object before use.
        for op, key, idkey in (
            ("describe-subnets", "Subnets", "SubnetId"),
            ("describe-security-groups", "SecurityGroups", "GroupId"),
            ("describe-vpc-endpoints", "VpcEndpoints", "VpcEndpointId"),
            ("describe-route-tables", "RouteTables", "RouteTableId"),
            ("describe-network-interfaces", "NetworkInterfaces", "NetworkInterfaceId"),
            ("describe-network-acls", "NetworkAcls", "NetworkAclId"),
        ):
            d = w.run("ec2", op)
            if d is not False:
                for x in d.get(key, []):
                    if (
                        own(x.get("Tags") or x.get("TagSet"), s.depl)
                        and x.get("VpcId") not in owned_vpcs
                    ):
                        s.add(r, "ec2-native-child", x[idkey], s.ec2child)
        # Tagged NAT/IGW objects need a proven selected VPC before the VPC
        # handler can remove them. Never silently hide an orphaned dependency.
        for op, key, idkey in (
            ("describe-nat-gateways", "NatGateways", "NatGatewayId"),
            ("describe-internet-gateways", "InternetGateways", "InternetGatewayId"),
        ):
            d = w.run("ec2", op)
            if d is False:
                continue
            for x in d.get(key, []):
                parents = {x.get("VpcId")} | {
                    a.get("VpcId") for a in x.get("Attachments", [])
                }
                if (
                    own(x.get("Tags"), s.depl)
                    and x.get("State") != "deleted"
                    and not parents.intersection(owned_vpcs)
                ):
                    s.res.append(
                        {
                            "region": r,
                            "resource": x[idkey],
                            "kind": "blocked",
                            "error": "tagged NAT/IGW has no selected owned VPC; explicit dependency review required",
                        }
                    )
        d = w.run("ec2", "describe-addresses")
        if d is not False:
            for x in d.get("Addresses", []):
                if x.get("AllocationId") and own(x.get("Tags"), s.depl):
                    s.add(r, "eip", x["AllocationId"], s.ec2child)
        # Instances (including the operations host) are selected by their exact tags,
        # never by instance/profile/name convention.
        d = w.run("ec2", "describe-instances")
        if d is not False:
            for reservation in d.get("Reservations", []):
                for x in reservation.get("Instances", []):
                    if (
                        own(x.get("Tags"), s.depl)
                        and x.get("State", {}).get("Name") != "terminated"
                    ):
                        s.add(r, "ec2-instance", x["InstanceId"], s.instance)
        d = w.run("s3api", "list-buckets")
        if d is not False:
            for x in d.get("Buckets", []):
                name = x["Name"]
                loc = w.run("s3api", "get-bucket-location", "--bucket", name)
                if loc is False:
                    continue
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
                if bucket_region == "EU":
                    bucket_region = "eu-west-1"
                if bucket_region != r:
                    continue
                t = w.run("s3api", "get-bucket-tagging", "--bucket", name, missing=True)
                if t not in (False, None) and own(t.get("TagSet"), s.depl):
                    kind = (
                        "backend-s3"
                        if td(t.get("TagSet")).get("Purpose")
                        == "terraform-state-bootstrap"
                        else "s3"
                    )
                    s.add(r, kind, name, s.s3)

    def iam(s):
        w = AWS(None, s.res)
        for x in w.pages("iam", "list-roles", "Roles"):
            n = x["RoleName"]
            t = w.run("iam", "list-role-tags", "--role-name", n)
            # IAM is global: deployment must carry its source region tag.
            if t is not False and any(own(t.get("Tags"), s.depl, r) for r in s.regions):
                s.add(s.regions[0], "iam", n, s.role)
        for x in w.pages("iam", "list-instance-profiles", "InstanceProfiles"):
            n = x["InstanceProfileName"]
            t = w.run("iam", "list-instance-profile-tags", "--instance-profile-name", n)
            if t is not False and any(own(t.get("Tags"), s.depl, r) for r in s.regions):
                s.add(s.regions[0], "iam-profile", n, s.instance_profile)
        for x in w.pages(
            "iam", "list-open-id-connect-providers", "OpenIDConnectProviderList"
        ):
            arn = x["Arn"]
            t = w.run(
                "iam",
                "list-open-id-connect-provider-tags",
                "--open-id-connect-provider-arn",
                arn,
            )
            if t is not False and any(own(t.get("Tags"), s.depl, r) for r in s.regions):
                s.add(s.regions[0], "iam-oidc", arn, s.oidc)
        for x in w.pages("iam", "list-policies", "Policies", "--scope", "Local"):
            arn = x["Arn"]
            t = w.run("iam", "list-policy-tags", "--policy-arn", arn)
            if t is not False and any(own(t.get("Tags"), s.depl, r) for r in s.regions):
                s.res.append(
                    {
                        "region": s.regions[0],
                        "resource": arn,
                        "error": "tagged customer-managed IAM policy requires explicit detach inventory; skipped",
                        "kind": "blocked",
                    }
                )

    def tagged_kind(s, arn):
        if ":kms:" in arn:
            return "kms"
        if ":logs:" in arn:
            return "logs"
        if ":codebuild:" in arn and ":project/" in arn:
            return "codebuild"
        if ":cloudtrail:" in arn and ":trail/" in arn:
            return "cloudtrail"
        if ":firehose:" in arn and ":deliverystream/" in arn:
            return "firehose"
        if ":elasticloadbalancing:" in arn and ":loadbalancer/" in arn:
            return "elb"
        if ":sns:" in arn:
            return "sns"
        if ":scheduler:" in arn:
            return "scheduler"
        if ":ec2:" in arn and ":elastic-ip/" in arn:
            return "eip"
        if ":ec2:" in arn and (":launch-template/" in arn or ":volume/" in arn):
            return "ec2-child"
        if ":ec2:" in arn and ":vpc-flow-log/" in arn:
            return "flow-log"
        return None

    def config(s, r):
        # Config has no resource tags.  Its ownership is proven only when BOTH the
        # recorder role and delivery bucket are independently selected resources.
        w = AWS(r, s.res)
        rec = w.run("configservice", "describe-configuration-recorders")
        chan = w.run("configservice", "describe-delivery-channels")
        if rec is False or chan is False:
            return
        buckets = {x[2] for x in s.items if x[1] in ("s3", "backend-s3")}
        for c in chan.get("DeliveryChannels", []):
            bucket = c.get("s3BucketName")
            for x in rec.get("ConfigurationRecorders", []):
                role = x.get("roleARN", "")
                name = role.rsplit("/", 1)[-1]
                tags = w.run("iam", "list-role-tags", "--role-name", name)
                if tags is False:
                    continue
                role_selected = any(own(tags.get("Tags"), s.depl, z) for z in s.regions)
                bucket_selected = bucket in buckets
                if bucket_selected and role_selected:
                    s.add(
                        r,
                        "config",
                        x.get("name", "default") + "|" + c.get("name", "default"),
                        s.config_delete,
                    )
                elif bucket_selected != role_selected:
                    s.res.append(
                        {
                            "region": r,
                            "resource": "config:" + x.get("name", "default"),
                            "error": "Config partially matches selected dependency; ownership cannot be proven",
                            "kind": "blocked",
                        }
                    )

    def scheduler(s, r):
        w = AWS(r, s.res)
        roles = {x[2] for x in s.items if x[1] == "iam"}
        for group in w.pages("scheduler", "list-schedule-groups", "ScheduleGroups"):
            g = group.get("Name")
            for item in w.pages(
                "scheduler", "list-schedules", "Schedules", "--group-name", g
            ):
                name = item.get("Name")
                d = w.run(
                    "scheduler", "get-schedule", "--group-name", g, "--name", name
                )
                role = (
                    ""
                    if d is False
                    else d.get("Target", {}).get("RoleArn", "").rsplit("/", 1)[-1]
                )
                if role in roles:
                    s.add(r, "scheduler-native", g + "|" + name, s.scheduler_delete)
                # Schedules are untaggable.  A foreign target role is not an
                # owned candidate and must be left entirely out of this run.

    def scheduler_delete(s, i):
        group, name = i[2].split("|", 1)
        w = AWS(i[0], s.res)
        d = w.run("scheduler", "get-schedule", "--group-name", group, "--name", name)
        role = (
            ""
            if d is False
            else d.get("Target", {}).get("RoleArn", "").rsplit("/", 1)[-1]
        )
        roles = {x[2] for x in s.items if x[1] == "iam"}
        tags = w.run("iam", "list-role-tags", "--role-name", role) if role else False
        if (
            role not in roles
            or tags is False
            or not any(own(tags.get("Tags"), s.depl, region) for region in s.regions)
        ):
            s.res.append(
                {
                    "region": i[0],
                    "resource": i[2],
                    "error": "schedule target role changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        s.mut(i, "scheduler", "delete-schedule", "--group-name", group, "--name", name)

    def config_delete(s, i):
        recorder, channel = i[2].split("|", 1)
        s.mut(
            i,
            "configservice",
            "stop-configuration-recorder",
            "--configuration-recorder-name",
            recorder,
        )
        s.mut(
            i,
            "configservice",
            "delete-configuration-recorder",
            "--configuration-recorder-name",
            recorder,
        )
        s.mut(
            i,
            "configservice",
            "delete-delivery-channel",
            "--delivery-channel-name",
            channel,
        )

    def unsupported(s, i):
        arn = i[2]
        if not s.a.execute:
            s.res.append(
                {
                    "region": i[0],
                    "resource": arn,
                    "error": "tagged resource is planned for allow-listed cleanup on --execute",
                    "kind": "planned",
                }
            )
            return
        if ":kms:" in arn:
            t = AWS(i[0], s.res).run("kms", "list-resource-tags", "--key-id", arn)
            if t is False or not own(t.get("Tags"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": arn,
                        "error": "KMS ownership changed since inventory",
                        "kind": "blocked",
                    }
                )
                return
            key = AWS(i[0], s.res).run("kms", "describe-key", "--key-id", arn)
            if (
                key is not False
                and key.get("KeyMetadata", {}).get("KeyState") == "PendingDeletion"
            ):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": arn,
                        "error": "KMS key is pending scheduled deletion",
                        "kind": "pending",
                    }
                )
                return
            s.mut(
                i,
                "kms",
                "schedule-key-deletion",
                "--key-id",
                arn,
                "--pending-window-in-days",
                "7",
            )
            return
        # Discovery is not authority to mutate. Re-read the exact resource's tags
        # immediately before every RGTA-dispatched deletion.
        check = AWS(i[0], s.res).run(
            "resourcegroupstaggingapi", "get-resources", "--resource-arn-list", arn
        )
        mappings = [] if check is False else check.get("ResourceTagMappingList", [])
        if len(mappings) != 1 or not own(mappings[0].get("Tags"), s.depl):
            s.res.append(
                {
                    "region": i[0],
                    "resource": arn,
                    "error": "current ownership tags missing or changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        # Services below arrive through RGTA.  Dispatch remains allow-listed; an ARN
        # never becomes an instruction merely because it has a familiar name.
        if ":logs:" in arn:
            name = arn.split(":log-group:", 1)[-1].split(":*", 1)[0]
            s.mut(i, "logs", "delete-log-group", "--log-group-name", name)
            return
        if ":codebuild:" in arn and ":project/" in arn:
            name = arn.rsplit(":project/", 1)[1]
            s.mut(i, "codebuild", "delete-webhook", "--project-name", name)
            s.mut(i, "codebuild", "delete-project", "--name", name)
            return
        if ":cloudtrail:" in arn and ":trail/" in arn:
            name = arn.rsplit(":trail/", 1)[1]
            s.mut(i, "cloudtrail", "stop-logging", "--name", name)
            s.mut(i, "cloudtrail", "delete-trail", "--name", name)
            return
        if ":firehose:" in arn and ":deliverystream/" in arn:
            name = arn.rsplit(":deliverystream/", 1)[1]
            s.mut(
                i, "firehose", "delete-delivery-stream", "--delivery-stream-name", name
            )
            s.wait(
                i,
                "firehose",
                "describe-delivery-stream",
                "--delivery-stream-name",
                name,
            )
            return
        if ":sns:" in arn:
            s.mut(i, "sns", "delete-topic", "--topic-arn", arn)
            return
        if ":scheduler:" in arn and ":schedule/" in arn:
            # ARN suffix is schedule-group/schedule-name.  Individual schedules are
            # safe only because RGTA gave us exact ownership tags.
            pair = arn.rsplit(":schedule/", 1)[1].split("/", 1)
            if len(pair) == 2:
                s.mut(
                    i,
                    "scheduler",
                    "delete-schedule",
                    "--group-name",
                    pair[0],
                    "--name",
                    pair[1],
                )
                return
        if ":scheduler:" in arn and ":schedule-group/" in arn:
            group = arn.rsplit(":schedule-group/", 1)[1]
            s.mut(i, "scheduler", "delete-schedule-group", "--name", group)
            return
        if ":elasticloadbalancing:" in arn and ":loadbalancer/" in arn:
            s.mut(i, "elbv2", "delete-load-balancer", "--load-balancer-arn", arn)
            s.wait(i, "elbv2", "describe-load-balancers", "--load-balancer-arns", arn)
            return
        if ":ec2:" in arn and ":launch-template/" in arn:
            s.mut(
                i,
                "ec2",
                "delete-launch-template",
                "--launch-template-id",
                arn.rsplit("/", 1)[1],
            )
            return
        if ":ec2:" in arn and ":volume/" in arn:
            # Only detached tagged EBS volumes may be removed; attachments are a parent
            # dependency and must be released by their selected instance/nodegroup.
            d = AWS(i[0], s.res).run(
                "ec2", "describe-volumes", "--volume-ids", arn.rsplit("/", 1)[1]
            )
            if d is not False and d.get("Volumes", [{}])[0].get("Attachments"):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": arn,
                        "error": "tagged EBS volume remains attached",
                        "kind": "blocked",
                    }
                )
            elif d is not False:
                s.mut(i, "ec2", "delete-volume", "--volume-id", arn.rsplit("/", 1)[1])
            return
        if ":ec2:" in arn and ":elastic-ip/" in arn:
            allocation = arn.rsplit("/", 1)[1]
            d = AWS(i[0], s.res).run(
                "ec2", "describe-addresses", "--allocation-ids", allocation
            )
            addresses = [] if d is False else d.get("Addresses", [])
            if len(addresses) != 1 or not own(addresses[0].get("Tags"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": arn,
                        "error": "EIP ownership changed since inventory",
                        "kind": "blocked",
                    }
                )
                return
            if addresses[0].get("AssociationId"):
                s.mut(
                    i,
                    "ec2",
                    "disassociate-address",
                    "--association-id",
                    addresses[0]["AssociationId"],
                )
            s.mut(i, "ec2", "release-address", "--allocation-id", allocation)
            return
        if ":ec2:" in arn and ":vpc-flow-log/" in arn:
            s.mut(i, "ec2", "delete-flow-logs", "--flow-log-ids", arn.rsplit("/", 1)[1])
            return
        if ":iam::" in arn and ":instance-profile/" in arn:
            s.instance_profile(i, arn.rsplit("/", 1)[1])
            return
        s.res.append(
            {
                "region": i[0],
                "resource": arn,
                "error": "unsupported tagged resource type; no generic deletion attempted",
                "kind": "blocked",
            }
        )

    def instance_profile(s, i, name=None):
        name = name or i[2]
        w = AWS(None, s.res)
        d = w.run("iam", "get-instance-profile", "--instance-profile-name", name)
        if d is False:
            return
        profile = d.get("InstanceProfile", {})
        tags = w.run(
            "iam", "list-instance-profile-tags", "--instance-profile-name", name
        )
        if tags is False or not any(
            own(tags.get("Tags"), s.depl, r) for r in s.regions
        ):
            s.res.append(
                {
                    "region": i[0],
                    "resource": name,
                    "error": "instance profile ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        roles = profile.get("Roles", [])
        selected = []
        for role in roles:
            tags = w.run("iam", "list-role-tags", "--role-name", role["RoleName"])
            if tags is False:
                return
            if not any(own(tags.get("Tags"), s.depl, r) for r in s.regions):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": name,
                        "error": "instance profile has foreign or unproven role",
                        "kind": "blocked",
                    }
                )
                return
            if (
                role.get("Arn") == s.caller_arn
                or role["RoleName"]
                == s.caller_arn.split(":assumed-role/", 1)[-1].split("/", 1)[0]
            ):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": name,
                        "error": "instance profile includes current caller role",
                        "kind": "blocked",
                    }
                )
                return
            selected.append(role["RoleName"])
        for role in selected:
            s.mut(
                i,
                "iam",
                "remove-role-from-instance-profile",
                "--instance-profile-name",
                name,
                "--role-name",
                role,
            )
        s.mut(i, "iam", "delete-instance-profile", "--instance-profile-name", name)

    def oidc(s, i):
        w = AWS(None, s.res)
        arn = i[2]
        d = w.run(
            "iam", "get-open-id-connect-provider", "--open-id-connect-provider-arn", arn
        )
        if d is False:
            return
        t = w.run(
            "iam",
            "list-open-id-connect-provider-tags",
            "--open-id-connect-provider-arn",
            arn,
        )
        if t is False or not any(own(t.get("Tags"), s.depl, r) for r in s.regions):
            s.res.append(
                {
                    "region": i[0],
                    "resource": arn,
                    "error": "OIDC provider ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        s.mut(
            i,
            "iam",
            "delete-open-id-connect-provider",
            "--open-id-connect-provider-arn",
            arn,
        )

    def mut(s, i, *q):
        AWS(i[0], s.res).run(*q, write=True, missing=True)

    def wait(s, i, *q):
        end = time.monotonic() + s.a.wait_seconds
        while time.monotonic() < end:
            n = len(s.res)
            d = AWS(i[0], s.res).run(*q, missing=True)
            if d is None and len(s.res) == n:
                return
            if d is False:
                return
            time.sleep(5)
        s.res.append(
            {
                "region": i[0],
                "resource": i[2],
                "error": "bounded wait timed out",
                "kind": "residual",
            }
        )

    def eks(s, i):
        w = AWS(i[0], s.res)
        n = i[2]
        tags = w.run(
            "eks",
            "list-tags-for-resource",
            "--resource-arn",
            f"arn:aws:eks:{i[0]}:{s.acct}:cluster/{n}",
        )
        if tags is False or not own(tags.get("tags"), s.depl):
            s.res.append(
                {
                    "region": i[0],
                    "resource": n,
                    "error": "EKS cluster ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        cluster = w.run("eks", "describe-cluster", "--name", n)
        cluster_sg = (
            ({} if cluster is False else cluster.get("cluster", {}))
            .get("resourcesVpcConfig", {})
            .get("clusterSecurityGroupId")
        )
        if cluster_sg:
            s.cluster_sgs.add(cluster_sg)
        for x in w.pages("eks", "list-nodegroups", "nodegroups", "--cluster-name", n):
            d = w.run(
                "eks", "describe-nodegroup", "--cluster-name", n, "--nodegroup-name", x
            )
            if d is not False and own(d.get("nodegroup", {}).get("tags"), s.depl):
                s.mut(
                    i,
                    "eks",
                    "delete-nodegroup",
                    "--cluster-name",
                    n,
                    "--nodegroup-name",
                    x,
                )
            else:
                s.res.append(
                    {
                        "region": i[0],
                        "resource": "nodegroup/" + x,
                        "error": "EKS child ownership unproven or foreign",
                        "kind": "blocked",
                    }
                )
        for x in w.pages(
            "eks", "list-fargate-profiles", "fargateProfileNames", "--cluster-name", n
        ):
            d = w.run(
                "eks",
                "describe-fargate-profile",
                "--cluster-name",
                n,
                "--fargate-profile-name",
                x,
            )
            if d is not False and own(d.get("fargateProfile", {}).get("tags"), s.depl):
                s.mut(
                    i,
                    "eks",
                    "delete-fargate-profile",
                    "--cluster-name",
                    n,
                    "--fargate-profile-name",
                    x,
                )
            else:
                s.res.append(
                    {
                        "region": i[0],
                        "resource": "fargate/" + x,
                        "error": "EKS child ownership unproven or foreign",
                        "kind": "blocked",
                    }
                )
        for x in w.pages("eks", "list-addons", "addons", "--cluster-name", n):
            d = w.run("eks", "describe-addon", "--cluster-name", n, "--addon-name", x)
            if d is not False and own(d.get("addon", {}).get("tags"), s.depl):
                s.mut(i, "eks", "delete-addon", "--cluster-name", n, "--addon-name", x)
            else:
                s.res.append(
                    {
                        "region": i[0],
                        "resource": "addon/" + x,
                        "error": "EKS addon ownership unproven or foreign",
                        "kind": "blocked",
                    }
                )
        for x in w.pages(
            "eks", "list-pod-identity-associations", "associations", "--cluster-name", n
        ):
            aid = x.get("associationId")
            d = w.run(
                "eks",
                "describe-pod-identity-association",
                "--cluster-name",
                n,
                "--association-id",
                aid,
            )
            a = {} if d is False else d.get("association", {})
            role = a.get("roleArn", "").rsplit("/", 1)[-1]
            tags = (
                w.run("iam", "list-role-tags", "--role-name", role) if role else False
            )
            if (
                not aid
                or not a.get("namespace")
                or not a.get("serviceAccount")
                or tags is False
                or not any(own(tags.get("Tags"), s.depl, z) for z in s.regions)
            ):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": "pod-identity/" + str(aid),
                        "error": "pod identity lacks selected cluster and owned role ancestry",
                        "kind": "blocked",
                    }
                )
            else:
                s.mut(
                    i,
                    "eks",
                    "delete-pod-identity-association",
                    "--cluster-name",
                    n,
                    "--association-id",
                    aid,
                )
        # Access entries have no independent tag surface; parent cluster ownership
        # plus exact list/cluster binding is the only safe ancestry proof.
        for x in w.pages(
            "eks", "list-access-entries", "accessEntries", "--cluster-name", n
        ):
            if ":role/aws-service-role/" in x or "AWSServiceRoleFor" in x:
                continue
            s.mut(
                i,
                "eks",
                "delete-access-entry",
                "--cluster-name",
                n,
                "--principal-arn",
                x,
            )
        end = time.monotonic() + s.a.wait_seconds
        while time.monotonic() < end:
            if (
                not list(
                    w.pages("eks", "list-nodegroups", "nodegroups", "--cluster-name", n)
                )
                and not list(
                    w.pages(
                        "eks",
                        "list-fargate-profiles",
                        "fargateProfileNames",
                        "--cluster-name",
                        n,
                    )
                )
                and not list(
                    w.pages("eks", "list-addons", "addons", "--cluster-name", n)
                )
                and not list(
                    w.pages(
                        "eks",
                        "list-pod-identity-associations",
                        "associations",
                        "--cluster-name",
                        n,
                    )
                )
            ):
                break
            time.sleep(5)
        else:
            s.res.append(
                {
                    "region": i[0],
                    "resource": n,
                    "error": "EKS children did not finish deletion before timeout",
                    "kind": "residual",
                }
            )
            return
        s.mut(i, "eks", "delete-cluster", "--name", n)
        s.wait(i, "eks", "describe-cluster", "--name", n)

    def instance(s, i):
        w = AWS(i[0], s.res)
        d = w.run("ec2", "describe-instances", "--instance-ids", i[2])
        if d is False:
            return
        found = [x for r in d.get("Reservations", []) for x in r.get("Instances", [])]
        if len(found) != 1 or not own(found[0].get("Tags"), s.depl):
            s.res.append(
                {
                    "region": i[0],
                    "resource": i[2],
                    "error": "EC2 ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        s.mut(i, "ec2", "terminate-instances", "--instance-ids", i[2])
        end = time.monotonic() + s.a.wait_seconds
        while time.monotonic() < end:
            d = w.run("ec2", "describe-instances", "--instance-ids", i[2], missing=True)
            if d is None:
                return
            if d is False:
                return
            now = [x for r in d.get("Reservations", []) for x in r.get("Instances", [])]
            if now and now[0].get("State", {}).get("Name") == "terminated":
                return
            time.sleep(5)
        s.res.append(
            {
                "region": i[0],
                "resource": i[2],
                "error": "instance termination timed out",
                "kind": "residual",
            }
        )

    def ec2child(s, i):
        w = AWS(i[0], s.res)
        ident = i[2]
        if ident.startswith("eipalloc-"):
            d = w.run("ec2", "describe-addresses", "--allocation-ids", ident)
            found = [] if d is False else d.get("Addresses", [])
            if len(found) != 1 or not own(found[0].get("Tags"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": ident,
                        "error": "EIP ownership changed since inventory",
                        "kind": "blocked",
                    }
                )
                return
            if found[0].get("AssociationId"):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": ident,
                        "kind": "blocked",
                        "error": "EIP still has a live attachment; retain it until its verified parent is removed",
                    }
                )
                return
            s.mut(i, "ec2", "release-address", "--allocation-id", ident)
            return
        checks = {
            "subnet-": ("describe-subnets", "Subnets", "SubnetId", "--subnet-ids"),
            "sg-": (
                "describe-security-groups",
                "SecurityGroups",
                "GroupId",
                "--group-ids",
            ),
            "vpce-": (
                "describe-vpc-endpoints",
                "VpcEndpoints",
                "VpcEndpointId",
                "--vpc-endpoint-ids",
            ),
            "rtb-": (
                "describe-route-tables",
                "RouteTables",
                "RouteTableId",
                "--route-table-ids",
            ),
            "eni-": (
                "describe-network-interfaces",
                "NetworkInterfaces",
                "NetworkInterfaceId",
                "--network-interface-ids",
            ),
            "acl-": (
                "describe-network-acls",
                "NetworkAcls",
                "NetworkAclId",
                "--network-acl-ids",
            ),
        }
        match = next(
            (v for prefix, v in checks.items() if ident.startswith(prefix)), None
        )
        if match is None:
            s.res.append(
                {
                    "region": i[0],
                    "resource": ident,
                    "error": "unsupported EC2 child identifier",
                    "kind": "blocked",
                }
            )
            return
        """legacy alternatives retained below for stable edit context
            ("describe-subnets", "Subnets", "SubnetId", "--subnet-ids"),
            ("describe-security-groups", "SecurityGroups", "GroupId", "--group-ids"),
            (
                "describe-vpc-endpoints",
                "VpcEndpoints",
                "VpcEndpointId",
                "--vpc-endpoint-ids",
            ),
            (
                "describe-route-tables",
                "RouteTables",
                "RouteTableId",
                "--route-table-ids",
            ),
            (
                "describe-network-interfaces",
                "NetworkInterfaces",
                "NetworkInterfaceId",
                "--network-interface-ids",
            ),
            (
                "describe-network-acls",
                "NetworkAcls",
                "NetworkAclId",
                "--network-acl-ids",
            ),
        )"""
        for op, key, idkey, flag in (match,):
            d = w.run("ec2", op, flag, ident)
            found = [] if d is False else d.get(key, [])
            if len(found) != 1:
                s.res.append(
                    {
                        "region": i[0],
                        "resource": ident,
                        "error": "EC2 child absent at exact native recheck",
                        "kind": "blocked",
                    }
                )
                return
            x = found[0]
            if not own(x.get("Tags") or x.get("TagSet"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": ident,
                        "error": "EC2 child ownership changed since inventory",
                        "kind": "blocked",
                    }
                )
                return
            if op == "describe-subnets":
                s.mut(i, "ec2", "delete-subnet", "--subnet-id", ident)
            elif op == "describe-security-groups":
                s.mut(i, "ec2", "delete-security-group", "--group-id", ident)
            elif op == "describe-vpc-endpoints":
                s.mut(i, "ec2", "delete-vpc-endpoints", "--vpc-endpoint-ids", ident)
            elif op == "describe-network-interfaces":
                if x.get("Status") != "available":
                    s.res.append(
                        {
                            "region": i[0],
                            "resource": ident,
                            "error": "tagged network interface is not available",
                            "kind": "blocked",
                        }
                    )
                else:
                    s.mut(
                        i,
                        "ec2",
                        "delete-network-interface",
                        "--network-interface-id",
                        ident,
                    )
            elif op == "describe-route-tables":
                if any(a.get("Main") for a in x.get("Associations", [])):
                    s.res.append(
                        {
                            "region": i[0],
                            "resource": ident,
                            "error": "tagged main route table is retained with its VPC",
                            "kind": "blocked",
                        }
                    )
                else:
                    for a in x.get("Associations", []):
                        if a.get("RouteTableAssociationId"):
                            s.mut(
                                i,
                                "ec2",
                                "disassociate-route-table",
                                "--association-id",
                                a["RouteTableAssociationId"],
                            )
                    s.mut(i, "ec2", "delete-route-table", "--route-table-id", ident)
            else:
                if x.get("IsDefault"):
                    s.res.append(
                        {
                            "region": i[0],
                            "resource": ident,
                            "error": "tagged default network ACL is retained with its VPC",
                            "kind": "blocked",
                        }
                    )
                else:
                    s.mut(i, "ec2", "delete-network-acl", "--network-acl-id", ident)
            return
        d = w.run("ec2", "describe-addresses", "--allocation-ids", ident)
        found = [] if d is False else d.get("Addresses", [])
        if len(found) == 1 and own(found[0].get("Tags"), s.depl):
            if found[0].get("AssociationId"):
                s.mut(
                    i,
                    "ec2",
                    "disassociate-address",
                    "--association-id",
                    found[0]["AssociationId"],
                )
            s.mut(i, "ec2", "release-address", "--allocation-id", ident)
            return
        s.res.append(
            {
                "region": i[0],
                "resource": ident,
                "error": "EC2 child is absent or ownership changed since inventory",
                "kind": "blocked",
            }
        )

    def ddb(s, i):
        w = AWS(i[0], s.res)
        d = w.run("dynamodb", "describe-table", "--table-name", i[2])
        arn = False if d is False else d.get("Table", {}).get("TableArn")
        t = (
            w.run("dynamodb", "list-tags-of-resource", "--resource-arn", arn)
            if arn
            else False
        )
        if t is False or not own(t.get("Tags"), s.depl):
            s.res.append(
                {
                    "region": i[0],
                    "resource": i[2],
                    "error": "DynamoDB ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        s.mut(i, "dynamodb", "delete-table", "--table-name", i[2])
        s.wait(i, "dynamodb", "describe-table", "--table-name", i[2])

    def ecr(s, i):
        w = AWS(i[0], s.res)
        d = w.run("ecr", "describe-repositories", "--repository-names", i[2])
        repo = [] if d is False else d.get("repositories", [])
        t = (
            w.run(
                "ecr",
                "list-tags-for-resource",
                "--resource-arn",
                repo[0].get("repositoryArn", ""),
            )
            if len(repo) == 1
            else False
        )
        if t is False or not own(t.get("tags"), s.depl):
            s.res.append(
                {
                    "region": i[0],
                    "resource": i[2],
                    "error": "ECR ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        s.mut(i, "ecr", "delete-repository", "--repository-name", i[2], "--force")
        s.wait(i, "ecr", "describe-repositories", "--repository-names", i[2])

    def role(s, i):
        w = AWS(None, s.res)
        n = i[2]
        d = w.run("iam", "get-role", "--role-name", n)
        role = {} if d is False else d.get("Role", {})
        t = w.run("iam", "list-role-tags", "--role-name", n)
        if t is False or not any(own(t.get("Tags"), s.depl, r) for r in s.regions):
            s.res.append(
                {
                    "region": i[0],
                    "resource": n,
                    "error": "IAM role ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        if (
            role.get("Arn") == s.caller_arn
            or n == s.caller_arn.split(":assumed-role/", 1)[-1].split("/", 1)[0]
        ):
            s.res.append(
                {
                    "region": i[0],
                    "resource": n,
                    "error": "refusing to delete current caller role",
                    "kind": "blocked",
                }
            )
            return
        for x in w.pages(
            "iam", "list-attached-role-policies", "AttachedPolicies", "--role-name", n
        ):
            s.mut(
                i,
                "iam",
                "detach-role-policy",
                "--role-name",
                n,
                "--policy-arn",
                x["PolicyArn"],
            )
        for x in w.pages("iam", "list-role-policies", "PolicyNames", "--role-name", n):
            s.mut(i, "iam", "delete-role-policy", "--role-name", n, "--policy-name", x)
        s.mut(i, "iam", "delete-role", "--role-name", n)
        s.wait(i, "iam", "get-role", "--role-name", n)

    def s3(s, i):
        w = AWS(i[0], s.res)
        name = i[2]
        mark = None
        version = None
        tags = w.run("s3api", "get-bucket-tagging", "--bucket", name)
        if (
            tags is False
            or not own(tags.get("TagSet"), s.depl)
            or (
                (i[1] == "backend-s3")
                != (
                    td(tags.get("TagSet")).get("Purpose") == "terraform-state-bootstrap"
                )
            )
        ):
            s.res.append(
                {
                    "region": i[0],
                    "resource": name,
                    "error": "S3 ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return
        key = upload = None
        while True:
            more = (["--key-marker", key] if key else []) + (
                ["--upload-id-marker", upload] if upload else []
            )
            d = w.run(
                "s3api",
                "list-multipart-uploads",
                "--bucket",
                name,
                "--no-paginate",
                *more,
            )
            if d is False:
                return
            for u in d.get("Uploads", []):
                s.mut(
                    i,
                    "s3api",
                    "abort-multipart-upload",
                    "--bucket",
                    name,
                    "--key",
                    u["Key"],
                    "--upload-id",
                    u["UploadId"],
                )
            if not d.get("IsTruncated"):
                break
            key, upload = d.get("NextKeyMarker"), d.get("NextUploadIdMarker")
            if not key or not upload:
                s.res.append(
                    {
                        "region": i[0],
                        "resource": name,
                        "error": "multipart pagination tokens missing",
                        "kind": "inventory",
                    }
                )
                return
        while True:
            more = (["--key-marker", mark] if mark else []) + (
                ["--version-id-marker", version] if version else []
            )
            d = w.run(
                "s3api",
                "list-object-versions",
                "--bucket",
                name,
                "--no-paginate",
                *more,
            )
            if d is False:
                return
            objs = [
                {"Key": x["Key"], "VersionId": x["VersionId"]}
                for x in d.get("Versions", []) + d.get("DeleteMarkers", [])
            ]
            if objs:
                for batch in (objs[n : n + 1000] for n in range(0, len(objs), 1000)):
                    deleted = w.run(
                        "s3api",
                        "delete-objects",
                        "--bucket",
                        name,
                        "--delete",
                        json.dumps({"Objects": batch, "Quiet": True}),
                        write=True,
                    )
                    if deleted is False:
                        return
                    for e in deleted.get("Errors", []):
                        s.res.append(
                            {
                                "region": i[0],
                                "resource": name,
                                "error": "S3 retained/denied " + str(e),
                                "kind": "residual",
                            }
                        )
                    if s.res:
                        return
            if not d.get("IsTruncated"):
                break
            mark, version = d.get("NextKeyMarker"), d.get("NextVersionIdMarker")
            if not mark or not version:
                s.res.append(
                    {
                        "region": i[0],
                        "resource": name,
                        "error": "S3 pagination tokens missing",
                        "kind": "inventory",
                    }
                )
                return
        s.mut(i, "s3api", "delete-bucket", "--bucket", name)
        s.wait(i, "s3api", "head-bucket", "--bucket", name)

    def vpc(s, i):
        w = AWS(i[0], s.res)
        v = i[2]
        current = w.run("ec2", "describe-vpcs", "--vpc-ids", v)
        if current is False or not own(
            current.get("Vpcs", [{}])[0].get("Tags"), s.depl
        ):
            s.res.append(
                {
                    "region": i[0],
                    "resource": v,
                    "error": "VPC ownership changed since inventory",
                    "kind": "blocked",
                }
            )
            return

        def get(op, key):
            flag = "--filter" if op == "describe-nat-gateways" else "--filters"
            field = (
                "attachment.vpc-id" if op == "describe-internet-gateways" else "vpc-id"
            )
            d = w.run("ec2", op, flag, f"Name={field},Values={v}")
            return [] if d is False else d.get(key, [])

        for x in get("describe-vpc-endpoints", "VpcEndpoints"):
            if not own(x.get("Tags"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["VpcEndpointId"],
                        "error": "unproven or foreign VPC descendant",
                        "kind": "blocked",
                    }
                )
            else:
                s.mut(
                    i,
                    "ec2",
                    "delete-vpc-endpoints",
                    "--vpc-endpoint-ids",
                    x["VpcEndpointId"],
                )
                s.wait(
                    i,
                    "ec2",
                    "describe-vpc-endpoints",
                    "--vpc-endpoint-ids",
                    x["VpcEndpointId"],
                )
        for x in get("describe-nat-gateways", "NatGateways"):
            if not own(x.get("Tags"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["NatGatewayId"],
                        "error": "unproven or foreign VPC descendant",
                        "kind": "blocked",
                    }
                )
            else:
                s.mut(
                    i,
                    "ec2",
                    "delete-nat-gateway",
                    "--nat-gateway-id",
                    x["NatGatewayId"],
                )
                # NAT deletion is asynchronous and releases ENIs/EIPs only after deleted.
                s.nat_wait(i, x["NatGatewayId"])
        for x in get("describe-internet-gateways", "InternetGateways"):
            if not own(x.get("Tags"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["InternetGatewayId"],
                        "error": "unproven or foreign VPC descendant",
                        "kind": "blocked",
                    }
                )
            else:
                s.mut(
                    i,
                    "ec2",
                    "detach-internet-gateway",
                    "--internet-gateway-id",
                    x["InternetGatewayId"],
                    "--vpc-id",
                    v,
                )
                s.mut(
                    i,
                    "ec2",
                    "delete-internet-gateway",
                    "--internet-gateway-id",
                    x["InternetGatewayId"],
                )
        for x in get("describe-route-tables", "RouteTables"):
            # Main tables disappear with the VPC; custom tables must go first.
            if not any(a.get("Main") for a in x.get("Associations", [])) and own(
                x.get("Tags"), s.depl
            ):
                for a in x.get("Associations", []):
                    if not a.get("Main") and a.get("RouteTableAssociationId"):
                        s.mut(
                            i,
                            "ec2",
                            "disassociate-route-table",
                            "--association-id",
                            a["RouteTableAssociationId"],
                        )
                s.mut(
                    i,
                    "ec2",
                    "delete-route-table",
                    "--route-table-id",
                    x["RouteTableId"],
                )
            elif not any(a.get("Main") for a in x.get("Associations", [])):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["RouteTableId"],
                        "error": "unproven or foreign VPC route table",
                        "kind": "blocked",
                    }
                )
        # EIPs are handled as separately owned resources after this VPC's NAT
        # gateways have reached deleted.  Releasing one here risks detaching a
        # live NAT allocation and duplicates the exact EIP recheck.
        for x in get("describe-network-interfaces", "NetworkInterfaces"):
            if x.get("Status") == "available" and own(
                x.get("TagSet") or x.get("Tags"), s.depl
            ):
                s.mut(
                    i,
                    "ec2",
                    "delete-network-interface",
                    "--network-interface-id",
                    x["NetworkInterfaceId"],
                )
            elif x.get("Status") == "available":
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["NetworkInterfaceId"],
                        "error": "unproven or foreign VPC descendant",
                        "kind": "blocked",
                    }
                )
        for x in get("describe-subnets", "Subnets"):
            if not own(x.get("Tags"), s.depl):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["SubnetId"],
                        "error": "unproven or foreign VPC descendant",
                        "kind": "blocked",
                    }
                )
            else:
                s.mut(i, "ec2", "delete-subnet", "--subnet-id", x["SubnetId"])
        for x in get("describe-network-acls", "NetworkAcls"):
            if x.get("IsDefault"):
                continue
            if not own(x.get("Tags"), s.depl) or x.get("Associations"):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["NetworkAclId"],
                        "kind": "blocked",
                        "error": "custom network ACL is unowned or still associated; retained",
                    }
                )
            else:
                s.mut(
                    i,
                    "ec2",
                    "delete-network-acl",
                    "--network-acl-id",
                    x["NetworkAclId"],
                )
        # EKS may create one untagged cluster security group.  It is eligible
        # only when captured from an exact, currently-owned cluster before its
        # deletion; all other untagged groups remain foreign.
        groups = [
            x
            for x in get("describe-security-groups", "SecurityGroups")
            if x.get("GroupName") != "default"
            and (own(x.get("Tags"), s.depl) or x.get("GroupId") in s.cluster_sgs)
        ]
        selected = {x["GroupId"] for x in groups}
        for group in groups:
            # Revoke only rules whose source group and referenced group are both
            # selected.  Foreign references remain a hard residual, never a guess.
            rules = w.run(
                "ec2",
                "describe-security-group-rules",
                "--filters",
                "Name=group-id,Values=" + group["GroupId"],
            )
            if rules is False:
                continue
            for rule in rules.get("SecurityGroupRules", []):
                ref = rule.get("ReferencedGroupInfo", {}).get("GroupId")
                if ref in selected and rule.get("SecurityGroupRuleId"):
                    op = (
                        "revoke-security-group-egress"
                        if rule.get("IsEgress")
                        else "revoke-security-group-ingress"
                    )
                    s.mut(
                        i,
                        "ec2",
                        op,
                        "--group-id",
                        group["GroupId"],
                        "--security-group-rule-ids",
                        rule["SecurityGroupRuleId"],
                    )
        for x in groups:
            s.mut(i, "ec2", "delete-security-group", "--group-id", x["GroupId"])
        for x in get("describe-security-groups", "SecurityGroups"):
            if (
                x.get("GroupName") != "default"
                and not own(x.get("Tags"), s.depl)
                and x.get("GroupId") not in s.cluster_sgs
            ):
                s.res.append(
                    {
                        "region": i[0],
                        "resource": x["GroupId"],
                        "error": "unproven or foreign VPC descendant",
                        "kind": "blocked",
                    }
                )
        s.mut(i, "ec2", "delete-vpc", "--vpc-id", v)

    def nat_wait(s, i, nat):
        end = time.monotonic() + s.a.wait_seconds
        while time.monotonic() < end:
            d = AWS(i[0], s.res).run(
                "ec2", "describe-nat-gateways", "--nat-gateway-ids", nat, missing=True
            )
            if d is None:
                return
            if d is False:
                return
            if all(x.get("State") == "deleted" for x in d.get("NatGateways", [])):
                return
            time.sleep(5)
        s.res.append(
            {
                "region": i[0],
                "resource": nat,
                "error": "NAT deletion timed out",
                "kind": "residual",
            }
        )

    def go(s):
        for r in s.regions:
            s.inventory(r)
        s.iam()
        for r in s.regions:
            s.scheduler(r)
        for r in s.regions:
            s.config(r)
        view = [{"region": x[0], "type": x[1], "id": x[2]} for x in s.items]
        print(
            json.dumps(
                {
                    "mode": "execute" if s.a.execute else "dry-run",
                    "account": s.acct,
                    "deployment": s.depl or "ALL_PROJECT_DEPLOYMENTS",
                    "resources": view,
                },
                indent=2,
            )
        )
        if s.a.execute:
            # A failed or incomplete inventory is never permission for a partial
            # teardown.  Operators get a residual report and can correct scope first.
            if s.res:
                print(
                    json.dumps({"status": "RESIDUAL", "residual": s.res}, indent=2),
                    file=sys.stderr,
                )
                return 2
            # Consumers disappear before their network, identity, and backend
            # dependencies.  Backends are deliberately skipped after *any* residual.
            order = {
                "codebuild": 0,
                "config": 1,
                "cloudtrail": 2,
                "firehose": 3,
                "elb": 4,
                "scheduler": 5,
                "scheduler-native": 5,
                "sns": 6,
                "logs": 7,
                "flow-log": 8,
                "eks": 10,
                "ec2-instance": 11,
                "ec2-child": 12,
                "ec2-native-child": 13,
                "vpc": 20,
                "eip": 25,
                "ecr": 30,
                "iam-profile": 40,
                "iam-oidc": 41,
                "iam": 42,
                "dynamodb": 60,
                "s3": 70,
                "backend-dynamodb": 91,
                "backend-s3": 92,
                "kms": 99,
            }
            verified_barriers = set()
            for i in sorted(s.items, key=lambda x: order[x[1]]):
                # Check actual absence before discarding recovery state/keys.
                barrier = (
                    "kms"
                    if i[1] == "kms"
                    else "backend" if i[1].startswith("backend-") else None
                )
                if barrier and barrier not in verified_barriers:
                    allowed = (
                        {"kms"}
                        if barrier == "kms"
                        else {"backend-dynamodb", "backend-s3", "kms"}
                    )
                    s.postflight(allowed)
                    verified_barriers.add(barrier)
                # KMS is intentionally final. Any failure retaining encrypted data means
                # it must remain usable; scheduling is not physical deletion.
                if i[1] in (
                    "dynamodb",
                    "s3",
                    "backend-dynamodb",
                    "backend-s3",
                    "kms",
                ) and any(x.get("kind") != "pending" for x in s.res):
                    continue
                i[3](i)
            s.postflight()
        else:
            # Dry run is an inventory with a failure signal for resources for which
            # this tool deliberately has no safe implementation.
            for i in s.items:
                if i[1] == "tagged-arn":
                    s.unsupported(i)
        bad = [x for x in s.res if x.get("kind") not in ("planned", "pending")]
        if bad:
            print(
                json.dumps({"status": "RESIDUAL", "residual": s.res}, indent=2),
                file=sys.stderr,
            )
            return 2
        if s.res:
            print(
                json.dumps({"status": "PLAN", "resources": s.res}, indent=2),
                file=sys.stderr,
            )
        if s.a.execute and any(x.get("kind") == "pending" for x in s.res):
            print("STATUS: PENDING_DELETION")
            return 0
        print(
            "STATUS: CLEANUP COMPLETE"
            if s.a.execute
            else "STATUS: CLEAN (dry-run only)"
        )
        return 0

    def postflight(s, allowed=()):
        # A second independent inventory is required before success.  KMS is the
        # sole expected retained resource: PendingDeletion is explicitly reported.
        again = Clean(s.a, s.acct, s.regions, s.caller_arn)
        for r in again.regions:
            again.inventory(r)
        again.iam()
        for r in again.regions:
            again.scheduler(r)
        for r in again.regions:
            again.config(r)
        s.res.extend(again.res)
        for i in again.items:
            if i[1] in allowed:
                continue
            if i[1] == "kms":
                d = AWS(i[0], s.res).run("kms", "describe-key", "--key-id", i[2])
                if (
                    d is not False
                    and d.get("KeyMetadata", {}).get("KeyState") == "PendingDeletion"
                ):
                    s.res.append(
                        {
                            "region": i[0],
                            "resource": i[2],
                            "error": "KMS key is pending scheduled deletion",
                            "kind": "pending",
                        }
                    )
                    continue
            s.res.append(
                {
                    "region": i[0],
                    "resource": i[2],
                    "error": "resource remains after cleanup postflight rescan",
                    "kind": "residual",
                }
            )


def main():
    a = cli()
    res = []
    d = AWS(None, res).run("sts", "get-caller-identity")
    if d is False:
        print(json.dumps({"status": "RESIDUAL", "residual": res}), file=sys.stderr)
        return 2
    if a.execute and d.get("Account") != a.account:
        fail("--account does not match caller account", 77)
    if a.all_regions:
        q = AWS(None, res).run("ec2", "describe-regions", "--all-regions")
        rs = (
            []
            if q is False
            else [
                x["RegionName"]
                for x in q.get("Regions", [])
                if x.get("OptInStatus") in (None, "opt-in-not-required", "opted-in")
            ]
        )
        if res:
            print(json.dumps({"status": "RESIDUAL", "residual": res}), file=sys.stderr)
            return 2
    else:
        rs = a.region
    return Clean(a, d["Account"], rs, d.get("Arn", "")).go()


raise SystemExit(main())
PY
