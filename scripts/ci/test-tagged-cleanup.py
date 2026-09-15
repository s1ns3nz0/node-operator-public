#!/usr/bin/env python3
# Check objective: Validate the tag-safe cleanup entry point.
"""Offline contract tests for the tag-safe cleanup entry point."""

import contextlib, io, json, os, pathlib, subprocess, tempfile, unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/delete-all-node-operator-resources.sh"
FAKE = """#!/usr/bin/env python3
import json,sys
a=sys.argv[1:]; env=__import__('os').environ; log=env['AWS_LOG'];open(log,'a').write(' '.join(a)+'\\n'); case=env.get('CASE','kms')
def out(x): print(json.dumps(x))
tags=[{'Key':'Project','Value':'node-operator'},{'Key':'ManagedBy','Value':'terraform'},{'Key':'Deployment','Value':'dev'},{'Key':'DeploymentRegion','Value':'us-east-1'}]
if a[:2]==['sts','get-caller-identity']:out({'Account':'111111111111','Arn':'arn:aws:iam::111111111111:role/current'})
elif a[:2]==['resourcegroupstaggingapi','get-resources']:
 arn={'kms':'arn:aws:kms:us-east-1:111111111111:key/x','unsupported':'arn:aws:lambda:us-east-1:111111111111:function:x','codebuild':'arn:aws:codebuild:us-east-1:111111111111:project/x','eip':'arn:aws:ec2:us-east-1:111111111111:elastic-ip/eipalloc-x','flow':'arn:aws:ec2:us-east-1:111111111111:vpc-flow-log/fl-x'}.get(case,'arn:aws:kms:us-east-1:111111111111:key/x')
 out({'ResourceTagMappingList':([{'ResourceARN':arn,'Tags':tags}] if '--pagination-token' not in a else []),'PaginationToken':('p2' if '--pagination-token' not in a else '')})
elif a[:2]==['eks','list-clusters']:out({'clusters':[]})
elif a[:2]==['ecr','describe-repositories']:out({'repositories':[]})
elif a[:2]==['ec2','describe-vpcs']:out({'Vpcs':[]})
elif a[:2]==['ec2','describe-addresses']:out({'Addresses':([{'AllocationId':'eipalloc-x','Tags':tags}] if case=='eip' else [])})
elif a[:2]==['s3api','list-buckets']:out({'Buckets':[]})
elif a[:2]==['iam','list-roles']:out({'Roles':[]})
elif a[:2]==['kms','list-resource-tags']:out({'Tags':([{'TagKey':x['Key'],'TagValue':x['Value']} for x in tags] if case=='kms_shape' else tags)})
elif a[:2]==['kms','describe-key']:
 out({'KeyMetadata':{'KeyState':('PendingDeletion' if 'schedule-key-deletion' in open(log).read() or case=='kms_pending' else 'Enabled')}})
else: out({})
"""


class TestTaggedCleanup(unittest.TestCase):
    def invoke(self, *args, case="kms"):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            aws = p / "aws"
            aws.write_text(FAKE)
            aws.chmod(0o755)
            log = p / "log"
            env = {
                **os.environ,
                "PATH": str(p) + os.pathsep + os.environ["PATH"],
                "AWS_LOG": str(log),
                "CASE": case,
            }
            q = subprocess.run(
                [str(SCRIPT), *args], text=True, capture_output=True, env=env
            )
            return q, (log.read_text() if log.exists() else "")

    def test_dry_run_never_mutates_and_paginates(self):
        q, log = self.invoke("--deployment", "dev", "--region", "us-east-1")
        self.assertEqual(
            q.returncode, 0
        )  # planned KMS is inventory, not a mutation failure
        self.assertNotIn(" delete-", log)
        self.assertIn("--pagination-token p2", log)

    def test_execute_requires_account_confirmation(self):
        q, _ = self.invoke("--deployment", "dev", "--region", "us-east-1", "--execute")
        self.assertEqual(q.returncode, 64)
        self.assertIn("--account", q.stderr)

    def test_wrong_account_refuses_before_mutation(self):
        q, log = self.invoke(
            "--deployment",
            "dev",
            "--region",
            "us-east-1",
            "--execute",
            "--account",
            "222222222222",
        )
        self.assertEqual(q.returncode, 77)
        self.assertNotIn("delete-", log)

    def test_kms_uses_explicit_seven_day_pending_deletion(self):
        q, log = self.invoke(
            "--all-project-deployments",
            "--region",
            "us-east-1",
            "--execute",
            "--account",
            "111111111111",
        )
        self.assertEqual(q.returncode, 0)
        self.assertIn("schedule-key-deletion", log)
        self.assertIn("--pending-window-in-days 7", log)

    def test_kms_real_tagkey_tagvalue_shape_is_accepted(self):
        q, log = self.invoke(
            "--deployment",
            "dev",
            "--region",
            "us-east-1",
            "--execute",
            "--account",
            "111111111111",
            case="kms_shape",
        )
        self.assertEqual(q.returncode, 0)
        self.assertIn("schedule-key-deletion", log)
        self.assertIn("STATUS: PENDING_DELETION", q.stdout)

    def test_unsupported_tagged_resource_is_preflight_blocked_not_planned(self):
        q, log = self.invoke(
            "--deployment", "dev", "--region", "us-east-1", case="unsupported"
        )
        self.assertEqual(q.returncode, 2)
        self.assertIn("unsupported tagged resource type", q.stderr)
        self.assertNotIn("delete-", log)

    def test_execute_blocks_before_mutation_for_unsupported_resource(self):
        q, log = self.invoke(
            "--deployment",
            "dev",
            "--region",
            "us-east-1",
            "--execute",
            "--account",
            "111111111111",
            case="unsupported",
        )
        self.assertEqual(q.returncode, 2)
        self.assertNotIn("delete-", log)

    def test_known_consumer_is_dispatched_before_infrastructure_order(self):
        q, log = self.invoke(
            "--deployment",
            "dev",
            "--region",
            "us-east-1",
            "--execute",
            "--account",
            "111111111111",
            case="codebuild",
        )
        self.assertEqual(q.returncode, 2)
        self.assertIn("delete-project --name x", log)
        self.assertIn("postflight rescan", q.stderr)

    def test_source_has_native_rechecks_and_dependency_guards(self):
        text = SCRIPT.read_text()
        for required in (
            "DynamoDB ownership changed since inventory",
            "ECR ownership changed since inventory",
            "refusing to delete current caller role",
            "list-instance-profile-tags",
            "list-open-id-connect-provider-tags",
            "disassociate-route-table",
            "describe-security-group-rules",
            "list-pod-identity-associations",
            "s.postflight()",
        ):
            self.assertIn(required, text)

    def test_backend_and_kms_are_skipped_after_any_residual(self):
        calls, result = self.run_order_case(retained=True)
        self.assertEqual(result, 2)
        self.assertIn("audit-data", calls)
        for protected in ("state", "lock", "key"):
            self.assertNotIn(protected, calls)

    def run_order_case(self, retained=False):
        # Load the real embedded implementation without its CLI invocation; all
        # resource handlers below are deterministic, non-network fixture callbacks.
        namespace = {}
        source = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        source = source.replace("raise SystemExit(main())", "")
        exec(compile(source, str(SCRIPT), "exec"), namespace)
        cleaner = namespace["Clean"](
            SimpleNamespace(
                execute=True, deployment="dev", all_project_deployments=False
            ),
            "111111111111",
            ["us-east-1"],
        )
        calls = []

        def delete(item):
            calls.append(item[2])
            if retained and item[2] == "audit-data":
                cleaner.res.append(
                    {
                        "kind": "residual",
                        "resource": "audit-data",
                        "error": "Object Lock retains data",
                    }
                )

        # Deliberately reverse discovery order: deletion order cannot depend on it.
        cleaner.items = [
            ("us-east-1", kind, name, delete)
            for kind, name in (
                ("kms", "key"),
                ("backend-s3", "state"),
                ("backend-dynamodb", "lock"),
                ("s3", "audit-data"),
                ("eks", "cluster"),
            )
        ]
        cleaner.inventory = lambda region: None
        cleaner.iam = lambda: None
        cleaner.scheduler = lambda region: None
        cleaner.config = lambda region: None
        cleaner.postflight = lambda allowed=(): calls.append(
            "verify:" + ",".join(sorted(allowed))
        )
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            result = cleaner.go()
        return calls, result

    def test_state_and_kms_follow_data_deletion_and_absence_barriers(self):
        calls, result = self.run_order_case()
        self.assertEqual(result, 0)
        self.assertLess(calls.index("cluster"), calls.index("audit-data"))
        self.assertLess(calls.index("audit-data"), calls.index("lock"))
        self.assertLess(
            calls.index("verify:backend-dynamodb,backend-s3,kms"), calls.index("lock")
        )
        self.assertLess(calls.index("state"), calls.index("verify:kms"))
        self.assertLess(calls.index("verify:kms"), calls.index("key"))

    def test_attached_eip_is_preserved_without_disassociation(self):
        namespace = {}
        source = (
            SCRIPT.read_text()
            .split("<<'PY'\n", 1)[1]
            .rsplit("\nPY", 1)[0]
            .replace("raise SystemExit(main())", "")
        )
        exec(compile(source, str(SCRIPT), "exec"), namespace)
        calls = []
        tags = {
            "Project": "node-operator",
            "ManagedBy": "terraform",
            "Deployment": "dev",
        }

        class FakeAWS:
            def __init__(self, *args):
                pass

            def run(self, *args, **kwargs):
                calls.append(args)
                assert args[:2] == ("ec2", "describe-addresses"), args
                return {
                    "Addresses": [
                        {
                            "AllocationId": "eipalloc-x",
                            "AssociationId": "eipassoc-live",
                            "Tags": tags,
                        }
                    ]
                }

        namespace["AWS"] = FakeAWS
        cleaner = namespace["Clean"](
            SimpleNamespace(deployment="dev", all_project_deployments=False),
            "111111111111",
            ["us-east-1"],
        )
        cleaner.ec2child(("us-east-1", "eip", "eipalloc-x", None))
        self.assertEqual(len(calls), 1)
        self.assertEqual(cleaner.res[0]["kind"], "blocked")

    def test_owned_vpc_children_are_not_duplicated_but_external_children_remain_visible(
        self,
    ):
        namespace = {}
        source = (
            SCRIPT.read_text()
            .split("<<'PY'\n", 1)[1]
            .rsplit("\nPY", 1)[0]
            .replace("raise SystemExit(main())", "")
        )
        exec(compile(source, str(SCRIPT), "exec"), namespace)
        tags = {
            "Project": "node-operator",
            "ManagedBy": "terraform",
            "Deployment": "dev",
        }

        class FakeAWS:
            def __init__(self, *args):
                pass

            def pages(self, *args):
                return iter(())

            def run(self, *args, **kwargs):
                if args[:2] == ("ec2", "describe-vpcs"):
                    return {"Vpcs": [{"VpcId": "vpc-owned", "Tags": tags}]}
                if args[:2] == ("ec2", "describe-subnets"):
                    return {
                        "Subnets": [
                            {
                                "SubnetId": "subnet-owned",
                                "VpcId": "vpc-owned",
                                "Tags": tags,
                            },
                            {
                                "SubnetId": "subnet-external",
                                "VpcId": "vpc-external",
                                "Tags": tags,
                            },
                        ]
                    }
                return {}

        namespace["AWS"] = FakeAWS
        cleaner = namespace["Clean"](
            SimpleNamespace(deployment="dev", all_project_deployments=False),
            "111111111111",
            ["us-east-1"],
        )
        cleaner.inventory("us-east-1")
        ids = [item[2] for item in cleaner.items]
        self.assertIn("vpc-owned", ids)
        self.assertNotIn("subnet-owned", ids)
        self.assertIn("subnet-external", ids)

    def test_baseline_eip_is_allowlisted_not_preflight_unsupported(self):
        q, log = self.invoke("--deployment", "dev", "--region", "us-east-1", case="eip")
        self.assertEqual(q.returncode, 0)
        self.assertIn("eipalloc-x", q.stdout)
        self.assertNotIn("unsupported tagged resource type", q.stderr)
        self.assertNotIn("release-address", log)
        self.assertEqual(q.stdout.count('"id": "eipalloc-x"'), 1)

    def test_baseline_flow_log_runs_before_network_teardown(self):
        q, log = self.invoke(
            "--deployment",
            "dev",
            "--region",
            "us-east-1",
            "--execute",
            "--account",
            "111111111111",
            case="flow",
        )
        self.assertEqual(q.returncode, 2)
        self.assertIn("delete-flow-logs --flow-log-ids fl-x", log)

    def test_terminated_instances_and_external_vpc_children_are_not_hidden(self):
        text = SCRIPT.read_text()
        self.assertIn('get("Name") != "terminated"', text)
        self.assertIn('"describe-network-acls"', text)
        self.assertIn("Independently tagged EC2 children", text)
        self.assertIn("PENDING_DELETION", text)
        self.assertIn("ident.startswith(prefix)", text)


if __name__ == "__main__":
    unittest.main()
