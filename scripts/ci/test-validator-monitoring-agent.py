#!/usr/bin/env python3
"""Hermetic CloudWatch Agent scrape-to-EMF proof; never contacts AWS."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
STUB = ROOT / "scripts/ci/fixtures/validator-monitoring-stub.py"
AGENT = "amazon/cloudwatch-agent@sha256:f5680928b37cd5afacb5fd3de1b7ef7bfba57976f4f8b4227b49615467460cf2"
# Existing local RepoDigest for the hermetic protocol-stub runtime.  The test
# inspects it and never pulls an image.
PYTHON_IMAGE = "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
KEY = "0x" + "a" * 96


def command(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=30, **kwargs)


def require_local(image):
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"required local image unavailable: {image}")


def build_test_config():
    spec = importlib.util.spec_from_file_location("monitoring_config", ROOT / "scripts/release/validator_monitoring_config.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    config = module.build_config("test-monitor", "ap-northeast-2", "hoodi-test", KEY)
    config["prometheus"]["global"]["scrape_interval"] = "1s"
    config["prometheus"]["global"]["scrape_timeout"] = "1s"
    for job, target in zip(config["prometheus"]["scrape_configs"], ("beacon.stub:8080", "execution.stub:8080", "validator.stub:8080")):
        job["static_configs"][0]["targets"] = [target]
    config["cwagent"]["logs"]["endpoint_override"] = "http://stub:8080"
    return config


def flattened_events(record):
    events = []
    if not record.exists():
        return events
    for line in record.read_text().splitlines():
        events.extend(json.loads(line).get("events", []))
    return events


def proof_complete(events):
    emf = [event for event in events if metric_declarations(event)]
    components = {event.get("Component") for event in emf}
    counters = [event["validator_successful_attestations"] for event in emf if "validator_successful_attestations" in event]
    return {"beacon", "execution", "validator"} <= components and len(counters) >= 2


def metric_declarations(event):
    # This pinned Agent uses legacy EMF v0 plus the json/emf request header.
    # Modern EMF embeds the same declarations under _aws.
    metadata = event if event.get("Version") == "0" else event.get("_aws", {})
    return metadata.get("CloudWatchMetrics", [])


def scrape_count(record):
    if not record.exists():
        return 0
    return sum(1 for line in record.read_text().splitlines() if json.loads(line).get("request") == "scrape")


def post_targets(record):
    if not record.exists():
        return []
    return [json.loads(line).get("target", "") for line in record.read_text().splitlines() if json.loads(line).get("request") == "post"]


class AgentProof(unittest.TestCase):
    def test_agent_scrapes_and_emits_allowlisted_emf(self):
        require_local(AGENT)
        require_local(PYTHON_IMAGE)
        config = build_test_config()
        with tempfile.TemporaryDirectory(prefix="validator-monitoring-agent-") as temp:
            base = Path(temp)
            record = base / "records.jsonl"
            network = f"validator-monitoring-{uuid.uuid4().hex[:12]}"
            created = []
            try:
                command("network", "create", "--internal", network); created.append(("network", network))
                stub = command("run", "-d", "--network", network, "--network-alias", "stub", "--network-alias", "beacon.stub",
                    "--network-alias", "execution.stub", "--network-alias", "validator.stub",
                    "--mount", f"type=bind,src={STUB},dst=/stub.py,readonly",
                    "--mount", f"type=bind,src={base},dst=/records", PYTHON_IMAGE, "python", "/stub.py", "/records/records.jsonl").stdout.strip()
                created.append(("container", stub))
                agent = command("run", "-d", "--platform", "linux/amd64", "--network", network, "--read-only", "--user", "1000:1000",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0750",
                    "--tmpfs", "/opt/aws/amazon-cloudwatch-agent/etc:rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0750",
                    "--tmpfs", "/opt/aws/amazon-cloudwatch-agent/logs:rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0750",
                    "--tmpfs", "/opt/aws/amazon-cloudwatch-agent/var:rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0750",
                    "-e", "AWS_ACCESS_KEY_ID=testing", "-e", "AWS_SECRET_ACCESS_KEY=testing", "-e", "AWS_EC2_METADATA_DISABLED=true",
                    "-e", "RUN_IN_AWS=True",
                    "-e", "PROMETHEUS_CONFIG_CONTENT=" + json.dumps(config["prometheus"], separators=(",", ":")),
                    "-e", "CW_CONFIG_CONTENT=" + json.dumps(config["cwagent"], separators=(",", ":")), AGENT).stdout.strip()
                created.append(("container", agent))
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    events = flattened_events(record)
                    if proof_complete(events):
                        break
                    time.sleep(1)
                else:
                    log_result = command("logs", agent)
                    logs = (log_result.stdout + log_result.stderr)[-4000:]
                    scrapes = scrape_count(record)
                    posts = post_targets(record)
                    state = command("inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", agent).stdout.strip()
                    runtime = command("inspect", "--format", "path={{.Path}} args={{json .Args}} mounts={{json .Mounts}}", agent).stdout[-2000:]
                    copied = subprocess.run(
                        ["docker", "cp", f"{agent}:/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log", str(base / "agent.log")],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    file_log = (base / "agent.log").read_text(errors="replace")[-4000:] if copied.returncode == 0 else "agent file log unavailable"
                    translated = base / "amazon-cloudwatch-agent.toml"
                    copied_toml = subprocess.run(
                        ["docker", "cp", f"{agent}:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml", str(translated)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    yaml_path = base / "amazon-cloudwatch-agent.yaml"
                    copied_yaml = subprocess.run(
                        ["docker", "cp", f"{agent}:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.yaml", str(yaml_path)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    copied_etc = subprocess.run(
                        ["docker", "cp", f"{agent}:/opt/aws/amazon-cloudwatch-agent/etc/.", str(failure_dir := Path(tempfile.mkdtemp(prefix="validator-monitoring-agent-failure-")))],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    toml_text = translated.read_text(errors="replace") if copied_toml.returncode == 0 else ""
                    yaml_text = yaml_path.read_text(errors="replace") if copied_yaml.returncode == 0 else ""
                    endpoint_seen = "stub:8080" in toml_text or "stub:8080" in yaml_text
                    toml_summary = " | ".join(
                        line.strip() for line in (toml_text + "\n" + yaml_text).splitlines()
                        if any(token in line.lower() for token in ("prometheus", "logs", "endpoint", "outputs"))
                    )[-2000:]
                    for source in (translated, yaml_path, base / "agent.log", record):
                        if source.exists():
                            destination = failure_dir / source.name
                            destination.write_text(source.read_text(errors="replace").replace(KEY, "[public-key]").replace("testing", "[test-credential]"))
                    for source in failure_dir.rglob("*"):
                        if source.is_file():
                            source.write_text(source.read_text(errors="replace").replace(KEY, "[public-key]").replace("testing", "[test-credential]"))
                    self.fail(
                        f"agent emitted no EMF to local Logs stub after {scrapes} scrapes and {len(posts)} POSTs {posts[:3]} "
                        f"(state {state}; translated endpoint={endpoint_seen}; diagnostics={failure_dir}): "
                        + (logs + "\n" + file_log + "\nruntime: " + runtime + "\ntranslated: " + toml_summary
                           + "\ncopy errors: " + copied_toml.stderr + " | " + copied_yaml.stderr + " | " + copied_etc.stderr).replace(KEY, "[public-key]")[-8000:]
                    )
                emf = [event for event in events if metric_declarations(event)]
                for line in record.read_text().splitlines():
                    request = json.loads(line)
                    if request.get("events"):
                        self.assertEqual(request["format"], "json/emf")
                encoded = json.dumps(emf)
                self.assertIn("NodeOperator/Validator", encoded)
                self.assertIn("validator_balance", encoded)
                self.assertIn("validator_successful_attestations", encoded)
                self.assertNotIn("unapproved_metric", encoded)
                self.assertNotIn("pubkey", encoded)
                self.assertNotIn("cwagent_saved_scrape_", encoded)
                balances = [event["validator_balance"] for event in emf if "validator_balance" in event]
                self.assertTrue(balances)
                self.assertTrue(all(value == 32 for value in balances), balances)
                for event in emf:
                    for group in metric_declarations(event):
                        self.assertEqual(group["Namespace"], "NodeOperator/Validator")
                        self.assertEqual(len(group["Dimensions"]), 1)
                        self.assertCountEqual(group["Dimensions"][0], ["Deployment", "Network", "ValidatorSet", "Component"])
                counters = [event["validator_successful_attestations"] for event in emf if "validator_successful_attestations" in event]
                self.assertGreaterEqual(len(counters), 2)
                self.assertTrue(all(value == 1 for value in counters[1:]), counters)
            finally:
                cleanup_errors = []
                for kind, identifier in reversed(created):
                    remove = ["docker", "rm", "-f", identifier] if kind == "container" else ["docker", "network", "rm", identifier]
                    result = subprocess.run(remove, capture_output=True, text=True, timeout=30)
                    inspect = subprocess.run(["docker", "container" if kind == "container" else "network", "inspect", identifier], capture_output=True, text=True, timeout=30)
                    if result.returncode or inspect.returncode == 0:
                        cleanup_errors.append(f"{kind} cleanup failed for {identifier[:12]}")
                if cleanup_errors:
                    raise RuntimeError("; ".join(cleanup_errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-external-local", action="store_true")
    args, remaining = parser.parse_known_args()
    if args.skip_external_local:
        print("SKIP explicit local Docker proof (not a passing ingestion result)")
    else:
        unittest.main(argv=[sys.argv[0], *remaining])
