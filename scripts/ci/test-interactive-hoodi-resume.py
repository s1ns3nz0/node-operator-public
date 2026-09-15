#!/usr/bin/env python3
# Check objective: prove WORK_DIR resumes only infrastructure through the actual wrapper branch.
import errno, hashlib, json, os, pathlib, pty, select, shutil, signal, subprocess, tempfile, time, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/release/interactive-hoodi-release.sh"
HELPER = ROOT / "scripts/release/interactive-hoodi-resume.py"
ACCOUNT, REGION, DEPLOYMENT = "123456789012", "ap-northeast-2", "node-op-123"


def authority():
    rows = []
    for component, repository, digit in (
        ("web3signer", "runtime-web3signer", "1"), ("postgres", "runtime-postgres", "2"),
        ("prysm-validator", "runtime-prysm", "3"), ("validator-signing-fence", "runtime-fence", "4"),
        ("argocd-bootstrap", "gitops-argocd", "5"), ("vault-bootstrap", "gitops-vault", "6"),
        ("node-operator-client-chart", "gitops-client/chart", "7"),
    ):
        digest = "sha256:" + digit * 64
        row = {"component": component, "required": True, "source": f"approved.example/{repository}@{digest}", "destination": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{DEPLOYMENT}-{repository}@{digest}"}
        if component == "node-operator-client-chart": row["destination_tag"] = "0.1.37"
        rows.append(row)
    return json.dumps({"schema_version": 1, "complete": True, "artifacts": rows})


class ResumeWrapper(unittest.TestCase):
    def fixture(self):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        source = d / "source"
        rel = source / "scripts/release"
        rel.mkdir(parents=True)
        (d / "bundle-manifest.json").write_text(
            '{"schema_version":"v1","source_revision":"' + "a" * 40 + '","entries":[]}\n'
        )
        for src, name in (
            (WRAPPER, "interactive-hoodi-release.sh"),
            (HELPER, "interactive-hoodi-resume.py"),
        ):
            target = rel / name
            shutil.copy(src, target)
            target.chmod(0o755)
        for name in (
            "prepare-hoodi-zero-release-inputs.sh",
            "prepare-vault-bootstrap-tls.sh",
            "verify-existing-hoodi-validator.py",
            "node-operator-release.sh",
        ):
            p = rel / name
            p.write_text(
                '#!/usr/bin/env bash\necho "$@" >> "$RESUME_LOG"\nif [ "${1:-}" = deploy ]; then exit "${DEPLOY_RC:-0}"; fi\nexit 0\n'
            )
            p.chmod(0o755)
        deploy = rel / "hoodi-validator-release.sh"
        deploy.write_text('#!/usr/bin/env bash\necho "$@" >> "$RESUME_LOG"\nif [ "${1:-}" = deploy ]; then work=""; while [ "$#" -gt 0 ]; do [ "$1" = --work-dir ] && work="$2"; shift; done; mkdir -p "$work"; echo \'{"hoodi_subnet_ids":["subnet-a"]}\' > "$work/foundation-output.json"; echo \'{"artifacts":{"vault-chart":{"version":"0.31.0","manifest_digest":"sha256:8888888888888888888888888888888888888888888888888888888888888888"},"cert-manager-chart":{"manifest_digest":"sha256:9999999999999999999999999999999999999999999999999999999999999999"}}}\' > "$work/vault-artifact-mirror-receipt.json"; exit "${DEPLOY_RC:-0}"; fi\nexit 0\n')
        deploy.chmod(0o755)
        # Recovery reaches the release-wide authority gate before its terminal
        # confirmation.  These fixture-only stubs make that gate succeed so
        # each test continues to exercise the resume branch under test.
        inventory = rel / "installer_artifact_inventory.py"
        inventory.write_text("#!/usr/bin/env python3\nprint(" + repr(authority()) + ")\n")
        inventory.chmod(0o755)
        platform = rel / "run-platform-bootstrap.sh"
        platform.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$PLATFORM_LOG"\nwork=""; while [ "$#" -gt 0 ]; do [ "$1" = --baseline-work-dir ] && work="$2"; shift; done\n[ "${PLATFORM_RC:-0}" = 0 ] && touch "$work/.replay-ready"\nexit "${PLATFORM_RC:-0}"\n')
        platform.chmod(0o755)
        # The wrapper now creates verified deployment-bound client values
        # before invoking platform bootstrap.  This test double keeps the
        # production hook and its private-file contract in the exercised
        # path; it only replaces the external artifact verification itself.
        values_builder = rel / "build-deployment-bound-chart-values-input.py"
        values_builder.write_text(
            '#!/usr/bin/env python3\n'
            'import json, os, pathlib, stat, sys\n'
            'args = sys.argv\n'
            'output = pathlib.Path(args[args.index("--output") + 1])\n'
            'output.write_text(json.dumps({"schema_version": 1}) + "\\n")\n'
            'output.chmod(stat.S_IRUSR | stat.S_IWUSR)\n'
        )
        values_builder.chmod(0o755)
        replay = rel / "platform_bootstrap_replay.py"
        replay.write_text('#!/usr/bin/env python3\nimport pathlib, sys\na=sys.argv; w=pathlib.Path(a[a.index("--work-dir") + 1]);\nif not (w / ".replay-ready").exists(): raise SystemExit(65)\nprint("complete")\n')
        replay.chmod(0o755)
        ops = source / "scripts/ops"
        ops.mkdir(parents=True)
        for name in (
            "generate-hoodi-validator-keystore.sh",
            "validate-hoodi-deposit-data.sh",
        ):
            p = ops / name
            p.write_text("#!/usr/bin/env bash\nexit 99\n")
            p.chmod(0o755)
        work = d / "work"
        work.mkdir()
        work.chmod(0o700)
        manifest = d / "bundle-manifest.json"
        inputs = work / "inputs"
        inputs.mkdir()
        inputs.chmod(0o700)
        inp = inputs / "hoodi-zero-release-inputs.json"
        inp.write_text(
            '{"schema_version":1,"network":"hoodi","aws_account_id":"123456789012","aws_region":"ap-northeast-2","zero_resource_inputs":"' + str(inputs / "zero-resource/zero-resource-inputs.json") + '"}'
        )
        inp.chmod(0o600)
        wd = work / "deployment-work"
        wd.mkdir()
        wd.chmod(0o700)
        zero = inputs / "zero-resource"; zero.mkdir(); zero.chmod(0o700)
        (zero / "zero-resource-inputs.json").write_text('{"baseline_config":"' + str(zero / "baseline.tfvars.json") + '"}')
        (zero / "baseline.tfvars.json").write_text('{"name":"node-op-123"}')
        for item in zero.iterdir(): item.chmod(0o600)
        (source / ".ci/gitops").mkdir(parents=True)
        (source / ".ci/gitops/approved-oci-artifacts.json").write_text("{}\n")
        (d / "rendered").mkdir()
        (d / "rendered/installer-artifact-index.json").write_text(json.dumps({"components": {"vault-chart": {"version": "0.31.0", "expected_oci_manifest_digest": "sha256:" + "8" * 64}, "cert-manager-chart": {"expected_oci_manifest_digest": "sha256:" + "9" * 64}}}))
        subprocess.run(
            [
                "python3",
                str(rel / "interactive-hoodi-resume.py"),
                "record",
                "--work-dir",
                str(work),
                "--manifest",
                str(manifest),
                "--account",
                "123456789012",
                "--region",
                "ap-northeast-2",
                "--deployment",
                "node-op-123",
                "--inputs",
                str(inp),
                "--work",
                str(wd),
                "--session",
                str(work / "private-eks-session.json"),
            ],
            check=True,
        )
        fake = d / "bin"
        fake.mkdir()
        aws = fake / "aws"
        aws.write_text('#!/usr/bin/env bash\ncase "$1:$2" in sts:get-caller-identity) printf \'{"Account":"%s"}\\n\' "${AWS_ACCOUNT:-123456789012}" ;; ecr:describe-images) for x in "$@"; do case "$x" in imageDigest=*) echo "${x#imageDigest=}"; exit;; imageTag=*) echo "sha256:' + "7" * 64 + '"; exit;; esac; done;; *) exit 88;; esac\n')
        aws.chmod(0o755)
        for name in ("helm", "ruby"):
            command = fake / name
            command.write_text("#!/usr/bin/env bash\nexit 99\n")
            command.chmod(0o755)
        return d, work, fake

    def invoke(self, d, work, fake, rc="0", account="123456789012", use_env=True, **extra):
        master, slave = pty.openpty()
        env = {
            **os.environ,
            "PATH": str(fake) + os.pathsep + os.environ["PATH"],
            "RESUME_LOG": str(d / "log"),
            "PLATFORM_LOG": str(d / "platform-log"),
            "DEPLOY_RC": rc,
            "AWS_ACCOUNT": account,
            "DEFAULT_GITHUB_REPOSITORY": "example/operator",
            "DEFAULT_GITHUB_OWNER_ID": "101",
            "DEFAULT_GITHUB_REPOSITORY_ID": "102",
            "DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY": "example/gitops",
            "DEFAULT_GITOPS_CLIENT_GITHUB_OWNER_ID": "103",
            "DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY_ID": "104",
            **extra,
        }
        if use_env:
            env["WORK_DIR"] = str(work)
        p = subprocess.Popen(
            [str(d / "source/scripts/release/interactive-hoodi-release.sh")],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave)
        out = b""
        sent = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        pass
                    else:
                        raise
                else:
                    if chunk:
                        out += chunk
                        if not sent and b"Type RESUME to continue:" in out:
                            os.write(master, b"RESUME\n")
                            sent = True
            if p.poll() is not None:
                break
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            self.fail("wrapper PTY test timed out: " + out.decode(errors="replace"))
        os.close(master)
        return p.returncode, out.decode(errors="replace")

    def test_success_runs_deploy_once_and_stops_before_ceremonies(self):
        d, w, b = self.fixture()
        rc, out = self.invoke(d, w, b)
        self.assertEqual(rc, 0)
        self.assertIn("platform-only recovery completed", out)
        self.assertEqual((d / "log").read_text().count("deploy apply"), 1)
        self.assertEqual(
            __import__("json").loads((w / "interactive-resume.json").read_text())[
                "phase"
            ],
            "platform-complete",
        )

    def test_failure_keeps_infrastructure_resumable(self):
        d, w, b = self.fixture()
        rc, _ = self.invoke(d, w, b, "9")
        self.assertEqual(rc, 9)
        self.assertEqual(
            __import__("json").loads((w / "interactive-resume.json").read_text())[
                "phase"
            ],
            "infrastructure",
        )

    def test_manifest_mismatch_blocks_before_aws(self):
        d, w, b = self.fixture()
        # Preserve a valid release-manifest shape so this reaches the receipt
        # binding check rather than the earlier malformed-manifest boundary.
        (d / "bundle-manifest.json").write_text(
            '{"schema_version":"v1","source_revision":"' + "b" * 40
            + '","entries":[]}\n'
        )
        rc, out = self.invoke(d, w, b)
        self.assertEqual(rc, 65)
        self.assertIn("different release bundle", out)
        self.assertFalse((d / "log").exists())

    def test_malformed_manifest_blocks_before_aws(self):
        d, w, b = self.fixture()
        (d / "bundle-manifest.json").write_text('{"changed":true}\n')
        rc, out = self.invoke(d, w, b)
        self.assertEqual(rc, 65)
        self.assertIn("release bundle revision is invalid", out)
        self.assertFalse((d / "log").exists())

    def test_platform_phase_refuses_replay_before_deploy(self):
        d, w, b = self.fixture()
        helper = d / "source/scripts/release/interactive-hoodi-resume.py"
        manifest = d / "bundle-manifest.json"
        subprocess.run(
            [
                "python3",
                str(helper),
                "phase",
                "--work-dir",
                str(w),
                "--manifest",
                str(manifest),
                "--phase",
                "infrastructure-complete",
            ],
            check=True,
        )
        subprocess.run(
            [
                "python3",
                str(helper),
                "phase",
                "--work-dir",
                str(w),
                "--manifest",
                str(manifest),
                "--phase",
                "platform-started",
            ],
            check=True,
        )
        rc, out = self.invoke(d, w, b)
        self.assertEqual(rc, 65)
        self.assertIn("refusing blind restart", out)
        self.assertNotIn("deploy apply", (d / "log").read_text())

    def test_account_mismatch_blocks_before_deploy(self):
        d, w, b = self.fixture()
        rc, out = self.invoke(d, w, b, account="999999999999")
        self.assertEqual(rc, 65)
        self.assertIn("differs from current AWS identity", out)
        self.assertFalse((d / "log").exists())

    def test_traversal_and_session_symlink_block_before_deploy(self):
        d, w, b = self.fixture()
        receipt = w / "interactive-resume.json"
        value = __import__("json").loads(receipt.read_text())
        value["inputs_rel"] = "../outside"
        receipt.write_text(__import__("json").dumps(value))
        receipt.chmod(0o600)
        rc, out = self.invoke(d, w, b)
        self.assertEqual(rc, 65)
        self.assertIn("resume path or context is invalid", out)
        value["inputs_rel"] = "inputs/hoodi-zero-release-inputs.json"
        receipt.write_text(__import__("json").dumps(value))
        receipt.chmod(0o600)
        (w / "private-eks-session.json").symlink_to(
            w / "inputs/hoodi-zero-release-inputs.json"
        )
        rc, out = self.invoke(d, w, b)
        self.assertEqual(rc, 65)
        self.assertIn("paths are unavailable or unsafe", out)
        self.assertFalse((d / "log").exists())

    def test_existing_lock_and_env_file_selector(self):
        d, w, b = self.fixture()
        (w / ".interactive-resume.lock").mkdir()
        rc, out = self.invoke(d, w, b)
        self.assertEqual(rc, 75)
        self.assertIn("holds the WORK_DIR lock", out)
        (w / ".interactive-resume.lock").rmdir()
        env_dir = d / "release"
        env_dir.mkdir()
        (env_dir / "env").write_text("WORK_DIR=" + str(w) + "\n")
        rc, out = self.invoke(d, w, b, use_env=False)
        self.assertEqual(rc, 0)
        self.assertIn("platform-only recovery completed", out)

    def test_root_dotenv_relative_path_and_safe_literal_expansion(self):
        d, w, b = self.fixture()
        rc, _ = self.invoke(d, w, b)
        self.assertEqual(rc, 0)
        (d / ".env").write_text("WORK_DIR=work\nEXISTING_KEYSTORE_DIR=~/keys\n")
        rc, out = self.invoke(d, w, b, use_env=False)
        self.assertEqual(rc, 0, out)
        self.assertIn("Using non-secret configuration:", out)
        self.assertIn(".env", out)
        self.assertIn("platform-only recovery was already complete", out)

        sentinel = d / "executed"
        (d / ".env").write_text(f"WORK_DIR=$(touch {sentinel})\n")
        rc, out = self.invoke(d, w, b, use_env=False)
        self.assertEqual(rc, 65)
        self.assertIn("WORK_DIR is unavailable or unsafe", out)
        self.assertFalse(sentinel.exists())

    def test_config_conflict_symlink_and_failure_log_redaction(self):
        d, w, b = self.fixture()
        (d / ".env").write_text("WORK_DIR=work\n")
        (d / "release").mkdir()
        (d / "release/env").write_text("WORK_DIR=work\n")
        rc, out = self.invoke(d, w, b, use_env=False)
        self.assertEqual(rc, 65)
        self.assertIn("multiple configuration files", out)
        (d / "release/env").unlink()
        (d / ".env").unlink()
        (d / ".env").symlink_to(d / "release/env")
        rc, out = self.invoke(d, w, b, use_env=False)
        self.assertEqual(rc, 65)
        self.assertIn("regular non-symlink", out)
        (d / ".env").unlink()

        rc, _ = self.invoke(d, w, b, rc="9", AWS_SECRET_ACCESS_KEY="sensitive-sentinel")
        self.assertEqual(rc, 9)
        logs = list((w / "diagnostics").glob("installer-*"))
        self.assertTrue(logs)
        log = logs[-1].read_text()
        self.assertIn("status=failed", log)
        self.assertIn("exit_code=9", log)
        self.assertNotIn("sensitive-sentinel", log)
        rc, _ = self.invoke(d, w, b, rc="9")
        self.assertEqual(rc, 9)
        logs = list((w / "diagnostics").glob("installer-*"))
        self.assertGreaterEqual(len(logs), 2)


class ResumeContinuation(unittest.TestCase):
    """Exercise the receipt-only lifecycle contract without invoking a release."""

    public_key = "0x" + "a" * 96

    def fixture(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        work = root / "work"
        work.mkdir(mode=0o700)
        manifest = root / "bundle-manifest.json"
        manifest.write_text(
            json.dumps({"schema_version": "v1", "source_revision": "a" * 40})
        )
        inputs_dir = work / "inputs"
        inputs_dir.mkdir(mode=0o700)
        inputs = inputs_dir / "hoodi-zero-release-inputs.json"
        handoff_dir = inputs_dir / "validator-deployment"
        handoff_dir.mkdir(mode=0o700)
        handoff = handoff_dir / "validator-deployment-handoff.json"
        handoff.write_text(json.dumps({
            "validator_set": "hoodi-example", "validator_public_key": self.public_key,
        }))
        handoff.chmod(0o600)
        inputs.write_text(json.dumps({
            "aws_account_id": ACCOUNT, "aws_region": REGION,
            "validator_deployment_handoff": str(handoff),
        }))
        inputs.chmod(0o600)
        deployment = work / "deployment-work"
        deployment.mkdir(mode=0o700)
        self.call(
            "record", "--work-dir", work, "--manifest", manifest,
            "--account", ACCOUNT, "--region", REGION, "--deployment", DEPLOYMENT,
            "--inputs", inputs, "--work", deployment,
            "--session", work / "private-eks-session.json",
        )
        return root, work, manifest

    def call(self, op, *args, ok=True):
        result = subprocess.run(
            ["python3", str(HELPER), op, *map(str, args)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertEqual(result.returncode, 65, result.stderr)
        return result

    def platform_complete(self, work, manifest):
        for phase in ("infrastructure-complete", "platform-started", "platform-complete"):
            self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", phase)

    def bindable_context(self, work):
        custody = work / "custody"
        custody.mkdir(mode=0o700)
        attestation = custody / "deposit-attestation.json"
        attestation.write_text('{"public_key":"' + self.public_key + '"}\n')
        attestation.chmod(0o600)
        runtime = work / "custody-verifier-runtime"
        runtime.mkdir(mode=0o700)
        receipt = runtime / "receipt.json"
        receipt.write_text('{"schema_version":1}\n')
        receipt.chmod(0o600)
        keystore = work.parent / "external-keystore"
        keystore.mkdir(mode=0o700)
        return keystore, attestation, receipt

    def bind(self, work, manifest, keystore, attestation):
        return self.call(
            "bind-continuation", "--work-dir", work, "--manifest", manifest,
            "--keystore-dir", keystore, "--public-key", self.public_key,
            "--deposit-attestation", attestation,
        )

    def custody_ready(self, work, manifest):
        self.platform_complete(work, manifest)
        keystore, attestation, _ = self.bindable_context(work)
        self.bind(work, manifest, keystore, attestation)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "vault-started")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "vault-complete")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "collector-complete")
        audit = work / "audit"; audit.mkdir(mode=0o700)
        prepared = json.loads(self.call("prepare-audit", "--work-dir", work, "--manifest", manifest).stdout)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "audit-started")
        receipt = audit / "audit-challenge.json"
        receipt.write_text(json.dumps({"schema_version":1,"result":"socket-audit-challenge-emitted-and-root-revoked","aws_account_id":"123456789012","aws_region":"ap-northeast-2","deployment_name":"node-op-123","release_revision":"a"*40,"operation_id":prepared["operation_id"],"marker_hmac":"hmac-sha256:"+"a"*64,"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","after_ms":1}))
        receipt.chmod(0o600)
        self.call("reconcile-audit-complete", "--work-dir", work, "--manifest", manifest)

    def prepare_custody(self, work, manifest, validator_set="hoodi-example"):
        result = self.call(
            "prepare-custody", "--work-dir", work, "--manifest", manifest,
            "--validator-set", validator_set,
        )
        return json.loads(result.stdout)

    def activation_pending(self, work, manifest):
        self.custody_ready(work, manifest)
        prepared = self.prepare_custody(work, manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "custody-started")
        ceremony = work / "ceremony"; ceremony.mkdir(mode=0o700)
        signer_ca = ceremony / "signer-ca.crt"; known_clients = ceremony / "known-clients.txt"
        signer_ca.write_text("ca\n"); known_clients.write_text("known\n")
        signer_ca.chmod(0o644); known_clients.chmod(0o644)
        receipt = pathlib.Path(prepared["result_output"])
        receipt.write_text(json.dumps({
            "schema_version": 1, "operation_id": prepared["operation_id"],
            "validator_set": prepared["validator_set"], "expected_public_key": prepared["public_key"],
            "result": "onboarding-complete",
            "public_outputs": {
                "signer_ca_sha256": hashlib.sha256(signer_ca.read_bytes()).hexdigest(),
                "known_clients_sha256": hashlib.sha256(known_clients.read_bytes()).hexdigest(),
            },
        }))
        receipt.chmod(0o600)
        self.call("reconcile-custody-complete", "--work-dir", work, "--manifest", manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "runtime-complete")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "activation-pending")
        evidence = work / "evidence"; evidence.mkdir(mode=0o700)

    def prepare_activation(self, work, manifest):
        result = self.call("prepare-activation", "--work-dir", work, "--manifest", manifest)
        return json.loads(result.stdout)

    def test_bind_and_monotonic_lifecycle(self):
        _, work, manifest = self.fixture()
        self.platform_complete(work, manifest)
        keystore, attestation, _ = self.bindable_context(work)
        self.bind(work, manifest, keystore, attestation)
        value = json.loads((work / "interactive-resume.json").read_text())
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["release_revision"], "a" * 40)
        self.assertEqual(value["continuation"]["keystore_dir"], str(keystore.resolve()))
        self.assertEqual(value["continuation"]["public_key"], self.public_key)
        self.assertEqual(value["continuation"]["deposit_attestation_rel"], "custody/deposit-attestation.json")
        self.assertEqual(value["continuation"]["runtime_receipt_rel"], "custody-verifier-runtime/receipt.json")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "vault-started")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "vault-complete")
        self.assertEqual(json.loads((work / "interactive-resume.json").read_text())["phase"], "vault-complete")

    def test_no_implicit_continuation_or_phase_skip(self):
        _, work, manifest = self.fixture()
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "vault-started", ok=False)
        self.platform_complete(work, manifest)
        keystore, attestation, _ = self.bindable_context(work)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "vault-started", ok=False)
        self.bind(work, manifest, keystore, attestation)
        self.call("bind-continuation", "--work-dir", work, "--manifest", manifest,
                  "--keystore-dir", keystore, "--public-key", self.public_key,
                  "--deposit-attestation", attestation, ok=False)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "custody-started", ok=False)

    def test_changed_bound_identity_or_evidence_refuses_read(self):
        _, work, manifest = self.fixture()
        self.platform_complete(work, manifest)
        keystore, attestation, runtime = self.bindable_context(work)
        self.bind(work, manifest, keystore, attestation)
        runtime.write_text('{"schema_version":2}\n')
        runtime.chmod(0o600)
        self.call("read", "--work-dir", work, "--manifest", manifest, ok=False)
        runtime.write_text('{"schema_version":1}\n')
        runtime.chmod(0o600)
        shutil.rmtree(keystore)
        keystore.mkdir(mode=0o700)
        self.call("read", "--work-dir", work, "--manifest", manifest, ok=False)

    def test_release_identity_mismatch_and_legacy_v1_read(self):
        _, work, manifest = self.fixture()
        receipt = work / "interactive-resume.json"
        value = json.loads(receipt.read_text())
        value["schema_version"] = 1
        value.pop("release_revision")
        value.pop("continuation")
        receipt.write_text(json.dumps(value))
        receipt.chmod(0o600)
        self.call("read", "--work-dir", work, "--manifest", manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "vault-started", ok=False)
        manifest.write_text(json.dumps({"schema_version": "v1", "source_revision": "b" * 40}))
        self.call("read", "--work-dir", work, "--manifest", manifest, ok=False)

    def test_v2_release_revision_mismatch_refuses_read(self):
        _, work, manifest = self.fixture()
        receipt = work / "interactive-resume.json"
        value = json.loads(receipt.read_text())
        value["release_revision"] = "b" * 40
        receipt.write_text(json.dumps(value))
        receipt.chmod(0o600)
        result = self.call("read", "--work-dir", work, "--manifest", manifest, ok=False)
        self.assertIn("different release identity", result.stderr)

    def test_custody_prepare_binds_stable_operation_and_reconciles_exact_result(self):
        _, work, manifest = self.fixture()
        self.custody_ready(work, manifest)
        prepared = self.prepare_custody(work, manifest)
        self.assertEqual(self.prepare_custody(work, manifest), prepared)
        self.assertEqual(prepared["public_key"], self.public_key)
        self.assertEqual(prepared["validator_set"], "hoodi-example")
        self.assertRegex(prepared["operation_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(prepared["result_output"], str(work / "custody/custody-completion.json"))
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "custody-started")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "custody-complete", ok=False)
        self.call("reconcile-custody-complete", "--work-dir", work, "--manifest", manifest, ok=False)
        receipt = pathlib.Path(prepared["result_output"])
        ceremony = work / "ceremony"
        ceremony.mkdir(mode=0o700)
        signer_ca = ceremony / "signer-ca.crt"
        known_clients = ceremony / "known-clients.txt"
        signer_ca.write_text("ca\n")
        known_clients.write_text("known\n")
        signer_ca.chmod(0o644)
        known_clients.chmod(0o644)
        receipt.write_text(json.dumps({
            "schema_version": 1, "operation_id": prepared["operation_id"],
            "validator_set": prepared["validator_set"], "expected_public_key": prepared["public_key"],
            "result": "onboarding-complete",
            "public_outputs": {
                "signer_ca_sha256": hashlib.sha256(signer_ca.read_bytes()).hexdigest(),
                "known_clients_sha256": hashlib.sha256(known_clients.read_bytes()).hexdigest(),
            },
        }))
        receipt.chmod(0o600)
        self.call("reconcile-custody-complete", "--work-dir", work, "--manifest", manifest)
        self.assertEqual(json.loads((work / "interactive-resume.json").read_text())["phase"], "custody-complete")
        original_receipt = receipt.read_bytes()
        receipt.write_bytes(original_receipt.replace(b"onboarding-complete", b"onboarding-tampered"))
        receipt.chmod(0o600)
        self.call("read", "--work-dir", work, "--manifest", manifest, ok=False)
        receipt.write_bytes(original_receipt)
        receipt.chmod(0o600)
        known_clients.write_text("tampered\n")
        self.call("read", "--work-dir", work, "--manifest", manifest, ok=False)

    def test_audit_prepare_binds_fresh_operation_and_unknown_started_state_fails_closed(self):
        _, work, manifest = self.fixture()
        self.platform_complete(work, manifest)
        keystore, attestation, _ = self.bindable_context(work)
        self.bind(work, manifest, keystore, attestation)
        for phase in ("vault-started", "vault-complete", "collector-complete"):
            self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", phase)
        audit = work / "audit"; audit.mkdir(mode=0o700)
        prepared = json.loads(self.call("prepare-audit", "--work-dir", work, "--manifest", manifest).stdout)
        self.assertRegex(prepared["operation_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(prepared["receipt_output"], str(audit / "audit-challenge.json"))
        self.assertEqual(json.loads(self.call("prepare-audit", "--work-dir", work, "--manifest", manifest).stdout), prepared)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "audit-started")
        self.call("reconcile-audit-complete", "--work-dir", work, "--manifest", manifest, ok=False)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "audit-complete", ok=False)
        receipt = audit / "audit-challenge.json"
        receipt.write_text(json.dumps({
            "schema_version": 1, "result": "socket-audit-challenge-emitted-and-root-revoked",
            "aws_account_id": ACCOUNT, "aws_region": REGION, "deployment_name": DEPLOYMENT,
            "release_revision": "a" * 40, "operation_id": "0" * 32,
            "marker_hmac": "hmac-sha256:" + "a" * 64,
            "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "after_ms": 1,
        }))
        receipt.chmod(0o600)
        self.call("reconcile-audit-complete", "--work-dir", work, "--manifest", manifest, ok=False)

    def test_custody_prepare_rejects_unbound_set_and_mismatched_result(self):
        _, work, manifest = self.fixture()
        self.custody_ready(work, manifest)
        self.call(
            "prepare-custody", "--work-dir", work, "--manifest", manifest,
            "--validator-set", "hoodi-other", ok=False,
        )
        prepared = self.prepare_custody(work, manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "custody-started")
        receipt = pathlib.Path(prepared["result_output"])
        receipt.write_text(json.dumps({
            "schema_version": 1, "operation_id": "0" * 32,
            "validator_set": prepared["validator_set"], "expected_public_key": prepared["public_key"],
            "result": "onboarding-complete",
            "public_outputs": {},
        }))
        receipt.chmod(0o600)
        self.call("reconcile-custody-complete", "--work-dir", work, "--manifest", manifest, ok=False)

    def test_custody_reconcile_refuses_receipt_without_public_outputs(self):
        _, work, manifest = self.fixture()
        self.custody_ready(work, manifest)
        prepared = self.prepare_custody(work, manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "custody-started")
        receipt = pathlib.Path(prepared["result_output"])
        receipt.write_text(json.dumps({
            "schema_version": 1, "operation_id": prepared["operation_id"],
            "validator_set": prepared["validator_set"], "expected_public_key": prepared["public_key"],
            "result": "onboarding-complete",
            "public_outputs": {
                "signer_ca_sha256": "a" * 64,
                "known_clients_sha256": "b" * 64,
            },
        }))
        receipt.chmod(0o600)
        self.call("reconcile-custody-complete", "--work-dir", work, "--manifest", manifest, ok=False)

    def test_activation_prepare_reconciles_exact_lower_bound_and_revalidates(self):
        _, work, manifest = self.fixture()
        self.activation_pending(work, manifest)
        prepared = self.prepare_activation(work, manifest)
        self.assertEqual(self.prepare_activation(work, manifest), prepared)
        self.assertEqual(prepared["receipt_output"], str(work / "evidence/activation-receipt.json"))
        self.assertEqual(prepared["deployment_name"], "node-op-123")
        self.assertEqual(prepared["release_revision"], "a" * 40)
        self.assertRegex(prepared["operation_id"], r"^[0-9a-f]{32}$")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "activation-started")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "activated", ok=False)
        receipt = pathlib.Path(prepared["receipt_output"])
        receipt.write_text(json.dumps({
            "schema_version": 1, "result": "activation-post-ready-head-bound",
            "scope": "post-Ready private Beacon head lower bound only; not duty, finalization, signature, or end-to-end proof",
            "validator_set": "hoodi-example", "validator_public_key": self.public_key,
            "deployment_name": "node-op-123", "release_revision": "a" * 40,
            "operation_id": prepared["operation_id"],
            "controllers": {"client_statefulset_uid": "client-controller", "fence_deployment_uid": "fence-controller"},
            "pods": {"client_uid": "client-pod", "fence_uid": "fence-pod"},
            "lease": {"uid": "lease-uid", "holder_identity": "fence-pod"},
            "private_beacon": {"pod_uid": "beacon-pod", "validator_index": "1559065", "head_slot": 123},
        }))
        receipt.chmod(0o600)
        self.call("reconcile-activation", "--work-dir", work, "--manifest", manifest)
        self.assertEqual(json.loads((work / "interactive-resume.json").read_text())["phase"], "activated")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "observing")
        self.call("read", "--work-dir", work, "--manifest", manifest)
        receipt.write_text(receipt.read_text().replace('"head_slot": 123', '"head_slot": 124'))
        receipt.chmod(0o600)
        self.call("read", "--work-dir", work, "--manifest", manifest, ok=False)

    def test_activation_started_without_receipt_cannot_be_promoted_or_replayed(self):
        _, work, manifest = self.fixture()
        self.activation_pending(work, manifest)
        self.prepare_activation(work, manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "activation-started")
        self.call("reconcile-activation", "--work-dir", work, "--manifest", manifest, ok=False)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "activated", ok=False)
        self.call("read", "--work-dir", work, "--manifest", manifest)

    def test_complete_requires_the_observation_transition(self):
        _, work, manifest = self.fixture()
        self.activation_pending(work, manifest)
        self.prepare_activation(work, manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "activation-started")
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "complete", ok=False)

    def test_activation_receipt_identity_and_lower_bound_validation_fail_closed(self):
        _, work, manifest = self.fixture()
        self.activation_pending(work, manifest)
        prepared = self.prepare_activation(work, manifest)
        self.call("phase", "--work-dir", work, "--manifest", manifest, "--phase", "activation-started")
        receipt = pathlib.Path(prepared["receipt_output"])
        receipt.write_text(json.dumps({
            "schema_version": 1, "result": "activation-post-ready-head-bound",
            "scope": "not a lower bound", "validator_set": "hoodi-example", "validator_public_key": self.public_key,
            "deployment_name": "node-op-123", "release_revision": "a" * 40, "operation_id": prepared["operation_id"],
            "controllers": {"client_statefulset_uid": "client", "fence_deployment_uid": "fence"},
            "pods": {"client_uid": "client-pod", "fence_uid": "fence-pod"},
            "lease": {"uid": "lease", "holder_identity": "other-fence"},
            "private_beacon": {"pod_uid": "beacon", "validator_index": "1559065", "head_slot": -1},
        }))
        receipt.chmod(0o600)
        self.call("reconcile-activation", "--work-dir", work, "--manifest", manifest, ok=False)


if __name__ == "__main__":
    unittest.main()
