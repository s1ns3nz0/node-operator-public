#!/usr/bin/env python3
# Check objective: Verify authorized inventory selections reach the prepare call.
"""PTY proof that canonical inventory selections reach the real prepare call."""
import hashlib, json, os, pathlib, pty, select, shutil, stat, subprocess, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
ACCOUNT, REGION, DEPLOYMENT = "123456789012", "ap-northeast-2", "node-op-auth"
ROWS = (("web3signer", "baseline-validator-runtime-web3signer", "1"), ("postgres", "baseline-validator-runtime-postgres", "2"), ("prysm-validator", "baseline-validator-prysm", "3"), ("validator-signing-fence", "baseline-validator-fence", "4"), ("argocd-bootstrap", "baseline-gitops-argocd", "5"), ("vault-bootstrap", "baseline-gitops-vault", "6"), ("node-operator-client-chart", "baseline-gitops-client/node-operator-client", "7"))

def exe(path, text):
    path.write_text(text); path.chmod(path.stat().st_mode | stat.S_IXUSR)

def authority():
    artifacts = []
    for component, repository, digit in ROWS:
        digest = "sha256:" + digit * 64
        item = {"component": component, "required": True, "destination": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{DEPLOYMENT}-{repository}@{digest}", "source": f"approved.example/{repository}@{digest}"}
        if component == "node-operator-client-chart": item["destination_tag"] = "0.1.37"
        artifacts.append(item)
    return json.dumps({"schema_version": 1, "complete": True, "artifacts": artifacts})

def fixture(work):
    bundle = work / "bundle"; source = bundle / "source"; release = source / "scripts/release"; ops = source / "scripts/ops"
    release.mkdir(parents=True); ops.mkdir(parents=True)
    (source / "deploy/validator").mkdir(parents=True)
    (source / "deploy/prysm").mkdir(parents=True)
    shutil.copy2(ROOT / "deploy/validator/storage-class.yaml", source / "deploy/validator/storage-class.yaml")
    shutil.copy2(ROOT / "deploy/prysm/service.yaml", source / "deploy/prysm/service.yaml")
    (bundle / "bundle-manifest.json").write_text('{"source_revision":"' + "a" * 40 + '"}\n')
    shutil.copy(ROOT / "scripts/release/interactive-hoodi-release.sh", release / "interactive-hoodi-release.sh"); (release / "interactive-hoodi-release.sh").chmod(0o755)
    shutil.copy(ROOT / "scripts/release/apply-hoodi-validator-runtime.sh", release / "apply-hoodi-validator-runtime.sh"); (release / "apply-hoodi-validator-runtime.sh").chmod(0o755)
    exe(release / "node-operator-release.sh", "#!/usr/bin/env bash\n[ \"$1\" = verify ] && exit 0\nexit 99\n")
    exe(release / "installer_artifact_inventory.py", "#!/usr/bin/env python3\nprint(" + repr(authority()) + ")\n")
    prepare = "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" > \"$PREPARE_LOG\"\nout=''; while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output-dir ] && out=$2; shift; done\nif [ \"${PREPARE_EXIT:-97}\" = 0 ]; then mkdir -p \"$out/zero-resource\" \"$out/validator-deployment\"; printf '{\"name\":\"node-op-auth\"}\\n' > \"$out/zero-resource/baseline.tfvars.json\"; printf '{\"baseline_config\":\"%s/zero-resource/baseline.tfvars.json\"}\\n' \"$out\" > \"$out/zero-resource/zero-resource-inputs.json\"; printf '{\"zero_resource_inputs\":\"%s/zero-resource/zero-resource-inputs.json\"}\\n' \"$out\" > \"$out/hoodi-zero-release-inputs.json\"; : > \"$out/validator-deployment/runtime.yaml\"; : > \"$out/validator-deployment/client-and-fence.yaml\"; exit 0; fi\nexit \"${PREPARE_EXIT:-97}\"\n"
    exe(release / "prepare-hoodi-zero-release-inputs.sh", prepare)
    deploy = "#!/usr/bin/env bash\nprintf '%s %s\\n' \"$1\" \"${2:-}\" >> \"$RELEASE_LOG\"\n[ \"$1\" = deploy ] || exit 0\nwork=''; session=''; while [ \"$#\" -gt 0 ]; do [ \"$1\" = --work-dir ] && work=$2; [ \"$1\" = --private-eks-session-handoff ] && session=$2; shift; done\nmkdir -p \"$work\"; [ -z \"$session\" ] || printf '{}' > \"$session\"; printf '{\"hoodi_subnet_ids\":[\"subnet-a\"]}\\n' > \"$work/foundation-output.json\"; printf '{\"ebs_kms_key_arn\":{\"value\":\"arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc\"}}\\n' > \"$work/baseline-output.json\"; printf '{\"bucket\":\"bucket\",\"dynamodb_table\":\"table\",\"kms_key_id\":\"key\"}\\n' > \"$work/bootstrap-output.json\"; printf '{\"artifacts\":{\"vault-chart\":{\"version\":\"0.31.0\",\"manifest_digest\":\"sha256:8888888888888888888888888888888888888888888888888888888888888888\"},\"cert-manager-chart\":{\"manifest_digest\":\"sha256:9999999999999999999999999999999999999999999999999999999999999999\"}}}\\n' > \"$work/vault-artifact-mirror-receipt.json\"\n"
    deploy = deploy.replace('[ "$1" = deploy ] || exit 0', '''if [ "$1" = custody ]; then
ceremony=''; while [ "$#" -gt 0 ]; do [ "$1" = --ceremony-dir ] && ceremony=$2; shift; done
mkdir -p "$ceremony"; printf 'synthetic-public-fingerprint\\n' > "$ceremony/known-clients.txt"; exit 0
fi
[ "$1" = deploy ] || exit 0''')
    exe(release / "hoodi-validator-release.sh", deploy)
    exe(release / "run-platform-bootstrap.sh", "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" > \"$PLATFORM_LOG\"\nexit \"${PLATFORM_EXIT:-97}\"\n")
    exe(release / "build-deployment-bound-chart-values-input.py", "#!/usr/bin/env python3\nimport os,sys,json\nopen(os.environ['VALUES_LOG'],'w').write(' '.join(sys.argv[1:]))\nout=sys.argv[sys.argv.index('--output')+1]; json.dump({'schema_version':1},open(out,'w')); os.chmod(out,0o600)\n")
    exe(release / "platform_bootstrap_replay.py", "#!/usr/bin/env python3\nimport sys\nif sys.argv[1:2] == ['phase']: print('complete')\nelse: raise SystemExit(99)\n")
    exe(release / "verify-platform-private-eks-session.py", "#!/usr/bin/env python3\nimport os\nopen(os.environ['SESSION_LOG'], 'w').write('|'.join(os.environ.get(k, '') for k in ('AWS_PROFILE','AWS_REGION','AWS_DEFAULT_REGION','AWS_EC2_METADATA_DISABLED','EKS_CLUSTER_NAME','SSM_OPS_INSTANCE_ID','AWS_ACCESS_KEY_ID','PRIVATE_EKS_SESSION','PRIVATE_VAULT_SESSION','KUBECONFIG','VAULT_TOKEN')))\nif os.environ.get('SESSION_FAIL') == '1': raise SystemExit(65)\nprint('node-op-auth\\ti-0123456789abcdef0')\n")
    for name in ("prepare-vault-bootstrap-tls.sh", "verify-existing-hoodi-validator.py", "verify-hoodi-vault-readiness.sh"):
        exe(release / name, "#!/usr/bin/env bash\nexit 99\n")
    exe(release / "interactive-hoodi-resume.py", '''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1] == "prepare-custody":
    work = sys.argv[sys.argv.index("--work-dir") + 1]
    print(json.dumps({"operation_id":"a" * 32,"result_output":work + "/custody/custody-completion.json"}))
if sys.argv[1] == "prepare-audit":
    work = sys.argv[sys.argv.index("--work-dir") + 1]
    print(json.dumps({"operation_id":"b" * 32,"receipt_output":work + "/audit/audit-challenge.json"}))
raise SystemExit(65 if sys.argv[1:2] == ['bind-continuation'] and os.environ.get('CONTINUATION_BIND_FAIL') == '1' else 0)
''')
    # The collector installer is a required bundle member and must be invoked
    # before the resumed validator runtime.  This boundary test doubles only
    # its external apply, retaining an argument log as the invocation proof.
    exe(release / "apply-validator-log-collector.py", "#!/usr/bin/env python3\nimport os, sys\nopen(os.environ['COLLECTOR_LOG'], 'w').write(' '.join(sys.argv[1:]))\nraise SystemExit(int(os.environ.get('COLLECTOR_RC', '0')))\n")
    exe(release / "apply-kyverno-bootstrap.py", "#!/usr/bin/env python3\nimport os, sys\nopen(os.environ['COLLECTOR_LOG'], 'a').write('kyverno ' + ' '.join(sys.argv[1:]) + '\\n')\nraise SystemExit(int(os.environ.get('KYVERNO_RC', '0')))\n")
    exe(release / "custody_verifier_runtime.py", "#!/usr/bin/env python3\nimport os, sys\nraise SystemExit(int(os.environ.get('CUSTODY_PREFLIGHT_RC', '0')))\n")
    exe(release / "run-hoodi-validator-observation.py", "#!/usr/bin/env python3\nimport os, sys\nwith open(os.environ['EKS_LOG'], 'a') as log: log.write('observe-only:' + ' '.join(sys.argv[1:]) + '\\n')\nraise SystemExit(int(os.environ.get('OBSERVE_RC', '75')))\n")
    exe(ops / "generate-hoodi-validator-keystore.sh", "#!/usr/bin/env bash\nmkdir -p \"$2/validator_keys\"; jq -n --arg p \"$(printf 'a%.0s' {1..96})\" '{version:4,pubkey:$p,path:\"m/12381/3600/0/0/0\",uuid:\"00000000-0000-4000-8000-000000000000\",crypto:{kdf:{function:\"scrypt\",params:{dklen:32,n:262144,r:8,p:1,salt:(\"a\"*64)},message:\"\"},checksum:{function:\"sha256\",params:{},message:(\"b\"*64)},cipher:{function:\"aes-128-ctr\",params:{iv:(\"c\"*32)},message:(\"d\"*64)}}}' > \"$2/validator_keys/keystore-test.json\"; printf '{}' > \"$2/deposit_data-1.json\"\n")
    shutil.copy2(ROOT / "scripts/ops/verify-custody-validator-key.py", ops / "verify-custody-validator-key.py"); (ops / "verify-custody-validator-key.py").chmod(0o755)
    exe(ops / "validate-hoodi-deposit-data.sh", "#!/usr/bin/env bash\nmkdir -p \"$6\"; printf '{\"validator_public_key\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}' > \"$6/uc-1-deposit-attestation.json\"\n")
    exe(ops / "with-private-vault.sh", "#!/usr/bin/env bash\nprintf '%s' \"$AWS_PROFILE|$AWS_REGION|$AWS_DEFAULT_REGION|$AWS_EC2_METADATA_DISABLED|$EKS_CLUSTER_NAME|$SSM_OPS_INSTANCE_ID|${AWS_ACCESS_KEY_ID:-}|${PRIVATE_EKS_SESSION:-}|${PRIVATE_VAULT_SESSION:-}|${KUBECONFIG:-}|${VAULT_TOKEN:-}|${PRIVATE_VAULT_TARGET:-}\" > \"$VAULT_LOG\"\nif [ \"${VAULT_EXEC_CHILD:-0}\" = 1 ]; then\n  [ \"$1\" = -- ] || exit 64; shift\n  exec \"$@\"\nfi\nexit \"${VAULT_RC:-75}\"\n")
    exe(ops / "recover-and-bootstrap-hoodi-vault-v2.sh", "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" > \"$VAULT_HELPER_LOG\"\ncase \" $* \" in *\" --verify-initialization-completion \"*) exit \"${VERIFY_RC:-0}\" ;; *) exit 88 ;; esac\n")
    exe(ops / "recover-and-configure-private-vault-validator-audit.sh", "#!/usr/bin/env bash\nprintf 'audit-setup\\n' >> \"$VAULT_HELPER_LOG\"\nexit \"${AUDIT_RC:-0}\"\n")
    exe(ops / "verify-hoodi-vault-readiness.sh", "#!/usr/bin/env bash\nexit \"${READINESS_RC:-0}\"\n")
    exe(ops / "with-private-eks.sh", "#!/usr/bin/env bash\nprintf '%s\\n' \"$AWS_PROFILE|$AWS_REGION|$AWS_DEFAULT_REGION|$AWS_EC2_METADATA_DISABLED|$EKS_CLUSTER_NAME|$SSM_OPS_INSTANCE_ID|${AWS_ACCESS_KEY_ID:-}|${KUBECONFIG:-}\" >> \"$EKS_LOG\"\n[ \"$1\" = -- ] && shift\nKUBECONFIG=generated-kube \"$@\"\n")
    exe(ops / "ensure-vault-agent-ca.sh", "#!/usr/bin/env bash\nprintf 'ca:%s\\n' \"${KUBECONFIG:-}\" >> \"$EKS_LOG\"\n")
    exe(ops / "ensure-validator-encrypted-storageclass.sh", "#!/usr/bin/env bash\nprintf 'validator-storageclass:%s\\n' \"$*\" >> \"$EKS_LOG\"\n")
    fake = work / "bin"; fake.mkdir()
    (source / ".ci/gitops").mkdir(parents=True); (source / ".ci/gitops/approved-oci-artifacts.json").write_text("{}\n")
    (bundle / "rendered").mkdir()
    chart_digest = "sha256:" + "8" * 64
    cert_digest = "sha256:" + "9" * 64
    (bundle / "rendered/installer-artifact-index.json").write_text(json.dumps({"components": {"vault-chart": {"version": "0.31.0", "expected_oci_manifest_digest": chart_digest}, "cert-manager-chart": {"expected_oci_manifest_digest": cert_digest}}}) + "\n")
    aws = "#!/usr/bin/env bash\nprintf 'aws %s\\n' \"$*\" >> \"$AWS_LOG\"\ncase \"$1:$2\" in\nsts:get-caller-identity) printf '{\"Account\":\"123456789012\",\"Arn\":\"arn:aws:iam::123456789012:user/test\"}\\n' ;;\niam:get-role) printf '(NoSuchEntity)' >&2; exit 1 ;;\niam:create-role|iam:put-role-policy) exit 0 ;;\nec2:describe-availability-zones) printf 'ap-northeast-2a\\tap-northeast-2b\\n' ;;\nconfigservice:describe-configuration-recorders) printf '1\\n' ;;\necr:describe-images) repository=''; previous=''; for arg in \"$@\"; do [ \"$previous\" = --repository-name ] && repository=$arg; previous=$arg; done; if [ \"$repository\" = \"${ECR_FAIL_REPOSITORY:-}\" ]; then case \"${ECR_RESULT:?}\" in missing) printf 'None\\n' ;; wrong) printf 'sha256:'; printf '9%.0s' {1..64}; printf '\\n' ;; esac; exit 0; fi; for arg in \"$@\"; do case \"$arg\" in imageDigest=*) printf '%s\\n' \"${arg#imageDigest=}\"; exit 0 ;; imageTag=*) printf 'sha256:'; printf '7%.0s' {1..64}; printf '\\n'; exit 0 ;; esac; done ;;\n*) exit 88 ;;\nesac\n"
    exe(fake / "aws", aws)
    exe(fake / "docker", "#!/usr/bin/env bash\nprintf 'docker %s\\n' \"$*\" >> \"$DOCKER_LOG\"\nexit 94\n")
    # The wrapper preflights these release dependencies. Chart rendering is
    # intentionally outside this PTY fixture; fail if either command is used.
    exe(fake / "helm", "#!/usr/bin/env bash\nexit 99\n")
    exe(fake / "ruby", "#!/usr/bin/env bash\nexit 99\n")
    exe(fake / "kubectl", "#!/usr/bin/env bash\nprintf 'kubectl:%s\\n' \"${KUBECONFIG:-}\" >> \"$EKS_LOG\"\nexit 76\n")
    return bundle, fake, release / "interactive-hoodi-release.sh"

def run(script, fake, work, answers, **extra):
    master, slave = pty.openpty(); env = {**os.environ, "PATH": str(fake) + os.pathsep + os.environ["PATH"], "AWS_LOG": str(work / "aws.log"), "DOCKER_LOG": str(work / "docker.log"), "PREPARE_LOG": str(work / "prepare.log"), "PLATFORM_LOG": str(work / "platform.log"), "RELEASE_LOG": str(work / "release.log"), "SESSION_LOG": str(work / "session.log"), "VAULT_LOG": str(work / "vault.log"), "VAULT_HELPER_LOG": str(work / "vault-helper.log"), "EKS_LOG": str(work / "eks.log"), "COLLECTOR_LOG": str(work / "collector.log"), "VALUES_LOG": str(work / "values.log"), **extra}
    for key in ("WORK_DIR", "REGION", "DEPLOYMENT_NAME", "VALIDATOR_SET", "VALIDATOR_PUBLIC_KEY", "WITHDRAWAL_ADDRESS", "EXISTING_KEYSTORE_DIR", "WEB3SIGNER_IMAGE", "POSTGRES_IMAGE", "PRYSM_IMAGE", "FENCE_IMAGE", "ARGOCD_BOOTSTRAP_IMAGE", "VAULT_BOOTSTRAP_IMAGE", "CLIENT_CHART_VERSION", "CLIENT_CHART_DIGEST"):
        env.pop(key, None)
    for key in tuple(env):
        if key.startswith("DEFAULT_"): env.pop(key)
    # Artifact/custody tests supply an explicit synthetic user configuration;
    # the production installer must not supply a maintainer-wallet default.
    env["DEFAULT_WITHDRAWAL"] = "0x" + "1" * 40
    env.update({"DEFAULT_GITHUB_REPOSITORY": "example/operator", "DEFAULT_GITHUB_OWNER_ID": "101", "DEFAULT_GITHUB_REPOSITORY_ID": "102", "DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY": "example/gitops", "DEFAULT_GITOPS_CLIENT_GITHUB_OWNER_ID": "103", "DEFAULT_GITOPS_CLIENT_GITHUB_REPOSITORY_ID": "104"})
    env.update(extra)  # Explicit fixture inputs take precedence over ambient cleanup.
    proc = subprocess.Popen([str(script)], stdin=slave, stdout=slave, stderr=slave, env=env); os.close(slave); os.write(master, answers.encode()); out = bytearray(); deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline and proc.poll() is None:
            ready, _, _ = select.select([master], [], [], .1)
            if ready:
                try: out.extend(os.read(master, 8192))
                except OSError: pass
        if proc.poll() is None:
            proc.kill(); raise AssertionError("PTY timed out: " + out.decode(errors="replace")[-2000:])
        while True:
            try: chunk = os.read(master, 8192)
            except OSError: break
            if not chunk: break
            out.extend(chunk)
        return proc.wait(), out.decode(errors="replace")
    finally:
        if proc.poll() is None: proc.kill()
        proc.wait()
        os.close(master)

def positive():
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); bundle, fake, script = fixture(work)
        source = "approved.example/baseline-validator-runtime-web3signer@sha256:" + "1" * 64
        (bundle / "env").write_text("WEB3SIGNER_IMAGE=" + source + "\n")
        code, out = run(script, fake, work, f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n")
        assert code == 97, (code, out)
        actual = (work / "prepare.log").read_text()
        for component, repository, digit in ROWS[:4]: assert f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{DEPLOYMENT}-{repository}@sha256:{digit * 64}" in actual, actual

def conflict(setting, diagnostic):
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); bundle, fake, script = fixture(work)
        (bundle / "env").write_text(setting + "\n")
        code, out = run(script, fake, work, f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\n")
        calls = (work / "aws.log").read_text()
        assert code == 65 and diagnostic in out, out
        assert "iam get-role" not in calls and not (work / "prepare.log").exists(), calls

def platform_boundary():
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        answers = f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n"
        code, out = run(script, fake, work, answers, PREPARE_EXIT="0", PLATFORM_EXIT="0", VAULT_RC="0", READINESS_RC="70")
        assert code == 70 and "custody apply" not in (work / "release.log").read_text(), (code, out)
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        code, out = run(script, fake, work, f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n", PREPARE_EXIT="0")
        assert code == 97, (code, out)
        actual = (work / "platform.log").read_text()
        for component, repository, digit in ROWS[4:6]: assert f"--{'argocd' if component == 'argocd-bootstrap' else 'vault'}-image {ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{DEPLOYMENT}-{repository}@sha256:{digit * 64}" in actual, actual
        assert f"--client-chart-version 0.1.37 --client-chart-digest sha256:{'7' * 64}" in actual, actual
        assert not (work / "docker.log").exists(), actual

def platform_failure(component, result):
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        repository = f"{DEPLOYMENT}-{dict((component, repository) for component, repository, _ in ROWS)[component]}"
        code, out = run(script, fake, work, f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n", PREPARE_EXIT="0", ECR_RESULT=result, ECR_FAIL_REPOSITORY=repository)
        calls = (work / "aws.log").read_text()
        assert code == 65 and not (work / "platform.log").exists(), (code, out)
        assert f"--repository-name {repository}" in calls, calls
        assert not (work / "docker.log").exists(), calls

def postplatform_session_boundary():
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        answers = f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n"
        code, out = run(script, fake, work, answers, PREPARE_EXIT="0", PLATFORM_EXIT="0", AWS_PROFILE="chosen", AWS_ACCESS_KEY_ID="ambient-key", PRIVATE_EKS_SESSION="ambient-eks", PRIVATE_VAULT_SESSION="ambient-vault", KUBECONFIG="ambient-kube", VAULT_TOKEN="ambient-token")
        assert code == 75, (code, out)
        assert (work / "session.log").read_text() == "chosen|ap-northeast-2|ap-northeast-2|true|||||||", (work / "session.log").read_text()
        assert (work / "vault.log").read_text() == "chosen|ap-northeast-2|ap-northeast-2|true|node-op-auth|i-0123456789abcdef0||||||pod/vault-0"
        assert "custody apply" not in (work / "release.log").read_text()
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        answers = f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n"
        code, out = run(script, fake, work, answers, PREPARE_EXIT="0", PLATFORM_EXIT="0", SESSION_FAIL="1")
        assert code == 65 and not (work / "vault.log").exists(), (code, out)
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        answers = f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n"
        code, out = run(script, fake, work, answers, PREPARE_EXIT="0", PLATFORM_EXIT="0", VAULT_RC="0", AWS_PROFILE="chosen", AWS_ACCESS_KEY_ID="ambient-key", KUBECONFIG="ambient-kube", VAULT_TOKEN="ambient-token")
        assert code == 76, (code, out)
        lines = (work / "eks.log").read_text().splitlines()
        outer_ready = lines[0]
        assert outer_ready == "chosen|ap-northeast-2|ap-northeast-2|true|node-op-auth|i-0123456789abcdef0||", outer_ready
        # The first failing publication is now known-clients; runtime/CA must
        # not proceed when either side of that ConfigMap pipeline fails.
        assert lines.count(outer_ready) == 4, lines
        storage_call = next(index for index, line in enumerate(lines) if line.startswith("validator-storageclass:"))
        runtime_publish = next(index for index, line in enumerate(lines) if line == "kubectl:generated-kube")
        assert storage_call < runtime_publish, lines
        assert lines.count("kubectl:generated-kube") == 2, lines
        assert not any(line.startswith("ca:") for line in lines), lines

def custody_preflight_failure():
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        answers = f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n"
        code, out = run(script, fake, work, answers, CUSTODY_PREFLIGHT_RC="65")
        assert code == 65 and "custody verifier preflight failed" in out, (code, out)
        assert not (work / "prepare.log").exists()
        assert not (work / "platform.log").exists()
        assert not (work / "vault.log").exists()

def continuation_binding_failure():
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        answers = f"DEPLOY\n\n\n{DEPLOYMENT}\n\nCONFIRM\nCREATE\n{work / 'run'}\n\nyes\n"
        code, out = run(script, fake, work, answers, PREPARE_EXIT="0", PLATFORM_EXIT="0", CONTINUATION_BIND_FAIL="1")
        assert code == 65 and "could not bind custody continuation" in out, (code, out)
        assert (work / "platform.log").exists()
        assert not (work / "vault.log").exists()

def bound_continuation_resume():
    for phase in ("custody-complete", "vault-started", "custody-started", "custody-started-unproven"):
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary); bundle, fake, script = fixture(work)
            selected = work / "run"; selected.mkdir(mode=0o700)
            custody = selected / "custody"
            subprocess.run([str(bundle / "source/scripts/ops/generate-hoodi-validator-keystore.sh"), "--output-dir", str(custody)], check=True, capture_output=True)
            attestation = custody / "attestation.json"
            attestation.write_text(json.dumps({"withdrawal_address": "0x" + "a" * 40}))
            inputs = selected / "inputs"; inputs.mkdir()
            (inputs / "hoodi-zero-release-inputs.json").write_text(json.dumps({"validator_set":"hoodi-example"}))
            manifests = inputs / "validator-deployment"; manifests.mkdir()
            for name in ("runtime.yaml", "client-and-fence.yaml"): (manifests / name).write_text("# synthetic\n")
            deployment = selected / "deployment-work"; deployment.mkdir(mode=0o700)
            (deployment / "baseline-output.json").write_text('{"ebs_kms_key_arn":{"value":"arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc"}}')
            (selected / "ceremony").mkdir(mode=0o700)
            (selected / "ceremony/known-clients.txt").write_text("synthetic-public-fingerprint\n")
            saved_phase = "custody-started" if phase.endswith("-unproven") else phase
            context = {"aws_account_id":ACCOUNT,"aws_region":REGION,"deployment_name":DEPLOYMENT,"release_revision":"a" * 40,"phase":saved_phase,"inputs_rel":"inputs/hoodi-zero-release-inputs.json","work_rel":"deployment-work","session_rel":"private-eks-session.json","continuation":{"keystore_dir":str(custody / "validator_keys"),"public_key":"0x" + "a" * 96,"deposit_attestation_rel":"custody/attestation.json"}}
            exe(bundle / "source/scripts/release/interactive-hoodi-resume.py", "#!/usr/bin/env python3\nimport sys\nif sys.argv[1] == 'read': print(" + repr(json.dumps(context)) + ")\nif sys.argv[1] == 'reconcile-custody-complete': raise SystemExit(" + ("65" if phase.endswith("-unproven") else "0") + ")\n")
            code, out = run(script, fake, work, "RESUME\n", WORK_DIR=str(selected), release_revision="b" * 40)
            assert not (work / "vault.log").exists(), (code, out)
            assert not (work / "release.log").exists(), (code, out)
            if phase == "vault-started":
                assert code == 75 and "must be reconciled" in out, (code, out)
                assert not (work / "eks.log").exists()
            elif phase == "custody-started-unproven":
                assert code == 75 and "custody completion is unproven" in out, (code, out)
            else:
                assert code == 76 and (work / "eks.log").exists(), (code, out)
                assert "validator-storageclass:--template" in (work / "eks.log").read_text(), (code, out)
                assert "--kms-key-arn arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc" in (work / "eks.log").read_text(), (code, out)
                collector = (work / "collector.log")
                # Collection now completes before the audit and custody
                # ceremonies. A resume already past custody must never replay
                # it merely to reconstruct the old ordering.
                assert not collector.exists(), (code, out)

def vault_initialization_resume_verification():
    for case in ("completed", "missing", "mismatched"):
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary); bundle, fake, script = fixture(work)
            selected = work / "run"; selected.mkdir(mode=0o700)
            inputs = selected / "inputs"; inputs.mkdir(mode=0o700)
            (inputs / "hoodi-zero-release-inputs.json").write_text(json.dumps({"validator_set":"hoodi-example"}))
            custody = selected / "custody"; custody.mkdir(mode=0o700)
            (custody / "attestation.json").write_text('{"withdrawal_address":"0x' + "b" * 40 + '"}')
            keys = work / "external-keys"; keys.mkdir(mode=0o700)
            exe(bundle / "source/scripts/ops/verify-custody-validator-key.py", "#!/usr/bin/env python3\n")
            context = {"aws_account_id":ACCOUNT,"aws_region":REGION,"deployment_name":DEPLOYMENT,"phase":"vault-started","inputs_rel":"inputs/hoodi-zero-release-inputs.json","work_rel":"deployment-work","session_rel":"private-eks-session.json","continuation":{"keystore_dir":str(keys),"public_key":"0x" + "a" * 96,"deposit_attestation_rel":"custody/attestation.json"}}
            exe(bundle / "source/scripts/release/interactive-hoodi-resume.py", "#!/usr/bin/env python3\nimport json, sys\nif sys.argv[1] == 'read': print(" + repr(json.dumps(context)) + ")\nelse: raise SystemExit(0)\n")
            if case != "missing":
                recovery = selected / "vault-recovery"; recovery.mkdir(mode=0o700)
                (recovery / "vault-initialization-checkpoint.json").write_text('{"schema_version":1,"status":"configured"}')
                (recovery / "vault-initialization-checkpoint.json").chmod(0o600)
            code, out = run(script, fake, work, "RESUME\n", WORK_DIR=str(selected), VAULT_EXEC_CHILD="1", VERIFY_RC="75" if case == "mismatched" else "0", READINESS_RC="70")
            assert code == (70 if case == "completed" else 75), (case, code, out)
            assert "custody apply" not in ((work / "release.log").read_text() if (work / "release.log").exists() else ""), (case, out)
            assert "kubectl:generated-kube" not in ((work / "eks.log").read_text() if (work / "eks.log").exists() else ""), (case, out)
            if case == "missing":
                assert not (work / "vault.log").exists(), (case, out)
                assert "no completed initialization checkpoint" in out, out
            else:
                invocation = (work / "vault-helper.log").read_text()
                assert "--verify-initialization-completion" in invocation and "operator init" not in invocation and "generate-root" not in invocation, (case, invocation)
                assert (work / "vault.log").exists(), (case, out)
                if case == "mismatched": assert "recorded Vault initialization completion could not be verified" in out, out

def actual_custody_receipt_resume_contract():
    for tamper in (False, True):
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary); bundle, fake, script = fixture(work)
            helper = bundle / "source/scripts/release/interactive-hoodi-resume.py"
            shutil.copy2(ROOT / "scripts/release/interactive-hoodi-resume.py", helper); helper.chmod(0o755)
            # The release branch is the subject here; crypto key validation is
            # separately covered by the custody verifier suite.
            exe(bundle / "source/scripts/ops/verify-custody-validator-key.py", "#!/usr/bin/env python3\n")
            selected = work / "run"; selected.mkdir(mode=0o700)
            inputs = selected / "inputs"; inputs.mkdir(mode=0o700)
            handoff_dir = inputs / "validator-deployment"; handoff_dir.mkdir(mode=0o700)
            public_key = "0x" + "a" * 96
            handoff = handoff_dir / "validator-deployment-handoff.json"
            handoff.write_text(json.dumps({"validator_set":"hoodi-example", "validator_public_key":public_key})); handoff.chmod(0o600)
            input_file = inputs / "hoodi-zero-release-inputs.json"
            input_file.write_text(json.dumps({"aws_account_id":ACCOUNT,"aws_region":REGION,"validator_set":"hoodi-example","validator_deployment_handoff":str(handoff)})); input_file.chmod(0o600)
            zero = inputs / "zero-resource"; zero.mkdir(mode=0o700)
            (zero / "baseline.tfvars.json").write_text('{"name":"node-op-auth"}'); (zero / "baseline.tfvars.json").chmod(0o600)
            for name in ("runtime.yaml", "client-and-fence.yaml"):
                (handoff_dir / name).write_text("# staged\n")
            deployment = selected / "deployment-work"; deployment.mkdir(mode=0o700)
            (deployment / "baseline-output.json").write_text('{"ebs_kms_key_arn":{"value":"arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789abc"}}')
            manifest = bundle / "bundle-manifest.json"
            subprocess.run(["python3", str(helper), "record", "--work-dir", str(selected), "--manifest", str(manifest), "--account", ACCOUNT, "--region", REGION, "--deployment", DEPLOYMENT, "--inputs", str(input_file), "--work", str(deployment), "--session", str(selected / "private-eks-session.json")], check=True)
            for phase in ("infrastructure-complete", "platform-started", "platform-complete"):
                subprocess.run(["python3", str(helper), "phase", "--work-dir", str(selected), "--manifest", str(manifest), "--phase", phase], check=True)
            custody = selected / "custody"; custody.mkdir(mode=0o700)
            keys = work / "external-keys"; keys.mkdir(mode=0o700)
            attestation = custody / "deposit-attestation.json"; attestation.write_text('{"withdrawal_address":"0x' + "b" * 40 + '"}'); attestation.chmod(0o600)
            runtime = selected / "custody-verifier-runtime"; runtime.mkdir(mode=0o700)
            (runtime / "receipt.json").write_text('{"schema_version":1}'); (runtime / "receipt.json").chmod(0o600)
            subprocess.run(["python3", str(helper), "bind-continuation", "--work-dir", str(selected), "--manifest", str(manifest), "--keystore-dir", str(keys), "--public-key", public_key, "--deposit-attestation", str(attestation)], check=True)
            for phase in ("vault-started", "vault-complete", "collector-complete"):
                subprocess.run(["python3", str(helper), "phase", "--work-dir", str(selected), "--manifest", str(manifest), "--phase", phase], check=True)
            audit = selected / "audit"; audit.mkdir(mode=0o700)
            audit_operation = json.loads(subprocess.run(["python3", str(helper), "prepare-audit", "--work-dir", str(selected), "--manifest", str(manifest)], check=True, text=True, capture_output=True).stdout)
            subprocess.run(["python3", str(helper), "phase", "--work-dir", str(selected), "--manifest", str(manifest), "--phase", "audit-started"], check=True)
            audit_receipt = pathlib.Path(audit_operation["receipt_output"])
            audit_receipt.write_text(json.dumps({"schema_version":1,"result":"socket-audit-challenge-emitted-and-root-revoked","aws_account_id":ACCOUNT,"aws_region":REGION,"deployment_name":DEPLOYMENT,"release_revision":"a" * 40,"operation_id":audit_operation["operation_id"],"marker_hmac":"hmac-sha256:" + "a" * 64,"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","after_ms":1})); audit_receipt.chmod(0o600)
            subprocess.run(["python3", str(helper), "reconcile-audit-complete", "--work-dir", str(selected), "--manifest", str(manifest)], check=True)
            prepared = json.loads(subprocess.run(["python3", str(helper), "prepare-custody", "--work-dir", str(selected), "--manifest", str(manifest), "--validator-set", "hoodi-example"], check=True, text=True, capture_output=True).stdout)
            subprocess.run(["python3", str(helper), "phase", "--work-dir", str(selected), "--manifest", str(manifest), "--phase", "custody-started"], check=True)
            ceremony = selected / "ceremony"; ceremony.mkdir(mode=0o700)
            signer = ceremony / "signer-ca.crt"; known = ceremony / "known-clients.txt"
            signer.write_text("ca\n"); known.write_text("known\n")
            signer.chmod(0o644); known.chmod(0o644)
            result = pathlib.Path(prepared["result_output"])
            result.write_text(json.dumps({"schema_version":1,"operation_id":prepared["operation_id"],"validator_set":"hoodi-example","expected_public_key":public_key,"result":"onboarding-complete","public_outputs":{"signer_ca_sha256":hashlib.sha256(signer.read_bytes()).hexdigest(),"known_clients_sha256":hashlib.sha256(known.read_bytes()).hexdigest()}})); result.chmod(0o600)
            if tamper: known.write_text("tampered\n")
            code, out = run(script, fake, work, "RESUME\n", WORK_DIR=str(selected), AWS_PROFILE="chosen", release_revision="b" * 40)
            assert not (work / "vault.log").exists(), (code, out)
            assert not (work / "release.log").exists(), (code, out)
            if tamper:
                assert code == 75 and "custody public output" in out, (code, out)
                assert "kubectl:generated-kube" not in ((work / "eks.log").read_text() if (work / "eks.log").exists() else ""), (code, out)
            else:
                assert code == 76 and (work / "eks.log").exists(), (code, out)

                # Exercise interrupted activation using the actual durable
                # helper. The fixture receipt is not live duty evidence.
                for phase in ("runtime-complete", "activation-pending"):
                    subprocess.run(["python3", str(helper), "phase", "--work-dir", str(selected), "--manifest", str(manifest), "--phase", phase], check=True)
                evidence = selected / "evidence"; evidence.mkdir(mode=0o700, exist_ok=True); evidence.chmod(0o700)
                activation = json.loads(subprocess.run(["python3", str(helper), "prepare-activation", "--work-dir", str(selected), "--manifest", str(manifest)], check=True, text=True, capture_output=True).stdout)
                subprocess.run(["python3", str(helper), "phase", "--work-dir", str(selected), "--manifest", str(manifest), "--phase", "activation-started"], check=True)
                eks_before = (work / "eks.log").read_bytes()
                code, out = run(script, fake, work, "RESUME\n", WORK_DIR=str(selected), AWS_PROFILE="chosen")
                assert code == 75 and "activation was not replayed" in out, (code, out)
                assert (work / "eks.log").read_bytes() == eks_before and not (work / "release.log").exists(), (code, out)
                activation_receipt = pathlib.Path(activation["receipt_output"])
                activation_receipt.write_text(json.dumps({
                    "schema_version":1, "result":"activation-post-ready-head-bound",
                    "scope":"post-Ready private Beacon head lower bound only; not duty, finalization, signature, or end-to-end proof",
                    "validator_set":"hoodi-example", "validator_public_key":public_key,
                    "deployment_name":DEPLOYMENT, "release_revision":"a" * 40,
                    "operation_id":activation["operation_id"],
                    "controllers":{"client_statefulset_uid":"client-controller", "fence_deployment_uid":"fence-controller"},
                    "pods":{"client_uid":"client-pod", "fence_uid":"fence-pod"},
                    "lease":{"uid":"lease", "holder_identity":"fence-pod"},
                    "private_beacon":{"pod_uid":"beacon", "validator_index":"123", "head_slot":320},
                })); activation_receipt.chmod(0o600)
                code, out = run(script, fake, work, "RESUME\n", WORK_DIR=str(selected), AWS_PROFILE="chosen")
                assert code == 75 and "reconciled without reactivation" in out, (code, out)
                assert json.loads((selected / "interactive-resume.json").read_text())["phase"] == "observing"
                assert "observe-only:" in (work / "eks.log").read_text() and not (work / "release.log").exists(), (code, out)
                assert "--required-finalized-epochs 3" in (work / "eks.log").read_text(), (code, out)
                code, out = run(script, fake, work, "RESUME\n", WORK_DIR=str(selected), AWS_PROFILE="chosen", REQUIRED_FINALIZED_EPOCHS="1", OBSERVE_RC="0")
                assert code == 0 and "delivery-metadata gates currently pass" in out, (code, out)
                assert json.loads((selected / "interactive-resume.json").read_text())["phase"] == "complete", (code, out)
                assert (work / "eks.log").read_text().count("observe-only:") == 2
                assert "--required-finalized-epochs 1" in (work / "eks.log").read_text(), (code, out)
                assert not (work / "release.log").exists(), (code, out)
                activation_receipt.write_text(activation_receipt.read_text() + "\n")
                code, out = run(script, fake, work, "", WORK_DIR=str(selected), AWS_PROFILE="chosen")
                assert code == 65 and "activation receipt changed" in out, (code, out)

def invalid_finalized_duty_threshold_is_rejected_before_aws():
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary); _, fake, script = fixture(work)
        code, out = run(script, fake, work, "", REQUIRED_FINALIZED_EPOCHS="4")
        assert code == 64 and "REQUIRED_FINALIZED_EPOCHS must be 1, 2, or 3" in out, (code, out)
        assert not (work / "aws.log").exists(), (code, out)

bound_continuation_resume()
vault_initialization_resume_verification()
actual_custody_receipt_resume_contract()
invalid_finalized_duty_threshold_is_rejected_before_aws()
continuation_binding_failure()
custody_preflight_failure()
positive()
conflict("FENCE_IMAGE=approved.example/other-repository@sha256:" + "4" * 64, "configured validator-signing-fence image conflicts with canonical artifact authority")
conflict("CLIENT_CHART_VERSION=0.1.38", "configured client chart reference conflicts with canonical artifact authority")
conflict("CLIENT_CHART_DIGEST=sha256:" + "f" * 64, "configured client chart reference conflicts with canonical artifact authority")
platform_boundary()
platform_failure("argocd-bootstrap", "missing")
platform_failure("vault-bootstrap", "wrong")
platform_failure("node-operator-client-chart", "missing")
platform_failure("node-operator-client-chart", "wrong")
postplatform_session_boundary()
print("PASS: PTY canonical selections reach prepare/platform and overrides stop before IAM")
