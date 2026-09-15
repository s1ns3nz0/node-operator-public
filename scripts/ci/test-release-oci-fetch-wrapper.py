#!/usr/bin/env python3
# Check objective: Isolate CI OIDC credentials to the versioned OCI fetch child and clean token files.
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class FetchWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.wrapper = self.root / "scripts/ci/workflows/fetch-release-oci-payload.sh"
        self.wrapper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/ci/workflows/fetch-release-oci-payload.sh", self.wrapper)
        (self.root / "scripts/release").mkdir()
        (self.root / "release").mkdir()
        (self.root / "release/oci-payload-source.json").write_text('{"region":"ap-northeast-2"}')
        self.runner = self.root / "runner"
        self.runner.mkdir(mode=0o700)
        binary = self.root / "bin"
        binary.mkdir()
        curl = binary / "curl"
        curl.write_text('''#!/usr/bin/env python3
import os,sys,json,stat
from pathlib import Path
arguments=sys.argv[1:]
config=Path(arguments[arguments.index('--config')+1])
assert stat.S_IMODE(config.stat().st_mode)==0o600
assert 'fixture-bearer' not in arguments
if os.environ.get('CURL_FAIL')=='1': sys.exit(1)
Path(arguments[arguments.index('--output')+1]).write_text(json.dumps({'value':'abc.def.ghi'}))
''')
        curl.chmod(0o700)
        (self.root / "scripts/release/release_oci_staging.py").write_text('''import os,sys
from pathlib import Path
assert 'AWS_ACCESS_KEY_ID' not in os.environ
assert 'AWS_SECRET_ACCESS_KEY' not in os.environ
assert os.environ['AWS_CONFIG_FILE']=='/dev/null'
assert os.environ['AWS_IGNORE_CONFIGURED_ENDPOINT_URLS']=='true'
assert os.environ['GITHUB_TOKEN']=='synthetic-preserve'
assert Path(os.environ['AWS_WEB_IDENTITY_TOKEN_FILE']).read_text().strip()=='abc.def.ghi'
assert os.environ['AWS_ROLE_ARN'].endswith(':role/fixture-reader')
Path(sys.argv[sys.argv.index('--output-dir')+1]).mkdir()
''')
        self.environment = dict(os.environ, PATH=str(binary)+os.pathsep+os.environ['PATH'],
            RUNNER_TEMP=str(self.runner), OCI_STAGING_READ_ROLE_ARN="arn:aws:iam::000000000000:role/fixture-reader",
            ACTIONS_ID_TOKEN_REQUEST_TOKEN="fixture-bearer", ACTIONS_ID_TOKEN_REQUEST_URL="https://example.invalid/token?x=1",
            AWS_ACCESS_KEY_ID="synthetic-old", AWS_SECRET_ACCESS_KEY="synthetic-old",
            GITHUB_TOKEN="synthetic-preserve")

    def run_wrapper(self):
        return subprocess.run(["bash", str(self.wrapper)], env=self.environment, capture_output=True)

    def test_scoped_child_and_cleaned_credentials(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue((self.runner / "release-oci/payload").is_dir())
        self.assertFalse(list(self.runner.glob('.release-oci-auth.*')))
        self.assertNotIn(b'abc.def.ghi', result.stdout+result.stderr)

    def test_failed_oidc_cleans_up_without_fetch(self):
        self.environment['CURL_FAIL']='1'
        self.assertNotEqual(self.run_wrapper().returncode, 0)
        self.assertFalse(list(self.runner.glob('.release-oci-auth.*')))
        self.assertFalse((self.runner / "release-oci/payload").exists())

    def test_invalid_role_fails_before_credentials(self):
        self.environment['OCI_STAGING_READ_ROLE_ARN']='invalid'
        self.assertNotEqual(self.run_wrapper().returncode, 0)
        self.assertFalse((self.runner / "release-oci").exists())

    def test_missing_descriptor_fails_before_credentials(self):
        (self.root / "release/oci-payload-source.json").unlink()
        self.assertNotEqual(self.run_wrapper().returncode, 0)
        self.assertFalse((self.runner / "release-oci").exists())

    def test_workflow_requires_oci_for_publication(self):
        # Structural wiring check, not proof of GitHub expression execution.
        workflow = (ROOT / '.github/workflows/release-bundle.yml').read_text()
        integrity, publication = workflow.split('  build-and-publish:', 1)
        self.assertIn("if: hashFiles('release/oci-payload-source.json') != '' || github.event_name == 'push' || inputs.mode == 'publish'", integrity)
        fetch_step = publication.split('- name: Version-bound OCI release inputs', 1)[1].split('- name:', 1)[0]
        self.assertNotIn('if:', fetch_step)
        self.assertIn("OCI_PAYLOAD_MANIFEST: ${{ format('{0}/release-oci/payload/payload-manifest.json', runner.temp) }}", publication)
        self.assertIn("OCI_PAYLOAD_DIR: ${{ format('{0}/release-oci/payload', runner.temp) }}", publication)


if __name__ == '__main__':
    unittest.main()
