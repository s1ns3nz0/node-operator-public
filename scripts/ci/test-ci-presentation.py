#!/usr/bin/env python3
# Check objective: Keep workflow display labels consistent and preserve event-routing names.
"""Check presentation conventions without adding a YAML parser dependency."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"


class Presentation(unittest.TestCase):
    def test_workflow_titles(self):
        for path in WORKFLOWS.glob("*.yml"):
            with self.subTest(workflow=path.name):
                title = re.search(r"^name: (.+)$", path.read_text(), re.M)
                self.assertIsNotNone(title)
                self.assertRegex(title[1], r"^(CI|Release|Mirror)(?: [A-Za-z].+)?$")

    def test_target_oriented_steps(self):
        for path in WORKFLOWS.glob("*.yml"):
            for title in re.findall(r"^\s+- name: (.+)$", path.read_text(), re.M):
                with self.subTest(workflow=path.name, step=title):
                    self.assertNotIn(" | ", title)
                    self.assertNotRegex(title, r"^(Run|Test|Verify|Validate|Install) ")

    def test_jobs_have_explicit_display_names(self):
        for path in WORKFLOWS.glob("*.yml"):
            source = path.read_text()
            jobs = re.findall(r"^  [A-Za-z0-9_-]+:\n((?:[ ]{4}[^\n]*\n|\n)+)", source, re.M)
            for job in jobs:
                if re.search(r"^    (runs-on|uses):", job, re.M):
                    self.assertRegex(job, r"(?m)^    name: .+")

    def test_literal_run_blocks_remain_thin(self):
        for path in WORKFLOWS.glob("*.yml"):
            lines = path.read_text().splitlines()
            for index, line in enumerate(lines):
                if line.strip() != "run: |":
                    continue
                indent = len(line) - len(line.lstrip())
                body = []
                for following in lines[index + 1:]:
                    if following.strip() and len(following) - len(following.lstrip()) <= indent:
                        break
                    if following.strip():
                        body.append(following)
                with self.subTest(workflow=path.name, line=index + 1):
                    self.assertLessEqual(len(body), 5)

    def test_extracted_scripts_have_no_github_expression_interpolation(self):
        for workflow in WORKFLOWS.glob("*.yml"):
            for ref in re.findall(r"run: (?:bash )?(scripts/(?:ci/workflows|release)/[A-Za-z0-9_-]+\.sh)", workflow.read_text()):
                with self.subTest(script=ref):
                    source = (ROOT / ref).read_text()
                    self.assertNotIn("${{", source)
                    self.assertRegex(source, r"(?m)^# Check objective: [A-Z].+\.$")

    def test_workflow_run_identity_bindings(self):
        for producer, consumer, title in (
            ("continuous-integration.yml", "evidence-gate.yml", "CI"),
            ("review-signal.yml", "evidence-gate.yml", "CI Evidence Review Signal"),
        ):
            with self.subTest(producer=producer):
                self.assertIn("name: " + title + "\n", (WORKFLOWS / producer).read_text())
                consumer_source = (WORKFLOWS / consumer).read_text()
                triggers = re.search(r"workflows: \[([^\]]+)\]", consumer_source).group(1)
                self.assertIn(title, [item.strip() for item in triggers.split(",")])

    def test_direct_check_entrypoints_document_their_objective(self):
        references = set()
        for path in WORKFLOWS.glob("*.yml"):
            references.update(re.findall(
                r"scripts/ci/(?:test-|verify-|run-|scan-|collect-|validate-|evaluate-|filter-|normalize-)[A-Za-z0-9_.-]+\.(?:sh|py)",
                path.read_text(),
            ))
        self.assertTrue(references)
        for manifest in (ROOT / "scripts/ci/suites").glob("*.txt"):
            references.update(line for line in manifest.read_text().splitlines() if line.startswith("scripts/ci/"))
        for reference in sorted(references):
            with self.subTest(script=reference):
                header = "\n".join((ROOT / reference).read_text().splitlines()[:12])
                self.assertRegex(header, r"(?m)^# Check objective: [A-Z].+\.$")


if __name__ == "__main__":
    unittest.main()
