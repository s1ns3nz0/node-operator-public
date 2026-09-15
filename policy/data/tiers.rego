package nodeoperator.config

import rego.v1

required_evidence := ["gitleaks", "osv", "semgrep", "zizmor", "checkov", "format", "terraform"]
exception_maximum_ttl_hours := 720
sensitive_path_prefixes := ["policy/", ".github/", "infra/", "kubernetes/"]
release_required_evidence := ["posture"]
minimum_scorecard_score := 7
maximum_scan_age_seconds := 86400
trusted_builder_ids := ["https://github.com/Attestations/GitHubHostedActions@v1"]
