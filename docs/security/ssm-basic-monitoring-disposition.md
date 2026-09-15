# Dedicated SSM host: basic monitoring

The user explicitly chose basic EC2 monitoring for the private SSM operations
host. Its purpose is administrative connectivity, not validator execution.
The ops-access module therefore sets `monitoring = false` for fresh and
retained hosts. This avoids enabling paid detailed monitoring solely to satisfy
a generic recommendation. It does not disable Vault audit, validator activity
logging, disk encryption, IMDSv2 or network restrictions.

CKV_AWS_126 remains a scanner finding. A time-bounded, reviewed policy
disposition accepts only that check for `aws_instance.host` in the exact
repository-relative file `infra/ops-access/main.tf`. The trusted collector must
supply the file identity; missing, ambiguous or different file paths do not
match. The disposition cannot use the legacy address-only exception path.
It expires on 2026-10-03; review the operational need before renewal.

This is a user-selected operational tradeoff, not a claim that Checkov passed
or a waiver for EBS optimization (CKV_AWS_135). It does not exempt other hosts,
modules, checks or failures. No live change is required to keep the existing
host at its already-basic monitoring level.
