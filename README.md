# node-operator

Secure, read-only EKS node-operator portfolio implementation for Hoodi execution
and consensus clients. Deployment is intentionally out of scope until separately
authorized.

## OpenSSF Best Practices

This project follows the OpenSSF Best Practices criteria. Registration and the
project-specific badge are maintained at [bestpractices.dev](https://bestpractices.dev/);
the repository intentionally does not embed a fabricated project ID.

The repository source is licensed under [Apache-2.0](LICENSE).

## Local policy checks

The policy foundation is runnable without AWS credentials. Install OPA, Conftest,
and ShellCheck, then run:

```bash
scripts/ci/test-policy.sh
scripts/ci/test-normalizer.sh
scripts/ci/test-conftest.sh
scripts/ci/test-script-quality.sh
```

`policy/tests/fixtures/` contains only synthetic, non-sensitive evidence. CI keeps
only normalized JSON/SARIF evidence for 90 days; raw logs and secret candidates are
not retained. See [the policy-as-code guide](docs/policy-as-code.md).
