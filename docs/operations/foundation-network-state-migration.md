# Foundation-network state migration

This procedure is for a separately approved maintenance window. It is not
authorized by the backend declaration or the local candidate reconciliation.

1. Copy `infra/foundation-network/backend.hcl.example` outside the release
   bundle. Verify its bucket, region, lock table, encryption and CMK against
   bootstrap outputs, and retain the isolated foundation key unchanged.
2. Before `terraform init -backend-config=FILE -migrate-state`, prove the
   destination object is absent and the approved role can perform encrypted
   state read/write and DynamoDB locking. Keep a mode-600 private local backup.
3. Review the exact migration prompt and state metadata. Never use force-copy.
   Compare canonical content and every managed address/resource ID before and
   after migration; lineage and serial changes require separate explanation.
4. Run an existing-mode refresh-backed plan. It must have no create, destroy,
   replacement, or routing change. Retain raw state and plans privately.

Do not migrate baseline, bootstrap, ops-access, VPC-private, or workload state
in this procedure.
