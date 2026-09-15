package nodeoperator.cis_eks_test

import rego.v1
import data.nodeoperator.cis_eks

valid := {
    "schema_version": 1, "scope": "eks-worker-node", "node": "synthetic-node",
    "benchmark": data.data.cis_eks.benchmark, "source_revision": data.data.cis_eks.source_revision,
    "full_cluster_compliance": false,
    "raw_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "results": [{"id": id, "status": "PASS"} | some id in data.data.cis_eks.required_check_ids],
    "counts": {"PASS": count(data.data.cis_eks.required_check_ids), "FAIL": 0, "WARN": 0, "INFO": 0},
}

test_all_expected_checks_pass if { cis_eks.worker_node_pass with input as valid }
test_empty_denied if { not cis_eks.worker_node_pass with input as {} }
test_missing_checks_denied if {
    not cis_eks.worker_node_pass with input as object.union(valid, {"results": []})
}
test_nonpass_cannot_be_hidden_by_summary if {
    every status in ["FAIL", "WARN", "INFO", "UNKNOWN"] {
        results := [{"id": id, "status": status} | some id in data.data.cis_eks.required_check_ids]
        not cis_eks.worker_node_pass with input as object.union(valid, {"results": results})
    }
}
test_cluster_compliance_overclaim_denied if {
    not cis_eks.worker_node_pass with input as object.union(valid, {"full_cluster_compliance": true})
}
test_wrong_benchmark_denied if {
    not cis_eks.worker_node_pass with input as object.union(valid, {"benchmark": "cis-1.5"})
}
