package nodeoperator.cis_eks

import rego.v1

# Node assessment prerequisite only. AWS/customer configuration and manual
# checks are separate evidence; this rule never asserts full CIS compliance.
default worker_node_pass := false

worker_node_pass if {
    input.schema_version == 1
    input.scope == "eks-worker-node"
    input.benchmark == data.data.cis_eks.benchmark
    input.source_revision == data.data.cis_eks.source_revision
    input.full_cluster_compliance == false
    is_string(input.node)
    count(input.node) > 0
    regex.match(`^[0-9a-f]{64}$`, input.raw_sha256)
    expected := {id | some id in data.data.cis_eks.required_check_ids}
    actual := {result.id | some result in input.results}
    actual == expected
    count(input.results) == count(expected)
    every result in input.results { result.status == "PASS" }
    input.counts == {"PASS": count(expected), "FAIL": 0, "WARN": 0, "INFO": 0}
}
