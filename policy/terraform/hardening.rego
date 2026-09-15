package nodeoperator.terraform

import rego.v1

# This policy intentionally consumes a static, normalized assessment rather
# than Terraform state, provider credentials, or a live plan. The producer is
# responsible for mapping Terraform configuration into `baseline`; this policy
# only evaluates the admitted security boundary.
deny contains violation if {
  baseline := object.get(input, "baseline", null)
  not is_object(baseline)
  violation := finding("terraform.baseline.malformed", "baseline must be a normalized object", "baseline")
}

deny contains violation if {
  baseline := baseline_object
  clusters := object.get(baseline, "eks_clusters", [])
  not is_array(clusters)
  violation := finding("terraform.eks.malformed", "EKS cluster inventory must be an array", "eks_clusters")
}

deny contains violation if {
  clusters := eks_clusters
  count(clusters) != 1
  violation := finding("terraform.eks.count", "baseline must declare exactly one EKS cluster", "eks_clusters")
}

deny contains violation if {
  cluster := eks_clusters[_]
  object.get(cluster, "endpoint_private_access", false) != true
  violation := finding("terraform.eks.private-endpoint", "EKS endpoint private access must be enabled", object.get(cluster, "address", "eks_clusters"))
}

deny contains violation if {
  cluster := eks_clusters[_]
  object.get(cluster, "endpoint_public_access", true) != false
  violation := finding("terraform.eks.public-endpoint", "EKS endpoint public access must be disabled", object.get(cluster, "address", "eks_clusters"))
}

deny contains violation if {
  cluster := eks_clusters[_]
  encrypted_resources := object.get(cluster, "encrypted_resources", [])
  not is_array(encrypted_resources)
  violation := finding("terraform.eks.encryption-malformed", "EKS encrypted resources must be an array", object.get(cluster, "address", "eks_clusters"))
}

deny contains violation if {
  cluster := eks_clusters[_]
  encrypted_resources := object.get(cluster, "encrypted_resources", [])
  is_array(encrypted_resources)
  not "secrets" in encrypted_resources
  violation := finding("terraform.eks.secrets-encryption", "EKS control-plane secrets encryption must be enabled", object.get(cluster, "address", "eks_clusters"))
}

deny contains violation if {
  cluster := eks_clusters[_]
  not valid_kms_key_arn(object.get(cluster, "kms_key_arn", ""))
  violation := finding("terraform.eks.kms-key", "EKS control-plane encryption must use a KMS key ARN", object.get(cluster, "address", "eks_clusters"))
}

deny contains violation if {
  baseline := baseline_object
  groups := object.get(baseline, "managed_node_groups", [])
  not is_array(groups)
  violation := finding("terraform.node-group.malformed", "managed node-group inventory must be an array", "managed_node_groups")
}

deny contains violation if {
  groups := managed_node_groups
  count(groups) != 3
  violation := finding("terraform.node-group.count", "baseline must declare exactly system, consensus, and execution managed node groups", "managed_node_groups")
}

deny contains violation if {
  group := managed_node_groups[_]
  not valid_pool_role(group)
  violation := finding("terraform.node-group.role", "managed node group must declare one approved node-operator.io/role", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  role := {"system", "consensus", "execution"}[_]
  not pool_present(role)
  violation := finding("terraform.node-group.required-pool", sprintf("baseline must declare the %s managed node group", [role]), "managed_node_groups")
}

deny contains violation if {
  group := managed_node_groups[_]
  valid_pool_role(group)
  not valid_instance_type(group)
  violation := finding("terraform.node-group.instance-type", "managed node group instance type must match its approved role", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  group := managed_node_groups[_]
  scaling := object.get(group, "scaling", {})
  not is_object(scaling)
  violation := finding("terraform.node-group.scaling-malformed", "managed node-group scaling must be an object", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  group := managed_node_groups[_]
  scaling := object.get(group, "scaling", {})
  is_object(scaling)
  not valid_scaling(group, scaling)
  violation := finding("terraform.node-group.scaling", "system nodes must remain always-on for Argo CD and platform services; Hoodi client nodes must remain scale-to-zero", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  group := managed_node_groups[_]
  azs := object.get(group, "availability_zones", [])
  not is_array(azs)
  violation := finding("terraform.node-group.az-malformed", "managed node-group availability zones must be an array", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  group := managed_node_groups[_]
  azs := object.get(group, "availability_zones", [])
  is_array(azs)
  not two_distinct_azs(azs)
  violation := finding("terraform.node-group.two-az", "managed node group must span exactly two distinct availability zones", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  group := managed_node_groups[_]
  object.get(group, "public_ip_association", true) != false
  violation := finding("terraform.node-group.public-ip", "managed node group must not associate public IP addresses", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  group := managed_node_groups[_]
  subnets := object.get(group, "private_subnet_ids", [])
  not is_array(subnets)
  violation := finding("terraform.node-group.private-subnets-malformed", "managed node-group private subnet IDs must be an array", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  group := managed_node_groups[_]
  subnets := object.get(group, "private_subnet_ids", [])
  is_array(subnets)
  count(subnets) < 2
  violation := finding("terraform.node-group.private-subnets", "managed node group must use at least two private subnets", object.get(group, "address", "managed_node_groups"))
}

deny contains violation if {
  baseline := baseline_object
  policies := object.get(baseline, "iam_policies", [])
  not is_array(policies)
  violation := finding("terraform.iam.malformed", "IAM policy inventory must be an array", "iam_policies")
}

deny contains violation if {
  policies := iam_policies
  count(policies) == 0
  violation := finding("terraform.iam.missing", "baseline must declare its node IAM policies", "iam_policies")
}

deny contains violation if {
  policy := iam_policies[_]
  statements := object.get(policy, "statements", [])
  not is_array(statements)
  violation := finding("terraform.iam.statement-malformed", "IAM policy statements must be an array", object.get(policy, "address", "iam_policies"))
}

deny contains violation if {
  policy := iam_policies[_]
  statements := object.get(policy, "statements", [])
  is_array(statements)
  count(statements) == 0
  violation := finding("terraform.iam.statement-missing", "IAM policy must contain explicit statements", object.get(policy, "address", "iam_policies"))
}

deny contains violation if {
  statement := iam_statements[_]
  allow_statement(statement)
  not valid_actions(statement)
  violation := finding("terraform.iam.actions-malformed", "allow IAM statements must declare an action array", statement_location(statement))
}

deny contains violation if {
  statement := iam_statements[_]
  allow_statement(statement)
  action := object.get(statement, "actions", [])[_]
  is_string(action)
  wildcard_action(action)
  violation := finding("terraform.iam.wildcard-action", "IAM allow actions must not use wildcards", statement_location(statement))
}

deny contains violation if {
  statement := iam_statements[_]
  allow_statement(statement)
  action := object.get(statement, "actions", [])[_]
  is_string(action)
  mutating_action(action)
  violation := finding("terraform.iam.mutation", "node IAM policy must be read-only and must not grant mutation actions", statement_location(statement))
}

deny contains violation if {
  statement := iam_statements[_]
  allow_statement(statement)
  action := object.get(statement, "actions", [])[_]
  is_string(action)
  sensitive_data_action(action)
  broad_resources(statement)
  violation := finding("terraform.iam.broad-data-access", "S3 and PostgreSQL-related IAM access must name exact resources", statement_location(statement))
}

baseline_object := baseline if {
  baseline := object.get(input, "baseline", {})
  is_object(baseline)
}

eks_clusters := clusters if {
  baseline := baseline_object
  clusters := object.get(baseline, "eks_clusters", [])
  is_array(clusters)
}

managed_node_groups := groups if {
  baseline := baseline_object
  groups := object.get(baseline, "managed_node_groups", [])
  is_array(groups)
}

iam_policies := policies if {
  baseline := baseline_object
  policies := object.get(baseline, "iam_policies", [])
  is_array(policies)
}

iam_statements contains statement if {
  policy := iam_policies[_]
  statements := object.get(policy, "statements", [])
  is_array(statements)
  statement := statements[_]
  is_object(statement)
}

valid_kms_key_arn(key_arn) if {
  is_string(key_arn)
  startswith(key_arn, "arn:")
  contains(key_arn, ":kms:")
}

pool_role(group) := role if {
  labels := object.get(group, "labels", {})
  is_object(labels)
  role := object.get(labels, "node-operator.io/role", "")
}

pool_present(role) if {
  group := managed_node_groups[_]
  pool_role(group) == role
}

valid_pool_role(group) if {
  pool_role(group) in {"system", "consensus", "execution"}
}

valid_instance_type(group) if {
  pool_role(group) in {"system", "consensus"}
  object.get(group, "instance_types", []) == ["m7i.2xlarge"]
}

valid_instance_type(group) if {
  pool_role(group) == "execution"
  object.get(group, "instance_types", []) == ["m7i.4xlarge"]
}

valid_scaling(group, scaling) if {
  pool_role(group) == "system"
  object.get(scaling, "min_size", null) == 3
  object.get(scaling, "desired_size", null) == 3
  object.get(scaling, "max_size", null) == 3
}

valid_scaling(group, scaling) if {
  pool_role(group) in {"consensus", "execution"}
  object.get(scaling, "min_size", null) == 0
  object.get(scaling, "desired_size", null) in {0, 1}
  object.get(scaling, "max_size", null) == 1
}

two_distinct_azs(azs) if {
  count(azs) == 2
  every az in azs { is_string(az) }
  count({az | az := azs[_]}) == 2
}

allow_statement(statement) if {
  lower(object.get(statement, "effect", "")) == "allow"
}

valid_actions(statement) if {
  actions := object.get(statement, "actions", [])
  is_array(actions)
  count(actions) > 0
  every action in actions { is_string(action) }
}

wildcard_action(action) if {
  contains(action, "*")
}

mutating_action(action) if {
  parts := split(lower(action), ":")
  count(parts) == 2
  operation := parts[1]
  mutation_prefix := ["add", "approve", "associate", "attach", "cancel", "change", "copy", "create", "delete", "deregister", "detach", "disable", "disassociate", "enable", "execute", "export", "grant", "import", "invoke", "modify", "move", "pass", "patch", "publish", "put", "reboot", "register", "remove", "replace", "restore", "revoke", "rotate", "run", "send", "set", "start", "stop", "tag", "terminate", "untag", "update", "write"][_]
  startswith(operation, mutation_prefix)
}

sensitive_data_action(action) if {
  normalized := lower(action)
  startswith(normalized, "s3:")
}

sensitive_data_action(action) if {
  normalized := lower(action)
  startswith(normalized, "rds:")
}

sensitive_data_action(action) if {
  normalized := lower(action)
  startswith(normalized, "rds-db:")
}

sensitive_data_action(action) if {
  normalized := lower(action)
  startswith(normalized, "postgresql:")
}

broad_resources(statement) if {
  resources := object.get(statement, "resources", [])
  not is_array(resources)
}

broad_resources(statement) if {
  resources := object.get(statement, "resources", [])
  is_array(resources)
  count(resources) == 0
}

broad_resources(statement) if {
  resources := object.get(statement, "resources", [])
  is_array(resources)
  resource := resources[_]
  not is_string(resource)
}

broad_resources(statement) if {
  resources := object.get(statement, "resources", [])
  is_array(resources)
  resource := resources[_]
  is_string(resource)
  contains(resource, "*")
}

statement_location(statement) := object.get(statement, "address", "iam_policies")

finding(id, msg, location) := {"id": id, "msg": msg, "location": location}
