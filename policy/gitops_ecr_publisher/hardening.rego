package nodeoperator.gitops_ecr_publisher

import rego.v1

approved_repository := "s1ns3nz0/node-operator-gitops"
approved_environment := "gitops-client-ecr-publish"

required_push_actions := {
  "ecr:BatchCheckLayerAvailability",
  "ecr:BatchGetImage",
  "ecr:CompleteLayerUpload",
  "ecr:DescribeImages",
  "ecr:InitiateLayerUpload",
  "ecr:PutImage",
  "ecr:UploadLayerPart",
}

deny contains {"id": "gitops-client-publisher.repository", "msg": "publisher must trust only the dedicated GitOps client repository"} if {
  input.publisher.repository != approved_repository
}

deny contains {"id": "gitops-client-publisher.environment", "msg": "publisher must require the protected GitOps client publishing environment"} if {
  input.publisher.environment != approved_environment
}

deny contains {"id": "gitops-client-publisher.audience", "msg": "publisher must require the AWS STS OIDC audience"} if {
  input.publisher.audience != "sts.amazonaws.com"
}

deny contains {"id": "gitops-client-publisher.repository-properties", "msg": "client image repository must be immutable, scanned, and protected from destroy"} if {
  not input.repository.image_tag_mutability == "IMMUTABLE"
}

deny contains {"id": "gitops-client-publisher.repository-properties", "msg": "client image repository must be immutable, scanned, and protected from destroy"} if {
  not input.repository.scan_on_push == true
}

deny contains {"id": "gitops-client-publisher.repository-properties", "msg": "client image repository must be immutable, scanned, and protected from destroy"} if {
  not input.repository.prevent_destroy == true
}

deny contains {"id": "gitops-client-publisher.ecr-scope", "msg": "only ECR authorization-token retrieval may use wildcard resources"} if {
  action := input.permissions[_]
  action.resource == "*"
  action.name != "ecr:GetAuthorizationToken"
}

deny contains {"id": "gitops-client-publisher.ecr-actions", "msg": "publisher must grant exactly the required ECR upload actions"} if {
  actual := {permission.name | permission := input.permissions[_]; permission.name != "ecr:GetAuthorizationToken"}
  actual != required_push_actions
}

deny contains {"id": "gitops-client-publisher.ecr-actions", "msg": "publisher must grant exactly the required ECR upload actions"} if {
  not {permission.name | permission := input.permissions[_]}["ecr:GetAuthorizationToken"]
}
