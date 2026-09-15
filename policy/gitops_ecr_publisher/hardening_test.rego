package nodeoperator.gitops_ecr_publisher_test

import rego.v1
import data.nodeoperator.gitops_ecr_publisher

test_dedicated_publisher_fixture_passes if {
  fixture := {
    "publisher": {"repository": "s1ns3nz0/node-operator-gitops", "environment": "gitops-client-ecr-publish", "audience": "sts.amazonaws.com"},
    "repository": {"image_tag_mutability": "IMMUTABLE", "scan_on_push": true, "prevent_destroy": true},
    "permissions": [
      {"name": "ecr:GetAuthorizationToken", "resource": "*"},
      {"name": "ecr:BatchCheckLayerAvailability", "resource": "arn:aws:ecr:ap-northeast-2:123456789012:repository/node-operator-baseline-gitops-client"},
      {"name": "ecr:BatchGetImage", "resource": "arn:aws:ecr:ap-northeast-2:123456789012:repository/node-operator-baseline-gitops-client"},
      {"name": "ecr:CompleteLayerUpload", "resource": "arn:aws:ecr:ap-northeast-2:123456789012:repository/node-operator-baseline-gitops-client"},
      {"name": "ecr:DescribeImages", "resource": "arn:aws:ecr:ap-northeast-2:123456789012:repository/node-operator-baseline-gitops-client"},
      {"name": "ecr:InitiateLayerUpload", "resource": "arn:aws:ecr:ap-northeast-2:123456789012:repository/node-operator-baseline-gitops-client"},
      {"name": "ecr:PutImage", "resource": "arn:aws:ecr:ap-northeast-2:123456789012:repository/node-operator-baseline-gitops-client"},
      {"name": "ecr:UploadLayerPart", "resource": "arn:aws:ecr:ap-northeast-2:123456789012:repository/node-operator-baseline-gitops-client"},
    ],
  }
  denial := gitops_ecr_publisher.deny with input as fixture
  count(denial) == 0
}

test_shared_repository_or_broad_ecr_access_is_rejected if {
  fixture := {
    "publisher": {"repository": "s1ns3nz0/node-operator", "environment": "gitops-client-ecr-publish", "audience": "sts.amazonaws.com"},
    "repository": {"image_tag_mutability": "MUTABLE", "scan_on_push": false, "prevent_destroy": false},
    "permissions": [
      {"name": "ecr:GetAuthorizationToken", "resource": "*"},
      {"name": "ecr:PutImage", "resource": "*"},
      {"name": "ecr:DeleteImage", "resource": "*"},
    ],
  }
  denial := gitops_ecr_publisher.deny with input as fixture
  denial[_].id == "gitops-client-publisher.repository"
  denial[_].id == "gitops-client-publisher.ecr-scope"
}
