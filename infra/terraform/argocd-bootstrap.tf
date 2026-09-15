variable "enable_argocd_bootstrap_runner" {
  description = "Create the one-purpose, VPC-internal CodeBuild executor used to install the reviewed private Argo CD chart."
  type        = bool
  default     = false
}

variable "enable_argocd_bootstrap_cluster_admin" {
  description = "Grant the temporary cluster-admin policy needed only while Helm installs the Argo CD control plane. Disable immediately after successful bootstrap."
  type        = bool
  default     = false
}

variable "argocd_bootstrap_subnet_ids" {
  description = "Explicit private subnet IDs for the Argo CD bootstrap executor. Required only when it is enabled."
  type        = list(string)
  default     = []
}

variable "argocd_bootstrap_image" {
  description = "Digest-pinned private ECR image containing Helm, kubectl, AWS CLI, and the reviewed Argo CD values. Required only when the executor is enabled."
  type        = string
  default     = ""

  validation {
    condition     = var.argocd_bootstrap_image == "" || can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z]{2}-[a-z0-9-]+-[0-9]+\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$", var.argocd_bootstrap_image))
    error_message = "argocd_bootstrap_image must be empty while disabled or a same-region private ECR image pinned by a sha256 digest."
  }
}

variable "gitops_client_chart_version" {
  description = "Exact immutable GitOps client chart version emitted by the protected publisher."
  type        = string
  default     = ""

  validation {
    condition     = var.gitops_client_chart_version == "" || can(regex("^0\\.1\\.[0-9]+$", var.gitops_client_chart_version))
    error_message = "gitops_client_chart_version must be empty while disabled or a publisher-issued 0.1.N version."
  }
}

variable "gitops_client_chart_oci_digest" {
  description = "OCI digest that the exact GitOps client chart version must resolve to."
  type        = string
  default     = ""

  validation {
    condition     = var.gitops_client_chart_oci_digest == "" || can(regex("^sha256:[a-f0-9]{64}$", var.gitops_client_chart_oci_digest))
    error_message = "gitops_client_chart_oci_digest must be empty while disabled or an immutable sha256 digest."
  }
}

variable "gitops_client_chart_values" {
  description = "Exact non-secret deployment-profile values rendered from the approved chart and mirror receipts."
  type = object({
    deployment = object({
      profile         = string
      storageKmsKeyId = string
    })
    dast = object({
      enabled = bool
    })
    clients = object({
      vaultAgentImage = string
      deployment = object({
        nethermindImage = string
        prysmImage      = string
        prysmP2PHostIp  = string
      })
    })
  })
  default  = null
  nullable = true

  validation {
    condition = var.gitops_client_chart_values == null ? true : (
      var.gitops_client_chart_values.deployment.profile == "deployment" &&
      var.gitops_client_chart_values.dast.enabled == false &&
      can(regex("^arn:aws:kms:[a-z]{2}-[a-z0-9-]+-[0-9]+:[0-9]{12}:key/[A-Za-z0-9-]+$", var.gitops_client_chart_values.deployment.storageKmsKeyId)) &&
      can(regex("^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$", var.gitops_client_chart_values.clients.deployment.prysmP2PHostIp)) &&
      alltrue([for image in [
        var.gitops_client_chart_values.clients.vaultAgentImage,
        var.gitops_client_chart_values.clients.deployment.nethermindImage,
        var.gitops_client_chart_values.clients.deployment.prysmImage,
      ] : can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z]{2}-[a-z0-9-]+-[0-9]+\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$", image))])
    )
    error_message = "gitops_client_chart_values must be the complete deployment profile: DAST disabled, a KMS ARN, an IPv4 Prysm P2P host, and three private-ECR digest references."
  }
}

variable "offline_hoodi_nat_public_ip" {
  description = "Synthetic authoritative Hoodi NAT public IP for network-isolated validation only. Never set for an apply."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.offline_hoodi_nat_public_ip == null || can(regex("^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$", var.offline_hoodi_nat_public_ip))
    error_message = "offline_hoodi_nat_public_ip must be an IPv4 address."
  }
}

locals {
  # Offline plans cannot query AWS data sources. The fixture must provide a
  # synthetic NAT address explicitly; live plans always use the existing NAT
  # gateway lookup and never accept this mock.
  argocd_hoodi_nat_public_ip = var.offline_validation ? var.offline_hoodi_nat_public_ip : try(data.aws_nat_gateway.hoodi_egress[0].public_ip, null)
}

variable "cert_manager_chart_manifest_digest" {
  description = "OCI manifest digest for the reviewed cert-manager chart mirrored into the private ECR repository."
  type        = string
  default     = "sha256:62c4745561eccfd723678c6547500750ebef5a880d81ff670d33124ab335f877"

  validation {
    condition     = can(regex("^sha256:[a-f0-9]{64}$", var.cert_manager_chart_manifest_digest))
    error_message = "cert_manager_chart_manifest_digest must be an OCI sha256 manifest digest."
  }
}

locals {
  argocd_chart_version       = "10.4.0"
  cert_manager_chart_version = "v1.21.1"
}

resource "aws_security_group" "argocd_bootstrap" {
  count       = var.enable_argocd_bootstrap_runner ? 1 : 0
  name_prefix = "${local.name_prefix}-argocd-bootstrap-"
  description = "Private Argo CD bootstrap executor egress to the EKS API and approved VPC endpoints only."
  vpc_id      = local.network_vpc_id

  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id, aws_security_group.endpoints.id]
    description     = "HTTPS to the private EKS API and approved interface endpoints"
  }

  # ECR returns presigned URLs for image/chart layers in AWS-managed S3. The
  # gateway endpoint keeps this private; its managed prefix list is narrower
  # than a CIDR-based internet egress rule.
  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [var.offline_validation ? "pl-78a54011" : data.aws_prefix_list.s3[0].id]
    description     = "HTTPS to ECR-managed S3 layers through the gateway endpoint"
  }

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-argocd-bootstrap"
    Purpose = "private-argocd-bootstrap"
  })
}

resource "aws_vpc_security_group_ingress_rule" "cluster_api_from_argocd_bootstrap" {
  count                        = var.enable_argocd_bootstrap_runner ? 1 : 0
  description                  = "Kubernetes API from private Argo CD bootstrap executor"
  security_group_id            = aws_security_group.cluster.id
  referenced_security_group_id = aws_security_group.argocd_bootstrap[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_iam_role" "argocd_bootstrap" {
  count = var.enable_argocd_bootstrap_runner ? 1 : 0
  name  = "${local.name_prefix}-argocd-bootstrap"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

data "aws_iam_policy_document" "argocd_bootstrap" {
  count = var.enable_argocd_bootstrap_runner ? 1 : 0

  statement {
    sid       = "WriteOnlyBootstrapLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.argocd_bootstrap[0].arn}:*"]
  }

  statement {
    sid       = "DescribeOnlyTargetCluster"
    actions   = ["eks:DescribeCluster"]
    resources = [aws_eks_cluster.private.arn]
  }

  # CodeBuild creates and tears down an ENI in the explicitly configured
  # private subnets. These EC2 control-plane calls do not grant instance or
  # security-group mutation authority.
  statement {
    sid = "ManageOnlyCodeBuildVpcNetworkInterface"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "GetEcrAuthorizationToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "PullOnlyPrivateBootstrapImageAndChart"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:GetDownloadUrlForLayer",
    ]
    # Keep this existing pull scope independent from unrelated additions to the
    # private GitOps repository map. The repository name is deterministic and
    # already enforced by the private GitOps foundation.
    resources = [
      "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/${local.private_gitops_repositories.argocd}",
      "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/${local.private_gitops_repositories.argocd_chart}",
      "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/${local.private_gitops_repositories.cert_manager}",
      "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/${local.private_gitops_repositories.cert_manager_chart}",
      aws_ecr_repository.gitops_client_chart[0].arn,
    ]
  }
}

resource "aws_iam_role_policy" "argocd_bootstrap" {
  count  = var.enable_argocd_bootstrap_runner ? 1 : 0
  name   = "${local.name_prefix}-argocd-bootstrap"
  role   = aws_iam_role.argocd_bootstrap[0].id
  policy = data.aws_iam_policy_document.argocd_bootstrap[0].json
}

resource "aws_cloudwatch_log_group" "argocd_bootstrap" {
  count             = var.enable_argocd_bootstrap_runner ? 1 : 0
  name              = "/aws/codebuild/${local.name_prefix}-argocd-bootstrap"
  retention_in_days = 30
  tags              = local.common_tags
}

# This is intentionally a dedicated, temporary cluster-admin access entry.
# Helm installs Argo CD CRDs and cluster-scoped RBAC. It must be removed by
# disabling this runner after the bootstrap evidence is accepted; it is never
# granted to a GitHub OIDC principal.
resource "aws_eks_access_entry" "argocd_bootstrap" {
  count         = var.enable_argocd_bootstrap_runner ? 1 : 0
  cluster_name  = aws_eks_cluster.private.name
  principal_arn = aws_iam_role.argocd_bootstrap[0].arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "argocd_bootstrap" {
  count         = var.enable_argocd_bootstrap_runner && var.enable_argocd_bootstrap_cluster_admin ? 1 : 0
  cluster_name  = aws_eks_cluster.private.name
  principal_arn = aws_iam_role.argocd_bootstrap[0].arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.argocd_bootstrap]
}

resource "aws_codebuild_project" "argocd_bootstrap" {
  count         = var.enable_argocd_bootstrap_runner ? 1 : 0
  name          = "${local.name_prefix}-argocd-bootstrap"
  description   = "One-purpose private Argo CD bootstrap executor"
  service_role  = aws_iam_role.argocd_bootstrap[0].arn
  build_timeout = 30

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = var.argocd_bootstrap_image
    type                        = "LINUX_CONTAINER"
    privileged_mode             = false
    image_pull_credentials_type = "SERVICE_ROLE"
  }

  vpc_config {
    vpc_id             = local.network_vpc_id
    subnets            = var.argocd_bootstrap_subnet_ids
    security_group_ids = [aws_security_group.argocd_bootstrap[0].id]
  }

  # NO_SOURCE and an inline, immutable Terraform buildspec remove a mutable
  # repository/S3 input. The only deployment payload is the pinned ECR image.
  source {
    type      = "NO_SOURCE"
    buildspec = <<-YAML
      version: 0.2
      phases:
        build:
          commands:
            - set -eu
            - aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.private.name}
            - aws ecr get-login-password --region ${var.aws_region} | helm registry login --username AWS --password-stdin ${var.aws_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com
            # Older approved bootstrap images may contain only the Argo CD
            # values file.  Rehydrate the reviewed, non-secret inputs from the
            # Terraform release bundle so the immutable image remains usable
            # without depending on a mutable repository or public network.
            - test -f /opt/node-operator/argocd-private-values.yaml || (echo '${base64encode(try(file("${path.module}/argocd-private-values.example.yaml"), file("${path.module}/../../docs/gitops/argocd-private-values.example.yaml")))}' | base64 -d > /opt/node-operator/argocd-private-values.yaml)
            - test -f /opt/node-operator/cert-manager-values.yaml || (echo '${base64encode(try(file("${path.module}/cert-manager-values.example.yaml"), file("${path.module}/../../docs/gitops/cert-manager-values.example.yaml")))}' | base64 -d > /opt/node-operator/cert-manager-values.yaml)
            - test -f /opt/node-operator/vault-tls-internal-ca.yaml || (echo '${base64encode(try(file("${path.module}/vault-tls-internal-ca.example.yaml"), file("${path.module}/../../docs/gitops/vault-tls-internal-ca.example.yaml")))}' | base64 -d > /opt/node-operator/vault-tls-internal-ca.yaml)
            # The release image embeds reviewed values, while repository names
            # are deployment-scoped. Rewrite only the non-secret ECR prefix at
            # runtime so a zero-resource account never pulls another stack's
            # images.
            # The reviewed values files carry the Seoul source registry as
            # provenance metadata.  Rewrite both the deployment prefix and
            # registry region before the private-cluster install; otherwise
            # nodes in a new region try to pull over a non-existent cross-
            # region ECR endpoint and remain in ImagePullBackOff.
            - sed -i -e 's#node-operator-baseline#${local.name_prefix}#g' -e 's#ap-northeast-2#${var.aws_region}#g' /opt/node-operator/argocd-private-values.yaml /opt/node-operator/cert-manager-values.yaml
            # A mirror operation can select an architecture or convert the
            # manifest. Resolve the destination reference before Helm renders
            # workloads; shell $variables remain literal in Terraform heredocs.
            - |
              for image_tag in 416a2d76870d996460e62bd7f521bf14fa017be9e3e904aab92163a331fcb61a d8b3961b51c8c7320633f8208dc46bf88aa13804d0f7cbe48a096b2c523cee42 ccf6b919ec0500745a47a910118f834f9636d0aac1ff221245cd2557ed8c7c98 d8ab6416e6e7303a86fa0a8daa82c94a8001f21c9d78eb2e7db20534e5d07ae8; do
                destination_digest="$(aws ecr describe-images --region ${var.aws_region} --repository-name ${aws_ecr_repository.private_gitops["cert_manager"].name} --image-ids imageTag="$image_tag" --query 'imageDetails[0].imageDigest' --output text)"
                printf '%s\n' "$destination_digest" | grep -Eq '^sha256:[a-f0-9]{64}$'
                sed -i "s#sha256:$image_tag#$destination_digest#g" /opt/node-operator/cert-manager-values.yaml
              done
            - helm upgrade --install argocd oci://${aws_ecr_repository.private_gitops["argocd_chart"].repository_url} --version ${local.argocd_chart_version} --namespace argocd --create-namespace --values /opt/node-operator/argocd-private-values.yaml --atomic --timeout 10m
            - kubectl wait --namespace argocd --for=condition=Available deployment/argocd-server --timeout=10m
            - helm upgrade --install cert-manager oci://${aws_ecr_repository.private_gitops["cert_manager_chart"].repository_url}@${var.cert_manager_chart_manifest_digest} --version ${local.cert_manager_chart_version} --namespace cert-manager --create-namespace --values /opt/node-operator/cert-manager-values.yaml --atomic --timeout 10m
            - kubectl wait --namespace cert-manager --for=condition=Available deployment/cert-manager --timeout=10m
            - kubectl wait --namespace cert-manager --for=condition=Available deployment/cert-manager-webhook --timeout=10m
            - kubectl wait --namespace cert-manager --for=condition=Available deployment/cert-manager-cainjector --timeout=10m
            - kubectl create namespace vault --dry-run=client -o yaml | kubectl apply -f -
            - kubectl label namespace vault pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest pod-security.kubernetes.io/audit=restricted pod-security.kubernetes.io/audit-version=latest pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/warn-version=latest --overwrite
            - kubectl apply -f /opt/node-operator/vault-tls-internal-ca.yaml
            - kubectl -n vault wait --for=condition=Ready certificate/vault-internal-ca --timeout=10m
            - kubectl -n vault wait --for=condition=Ready certificate/vault-server-tls --timeout=10m
            - kubectl -n vault get secret vault-tls -o name | grep -Fx 'secret/vault-tls'
            - test "$(aws ecr describe-images --region ${var.aws_region} --repository-name ${aws_ecr_repository.gitops_client_chart[0].name} --image-ids imageTag=${var.gitops_client_chart_version} --query 'imageDetails[0].imageDigest' --output text)" = "${var.gitops_client_chart_oci_digest}"
            - |
              cat <<'EOF' | kubectl apply -f -
              apiVersion: rbac.authorization.k8s.io/v1
              kind: Role
              metadata:
                name: node-operator-private-cd-application-reader
                namespace: argocd
              rules:
                - apiGroups: ["argoproj.io"]
                  resources: ["applications"]
                  resourceNames: ["node-operator-client"]
                  verbs: ["get"]
              ---
              apiVersion: rbac.authorization.k8s.io/v1
              kind: RoleBinding
              metadata:
                name: node-operator-private-cd-application-reader
                namespace: argocd
              roleRef:
                apiGroup: rbac.authorization.k8s.io
                kind: Role
                name: node-operator-private-cd-application-reader
              subjects:
                - kind: Group
                  name: node-operator:gitops-private-cd-readers
                  apiGroup: rbac.authorization.k8s.io
              EOF
            - |
              password="$(aws ecr get-login-password --region ${var.aws_region})"
              kubectl -n argocd create secret generic argocd-ecr-oci \
                --from-literal=type=helm \
                --from-literal=url=${aws_ecr_repository.gitops_client[0].repository_url} \
                --from-literal=username=AWS \
                --from-literal=password="$password" \
                --from-literal=enableOCI=true \
                --dry-run=client -o yaml | kubectl -n argocd apply -f -
              kubectl -n argocd label secret argocd-ecr-oci argocd.argoproj.io/secret-type=repo-creds --overwrite
            - |
              cat <<'EOF' | kubectl apply -f -
              apiVersion: v1
              kind: ServiceAccount
              metadata: {name: argocd-ecr-refresher, namespace: argocd}
              ---
              apiVersion: rbac.authorization.k8s.io/v1
              kind: Role
              metadata: {name: argocd-ecr-repo-creds-writer, namespace: argocd}
              rules:
                - apiGroups: [""]
                  resources: ["secrets"]
                  resourceNames: ["argocd-ecr-oci"]
                  verbs: ["get", "patch", "update"]
              ---
              apiVersion: rbac.authorization.k8s.io/v1
              kind: RoleBinding
              metadata: {name: argocd-ecr-repo-creds-writer, namespace: argocd}
              subjects: [{kind: ServiceAccount, name: argocd-ecr-refresher, namespace: argocd}]
              roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: argocd-ecr-repo-creds-writer}
              ---
              apiVersion: batch/v1
              kind: CronJob
              metadata: {name: argocd-ecr-oci-credentials, namespace: argocd}
              spec:
                schedule: "17 */6 * * *"
                concurrencyPolicy: Forbid
                successfulJobsHistoryLimit: 1
                failedJobsHistoryLimit: 2
                jobTemplate:
                  spec:
                    backoffLimit: 2
                    template:
                      spec:
                        serviceAccountName: argocd-ecr-refresher
                        restartPolicy: OnFailure
                        securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, seccompProfile: {type: RuntimeDefault}}
                        containers:
                          - name: refresh
                            image: ${var.argocd_bootstrap_image}
                            command: ["/bin/sh", "-ec"]
                            args:
                              - |
                                password="$(aws ecr get-login-password --region ${var.aws_region})"
                                test -n "$password"
                                kubectl -n argocd create secret generic argocd-ecr-oci --from-literal=type=helm --from-literal=url=${aws_ecr_repository.gitops_client[0].repository_url} --from-literal=username=AWS --from-literal=password="$password" --from-literal=enableOCI=true --dry-run=client -o yaml | kubectl -n argocd apply -f -
                                kubectl -n argocd label secret argocd-ecr-oci argocd.argoproj.io/secret-type=repo-creds --overwrite
                            securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}, readOnlyRootFilesystem: true, runAsNonRoot: true}
                            resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {cpu: 200m, memory: 128Mi}}
                            env: [{name: HOME, value: /tmp}]
                            volumeMounts: [{name: tmp, mountPath: /tmp}]
                        volumes: [{name: tmp, emptyDir: {}}]
              EOF
            - |
              cat <<'EOF' | kubectl apply -f -
              apiVersion: argoproj.io/v1alpha1
              kind: Application
              metadata:
                name: node-operator-client
                namespace: argocd
              spec:
                project: default
                source:
                  repoURL: ${aws_ecr_repository.gitops_client[0].repository_url}
                  chart: node-operator-client
                  targetRevision: ${var.gitops_client_chart_version}
                  helm:
                    valuesObject: ${jsonencode(var.gitops_client_chart_values)}
                destination:
                  server: https://kubernetes.default.svc
                  namespace: node-operator
                syncPolicy:
                  automated:
                    prune: false
                    selfHeal: true
                  syncOptions:
                    - CreateNamespace=false
              EOF
            # Applying the Application only stores its desired state. Wait for
            # Argo CD to compare and sync the digest-verified source, but do
            # not treat workload health as readiness: a first Vault install is
            # expected to remain sealed and uninitialized until its separate
            # approved ceremony.
            - |
              if ! kubectl -n argocd wait --for=jsonpath='{.status.sync.status}'=Synced application/node-operator-client --timeout=10m; then
                kubectl -n argocd get application/node-operator-client -o jsonpath='sync={.status.sync.status} health={.status.health.status} message={.status.operationState.message}{"\\n"}' || true
                printf '%s\n' 'Argo CD did not sync the digest-verified node-operator-client source; inspect its comparison error before retrying.' >&2
                exit 70
              fi
    YAML
  }

  lifecycle {
    # Keep the NAT binding independent of resource-derived values below. This
    # makes a mismatched deployment P2P address fail during plan, before an
    # Argo bootstrap apply can create any resources.
    precondition {
      condition = (
        local.argocd_hoodi_nat_public_ip != null &&
        var.gitops_client_chart_values != null &&
        var.gitops_client_chart_values.clients.deployment.prysmP2PHostIp == local.argocd_hoodi_nat_public_ip &&
        (!local.use_foundation_network || try(var.foundation_network.hoodi_nat_public_ip == local.argocd_hoodi_nat_public_ip, false))
      )
      error_message = "Argo NAT binding precondition failed."
    }

    precondition {
      condition = (
        var.enable_private_gitops_foundation &&
        can(regex("^${var.aws_account_id}\\.dkr\\.ecr\\.${var.aws_region}\\.amazonaws\\.com/${local.private_gitops_repositories.argocd}@sha256:[a-f0-9]{64}$", var.argocd_bootstrap_image)) &&
        can(regex("^0\\.1\\.[0-9]+$", var.gitops_client_chart_version)) &&
        can(regex("^sha256:[a-f0-9]{64}$", var.gitops_client_chart_oci_digest)) &&
        var.gitops_client_chart_values != null &&
        var.gitops_client_chart_values.deployment.profile == "deployment" &&
        var.gitops_client_chart_values.dast.enabled == false &&
        var.gitops_client_chart_values.deployment.storageKmsKeyId == aws_kms_key.ebs.arn &&
        can(regex("^${var.aws_account_id}\\.dkr\\.ecr\\.${var.aws_region}\\.amazonaws\\.com/${local.private_gitops_repositories.vault}@sha256:[a-f0-9]{64}$", var.gitops_client_chart_values.clients.vaultAgentImage)) &&
        can(regex("^${var.aws_account_id}\\.dkr\\.ecr\\.${var.aws_region}\\.amazonaws\\.com/${local.private_gitops_repositories.nodes}@sha256:[a-f0-9]{64}$", var.gitops_client_chart_values.clients.deployment.nethermindImage)) &&
        can(regex("^${var.aws_account_id}\\.dkr\\.ecr\\.${var.aws_region}\\.amazonaws\\.com/${local.private_gitops_repositories.nodes}@sha256:[a-f0-9]{64}$", var.gitops_client_chart_values.clients.deployment.prysmImage)) &&
        length(var.argocd_bootstrap_subnet_ids) > 0 &&
        alltrue([for subnet_id in var.argocd_bootstrap_subnet_ids : can(regex("^subnet-[a-z0-9]+$", subnet_id))])
      )
      error_message = "Enabled Argo CD bootstrap requires the private GitOps ECR foundation, an argocd-repository digest, and one or more explicit private subnet IDs."
    }
  }

  tags = local.common_tags

  depends_on = [aws_eks_access_policy_association.argocd_bootstrap]
}

output "argocd_bootstrap_project_name" {
  description = "Private CodeBuild project for the reviewed Argo CD bootstrap, or null while disabled."
  value       = try(aws_codebuild_project.argocd_bootstrap[0].name, null)
}
