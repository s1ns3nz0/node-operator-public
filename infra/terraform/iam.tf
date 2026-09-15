data "aws_iam_policy_document" "eks_cluster_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${local.name_prefix}-eks-cluster"
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume_role.json

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

data "aws_iam_policy_document" "node_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "nodes" {
  name               = "${local.name_prefix}-nodes"
  assume_role_policy = data.aws_iam_policy_document.node_assume_role.json

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_ecr_read_only" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

data "aws_iam_policy_document" "ebs_csi_assume_role" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

locals {
  # Existing clusters may still reference this pre-baseline EBS key through
  # the stable alias. Keep it readable during the one-way key migration.
  legacy_ebs_kms_key_arn = "arn:aws:kms:${var.aws_region}:${var.aws_account_id}:key/284d9f2f-7ace-4313-bd0e-be1cb5b8ecb9"
}

resource "aws_iam_role" "ebs_csi" {
  name               = "${local.name_prefix}-ebs-csi"
  assume_role_policy = data.aws_iam_policy_document.ebs_csi_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "ebs_csi" {
  statement {
    sid = "DescribeOnlyInApprovedRegion"
    actions = [
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInstances",
      "ec2:DescribeSnapshots",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVolumesModifications",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid = "CreateOnlyCSIManagedVolumes"
    actions = [
      "ec2:CreateVolume",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid = "ManageOnlyCSIManagedVolumes"
    actions = [
      "ec2:DeleteVolume",
      "ec2:AttachVolume",
      "ec2:DetachVolume",
      "ec2:DeleteTags",
      "ec2:ModifyVolume",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }

    condition {
      test     = "ForAllValues:StringLike"
      variable = "aws:TagKeys"
      values   = ["ebs.csi.aws.com/cluster", "CSIVolumeName", "kubernetes.io/created-for/*"]
    }
  }

  # The CSI driver applies its Kubernetes ownership tags in a follow-up
  # CreateTags call.  AWS does not include those request tags in every driver
  # version, so keep the region boundary here and enforce ownership through
  # the dedicated CSI role rather than rejecting legitimate volume creation.
  statement {
    sid       = "TagOnlyCSIManagedVolumes"
    actions   = ["ec2:CreateTags"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid       = "UseOnlyBaselineEBSKey"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncrypt*"]
    resources = distinct([aws_kms_key.ebs.arn, local.legacy_ebs_kms_key_arn])
  }

  statement {
    sid       = "CreateOnlyAWSResourceGrantsForBaselineEBSKey"
    actions   = ["kms:CreateGrant"]
    resources = distinct([aws_kms_key.ebs.arn, local.legacy_ebs_kms_key_arn])

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy" "ebs_csi" {
  name   = "${local.name_prefix}-ebs-csi"
  role   = aws_iam_role.ebs_csi.id
  policy = data.aws_iam_policy_document.ebs_csi.json
}

data "aws_iam_policy_document" "config_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${local.name_prefix}-config"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "vault_pod_assume_role" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "vault_kms" {
  statement {
    actions   = ["kms:DescribeKey"]
    resources = [aws_kms_key.vault.arn]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:Encrypt"]
    resources = [aws_kms_key.vault.arn]
  }

  statement {
    actions   = ["kms:CreateGrant"]
    resources = [aws_kms_key.vault.arn]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "vault" {
  name               = "${local.name_prefix}-vault"
  assume_role_policy = data.aws_iam_policy_document.vault_pod_assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "vault_kms" {
  name   = "${local.name_prefix}-vault-kms"
  role   = aws_iam_role.vault.id
  policy = data.aws_iam_policy_document.vault_kms.json
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}
