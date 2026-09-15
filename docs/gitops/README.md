# GitOps ownership contract

This repository does not own Kubernetes workload manifests. Terraform creates
the EKS infrastructure only. Argo CD runs inside that cluster and reads
reviewed workload manifests from a separate GitOps repository.

The GitOps repository must provide the Argo CD `Application` source (`repoURL`,
`targetRevision`, and `path`) and must not contain kubeconfigs, tokens, or
production credentials. The application destination and namespace are supplied
through an approved environment configuration.

Argo CD sync is the only supported workload deployment path after Terraform
readiness. A deployment is accepted only when the Application is `Synced` and
`Healthy`; otherwise promotion stops and the evidence records the failure.
