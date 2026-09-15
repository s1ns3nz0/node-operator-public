#!/usr/bin/env bash
set -euo pipefail
umask 077
usage() { printf '%s\n' "usage: ${0##*/} --promotion-handoff /absolute/file.json --argocd-image private-ecr@sha256:DIGEST --subnet-id subnet-ID [--subnet-id subnet-ID] --output /absolute/new.tfvars.json"; exit 64; }
promotion=''; image=''; output=''; subnets=()
while [ "$#" -gt 0 ]; do case "$1" in --promotion-handoff) promotion="${2:-}"; shift 2;; --argocd-image) image="${2:-}"; shift 2;; --subnet-id) subnets+=("${2:-}"); shift 2;; --output) output="${2:-}"; shift 2;; *) usage;; esac; done
case "$promotion:$output" in /*:/*) ;; *) usage;; esac
[ -f "$promotion" ] && [ ! -L "$promotion" ] && [ ! -e "$output" ] && [ ! -L "$output" ] || { printf '%s\n' 'promotion input/output path is unsafe' >&2; exit 65; }
[[ "$image" =~ ^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z0-9-]+-[0-9]+\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$ ]] || usage
[ "${#subnets[@]}" -gt 0 ] || usage
for subnet in "${subnets[@]}"; do [[ "$subnet" =~ ^subnet-[a-z0-9]+$ ]] || usage; done
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'missing command: jq' >&2; exit 127; }
account="$(jq -er 'select(.schema_version == "v1") | .aws_account_id | select(test("^[0-9]{12}$"))' "$promotion")" || exit 65
version="$(jq -er '.chart_version | select(test("^0\\.1\\.[0-9]+$"))' "$promotion")" || exit 65
digest="$(jq -er '.chart_oci_digest | select(test("^sha256:[a-f0-9]{64}$"))' "$promotion")" || exit 65
[[ "$image" == "$account".* ]] || { printf '%s\n' 'Argo bootstrap image belongs to another account' >&2; exit 65; }
jq -n --arg image "$image" --arg version "$version" --arg digest "$digest" --argjson subnets "$(printf '%s\n' "${subnets[@]}" | jq -R . | jq -s .)" '{enable_argocd_bootstrap_runner:true,enable_argocd_bootstrap_cluster_admin:true,argocd_bootstrap_image:$image,argocd_bootstrap_subnet_ids:$subnets,gitops_client_chart_version:$version,gitops_client_chart_oci_digest:$digest}' > "$output"
chmod 600 "$output"
printf 'PASS: Argo bootstrap tfvars prepared at %s; apply remains a separately approved operation.\n' "$output"
