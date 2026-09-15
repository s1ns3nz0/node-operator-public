#!/usr/bin/env python3
"""Render, but never apply, an isolated slashing-DB clone rehearsal."""
import argparse
import json
import re
import sys
from pathlib import Path

VOLUME = re.compile(r"^vol-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
REGION = re.compile(r"^[a-z]{2}-[a-z0-9-]+-[0-9]+$")
ZONE = re.compile(r"^[a-z]{2}-[a-z0-9-]+-[0-9]+[a-z]$")
SET = re.compile(r"^hoodi-[a-z0-9][a-z0-9-]*$")
KEY = re.compile(r"^0x[0-9a-f]{96}$")

def fail(message):
    print(message, file=sys.stderr); raise SystemExit(64)

def metadata(path):
    if not path.is_absolute() or path.is_symlink() or not path.is_file(): fail("clone metadata must be an absolute regular file")
    try: value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): fail("clone metadata is invalid")
    fields = {"schema_version","aws_account_id","source_volume_id","clone_volume_id","aws_region","availability_zone","size_gib","encrypted","kms_key_arn","postgres_image","postgres_major","validator_set","validator_public_key"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != 1: fail("clone metadata schema is invalid")
    if not isinstance(value["aws_account_id"], str) or not re.fullmatch(r"[0-9]{12}", value["aws_account_id"]): fail("clone metadata account is invalid")
    if not all(isinstance(value[x], str) and VOLUME.fullmatch(value[x]) for x in ("source_volume_id","clone_volume_id")) or value["source_volume_id"] == value["clone_volume_id"]: fail("clone metadata must name distinct source and clone EBS volumes")
    if not isinstance(value["aws_region"], str) or not REGION.fullmatch(value["aws_region"]) or not isinstance(value["availability_zone"], str) or not ZONE.fullmatch(value["availability_zone"]) or not value["availability_zone"].startswith(value["aws_region"]): fail("clone metadata region and availability zone are invalid")
    if type(value["size_gib"]) is not int or not 1 <= value["size_gib"] <= 16384: fail("clone metadata volume size is invalid")
    if value["encrypted"] is not True: fail("clone metadata must require encrypted EBS")
    region, account = value["aws_region"], value["aws_account_id"]
    if not isinstance(value["kms_key_arn"], str) or not re.fullmatch(rf"arn:aws:kms:{re.escape(region)}:{account}:key/[0-9a-f-]{{36}}", value["kms_key_arn"]): fail("clone metadata KMS key is invalid")
    image_pattern = rf"{account}\.dkr\.ecr\.{re.escape(region)}\.amazonaws\.com/[a-z0-9][a-z0-9-]*-baseline-validator-runtime-postgres@sha256:[0-9a-f]{{64}}"
    if not isinstance(value["postgres_image"], str) or not re.fullmatch(image_pattern, value["postgres_image"]): fail("clone metadata PostgreSQL image is not a selected-account private immutable reference")
    if type(value["postgres_major"]) is not int or not 10 <= value["postgres_major"] <= 99: fail("clone metadata PostgreSQL major is invalid")
    if not isinstance(value["validator_set"], str) or not SET.fullmatch(value["validator_set"]): fail("clone metadata validator set is invalid")
    if not isinstance(value["validator_public_key"], str) or not KEY.fullmatch(value["validator_public_key"]): fail("clone metadata validator public key is invalid")
    return value

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clone-metadata", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); m = metadata(args.clone_metadata)
    if not args.output.is_absolute(): fail("output must be an absolute path")
    name = f"validator-{m['validator_set']}-slashing-db-rehearsal"; ns = "validator-operations"; size = f"{m['size_gib']}Gi"
    labels = {"app.kubernetes.io/component":"slashing-db-rehearsal","node-operator.io/rehearsal":"isolated-clone","node-operator.io/validator-set":m["validator_set"]}
    annotations = {"node-operator.io/source-volume-id":m["source_volume_id"],"node-operator.io/clone-volume-id":m["clone_volume_id"],"node-operator.io/ebs-encrypted":"true","node-operator.io/kms-key-arn":m["kms_key_arn"],"node-operator.io/validator-public-key":m["validator_public_key"]}
    security = {"runAsNonRoot":True,"runAsUser":999,"runAsGroup":999,"fsGroup":999,"fsGroupChangePolicy":"OnRootMismatch","seccompProfile":{"type":"RuntimeDefault"}}
    csec = {"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}}
    pgdata = "/var/lib/postgresql/data/pgdata"; mount = {"name":"clone-data","mountPath":"/var/lib/postgresql/data"}; major = str(m["postgres_major"])
    check = f"test \"$(cat {pgdata}/PG_VERSION)\" = {major}; test \"$(postgres --version | awk '{{print $3}}' | cut -d. -f1)\" = {major}; state=\"$(LC_ALL=C pg_controldata {pgdata} | awk -F: '$1 ~ /^Database cluster state[[:space:]]*$/ {{v=$2; sub(/^[[:space:]]*/, \"\", v); sub(/[[:space:]]*$/, \"\", v); print v; exit}}')\"; test \"$state\" = 'shut down'"
    pod = {"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":ns,"labels":labels,"annotations":annotations},"spec":{"automountServiceAccountToken":False,"restartPolicy":"Never","terminationGracePeriodSeconds":60,"securityContext":security,"initContainers":[{"name":"verify-restored-cluster","image":m["postgres_image"],"command":["sh","-ec",check],"resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"500m","memory":"256Mi"}},"securityContext":csec,"volumeMounts":[mount]}],"containers":[{"name":"postgres","image":m["postgres_image"],"command":["postgres","-D",pgdata,"-c","listen_addresses=","-c","unix_socket_directories=/var/run/postgresql"],"resources":{"requests":{"cpu":"100m","memory":"256Mi"},"limits":{"cpu":"1","memory":"1Gi"}},"securityContext":csec,"volumeMounts":[mount,{"name":"socket","mountPath":"/var/run/postgresql"},{"name":"tmp","mountPath":"/tmp"}]}],"volumes":[{"name":"clone-data","persistentVolumeClaim":{"claimName":name}},{"name":"socket","emptyDir":{"sizeLimit":"64Mi"}},{"name":"tmp","emptyDir":{"sizeLimit":"64Mi"}}]}}
    pv = {"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":name,"labels":labels,"annotations":annotations},"spec":{"capacity":{"storage":size},"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],"persistentVolumeReclaimPolicy":"Retain","storageClassName":"","claimRef":{"namespace":ns,"name":name},"csi":{"driver":"ebs.csi.aws.com","volumeHandle":m["clone_volume_id"],"fsType":"ext4"},"nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"topology.kubernetes.io/zone","operator":"In","values":[m["availability_zone"]]}]}]}}}}
    pvc = {"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":name,"namespace":ns,"labels":labels,"annotations":annotations},"spec":{"accessModes":["ReadWriteOnce"],"storageClassName":"","volumeName":name,"resources":{"requests":{"storage":size}}}}
    network = {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":name,"namespace":ns,"labels":labels},"spec":{"podSelector":{"matchLabels":labels},"policyTypes":["Ingress","Egress"]}}
    try:
        with args.output.open("x", encoding="utf-8") as out: json.dump({"apiVersion":"v1","kind":"List","items":[pv,pvc,network,pod]}, out, indent=2); out.write("\n")
    except FileExistsError: fail("output already exists")

if __name__ == "__main__": main()
