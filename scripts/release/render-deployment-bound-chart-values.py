#!/usr/bin/env python3
"""Render fail-closed non-secret Helm values for a new node deployment."""
import argparse, json, os, re, sys
from pathlib import Path

DIGEST=re.compile(r"^[0-9]{12}\.dkr\.ecr\.([a-z]{2}-[a-z0-9-]+-[0-9]+)\.amazonaws\.com/([a-z0-9][a-z0-9._/-]*)@sha256:[a-f0-9]{64}$")
IP=re.compile(r"^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$")
NAME=re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
KMS=re.compile(r"^arn:aws:kms:[a-z]{2}-[a-z0-9-]+-[0-9]+:[0-9]{12}:key/[A-Za-z0-9-]+$")
class Error(ValueError): pass
def need(v, name, pattern=None):
 if not isinstance(v,str) or not v or (pattern and not pattern.fullmatch(v)): raise Error(f"invalid {name}")
 return v
def image(v,name,account,region,deployment):
 v=need(v,name,DIGEST); m=DIGEST.fullmatch(v)
 if m.group(1)!=region or not v.startswith(account+".") or not m.group(2).startswith(deployment+"-") or "node-operator-baseline-" in v: raise Error(f"{name} is not deployment-owned")
 return v
def render(data):
 if not isinstance(data,dict) or set(data)!={"aws_account_id","aws_region","deployment_name","chart","foundation","artifacts"}: raise Error("renderer input shape is invalid")
 account=need(data["aws_account_id"],"aws_account_id",re.compile(r"^[0-9]{12}$")); region=need(data["aws_region"],"aws_region",re.compile(r"^[a-z]{2}-[a-z0-9-]+-[0-9]+$")); deployment=need(data["deployment_name"],"deployment_name",NAME)
 chart=data["chart"]; foundation=data["foundation"]; artifacts=data["artifacts"]
 if not isinstance(chart,dict) or set(chart)!={"version","digest"} or not re.fullmatch(r"0\.1\.[0-9]+",chart["version"] or "") or not re.fullmatch(r"sha256:[a-f0-9]{64}",chart["digest"] or ""): raise Error("chart authorization is invalid")
 if not isinstance(foundation,dict) or set(foundation)!={"hoodi_nat_public_ip","ebs_kms_key_arn"}: raise Error("foundation output is invalid")
 nat=need(foundation["hoodi_nat_public_ip"],"hoodi_nat_public_ip",IP); kms=need(foundation["ebs_kms_key_arn"],"ebs_kms_key_arn",KMS)
 if not kms.startswith(f"arn:aws:kms:{region}:{account}:"): raise Error("ebs KMS key is outside deployment")
 if not isinstance(artifacts,dict) or set(artifacts)!={"nethermindImage","prysmImage","vaultAgentImage"}: raise Error("artifact receipt is invalid")
 return {"deployment":{"profile":"deployment","storageKmsKeyId":kms},"dast":{"enabled":False},"clients":{"vaultAgentImage":image(artifacts["vaultAgentImage"],"vault agent",account,region,deployment),"deployment":{"nethermindImage":image(artifacts["nethermindImage"],"nethermind",account,region,deployment),"prysmImage":image(artifacts["prysmImage"],"prysm",account,region,deployment),"prysmP2PHostIp":nat}}}
def main():
 p=argparse.ArgumentParser(); p.add_argument("--input",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 try:
  if a.input.is_symlink() or a.output.exists() or a.output.is_symlink() or a.output.parent.is_symlink(): raise Error("unsafe renderer path")
  value=render(json.loads(a.input.read_text()))
  a.output.parent.mkdir(parents=True,exist_ok=True)
  fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,"w") as handle: handle.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
 except (OSError,json.JSONDecodeError,Error) as e: print(f"deployment chart values rejected: {e}",file=sys.stderr); return 65
 return 0
if __name__=="__main__": raise SystemExit(main())
