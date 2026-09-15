#!/usr/bin/env python3
"""Bind live-verified mirror inputs to the deployment chart-values renderer."""
import argparse,json,os,sys,tempfile
from pathlib import Path
_release_dir=Path(__file__).resolve().parent
if str(_release_dir) not in sys.path: sys.path.insert(0,str(_release_dir))
from client_chart_release_authorization import validate_release_authorization,ClientChartAuthorizationError
from installer_full_artifact_mirror import verify,FullMirrorError
from installer_artifact_mirror import verify_pre_eks_vault_mirror
import importlib.util
_renderer_spec=importlib.util.spec_from_file_location("deployment_values_renderer",Path(__file__).with_name("render-deployment-bound-chart-values.py"))
if _renderer_spec is None or _renderer_spec.loader is None: raise RuntimeError("deployment values renderer is unavailable")
_renderer=importlib.util.module_from_spec(_renderer_spec);_renderer_spec.loader.exec_module(_renderer)
render,Error=_renderer.render,_renderer.Error
_capability_spec=importlib.util.spec_from_file_location("client_chart_deployment_capability",Path(__file__).with_name("verify-client-chart-deployment-capability.py"))
if _capability_spec is None or _capability_spec.loader is None: raise RuntimeError("deployment chart capability verifier is unavailable")
_capability=importlib.util.module_from_spec(_capability_spec);_capability_spec.loader.exec_module(_capability)
CapabilityError=_capability.CapabilityError
def verify_chart_capability(image_ref,chart_version,value,profile):
 with tempfile.TemporaryDirectory() as directory:
  values=Path(directory)/"deployment-values.json";values.write_text(json.dumps(value,sort_keys=True,separators=(",",":")))
  _capability.verify_layer_capability(_capability.fetch_authorized_layer(image_ref,profile),chart_version,values)
def main():
 p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);p.add_argument('--state',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--profile',required=True);p.add_argument('--release',required=True);p.add_argument('--account',required=True);p.add_argument('--region',required=True);p.add_argument('--deployment',required=True);p.add_argument('--foundation',type=Path,required=True);p.add_argument('--baseline',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 try:
  discovery={'aws_account_id':a.account,'aws_region':a.region,'deployment_name':a.deployment}; auth=validate_release_authorization(a.bundle,a.release,'stage'); receipt=verify(a.state,a.bundle,discovery,a.profile,a.release,work_dir=a.work,inputs_dir=a.inputs)
  vault=verify_pre_eks_vault_mirror(a.state,a.bundle,discovery,a.profile,a.release,a.inputs,work_dir=a.work,return_manifest=True); f=json.loads(a.foundation.read_text()); b=json.loads(a.baseline.read_text()); rows={x['component']:x['image_ref'] for x in receipt['artifacts']}
  chart_ref=rows['node-operator-client-chart']; digest=auth['target']['manifest_digest']; expected_chart=f"{a.account}.dkr.ecr.{a.region}.amazonaws.com/{a.deployment}-baseline-gitops-client/node-operator-client@{digest}"
  if chart_ref != expected_chart or chart_ref.rsplit('@',1)[1] != digest: raise CapabilityError("verified destination chart differs from release authorization")
  data={'aws_account_id':receipt['aws_account_id'],'aws_region':receipt['aws_region'],'deployment_name':receipt['deployment_name'],'chart':{'version':auth['target']['chart_version'],'digest':auth['target']['manifest_digest']},'foundation':{'hoodi_nat_public_ip':f['hoodi_nat_public_ip'],'ebs_kms_key_arn':b['ebs_kms_key_arn']['value']},'artifacts':{'nethermindImage':rows['nethermind'],'prysmImage':rows['prysm-beacon'],'vaultAgentImage':vault['manifest']['images']['agent']}}
  value=render(data); verify_chart_capability(chart_ref,auth['target']['chart_version'],value,a.profile); fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as h: json.dump(value,h,sort_keys=True,separators=(',',':'));h.write('\n')
 except (KeyError,OSError,json.JSONDecodeError,ClientChartAuthorizationError,FullMirrorError,Error,CapabilityError) as e: print('deployment chart values rejected',file=sys.stderr);return 65
 return 0
if __name__=='__main__':raise SystemExit(main())
