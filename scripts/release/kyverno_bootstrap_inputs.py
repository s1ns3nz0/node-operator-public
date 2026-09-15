"""Pure Kyverno Helm inputs derived from an already-verified full mirror receipt.

The caller is responsible for receipt verification; this module only validates
its declared binding and produces non-secret Helm JSON values.
"""
from __future__ import annotations
import re
from typing import Any

_ACCOUNT=re.compile(r"[0-9]{12}\Z"); _REGION=re.compile(r"[a-z]{2}-[a-z0-9-]+-[1-9][0-9]*\Z"); _NAME=re.compile(r"[a-z][a-z0-9-]{1,38}[a-z0-9]\Z"); _DIGEST=re.compile(r"sha256:[0-9a-f]{64}\Z"); _TAG=re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
RUNTIME={"kyverno-preflight":"admissionController.initContainer.image","kyverno":"admissionController.container.image","kyverno-background-controller":"backgroundController.image","kyverno-cleanup-controller":"cleanupController.image","kyverno-reports-controller":"reportsController.image","kyverno-readiness-checker":"test.image","kyverno-cli":"crds.migration.image"}
class KyvernoInputsError(ValueError): pass

def render(receipt:dict[str,Any], account:str, region:str, deployment:str)->dict[str,Any]:
 if not (_ACCOUNT.fullmatch(account) and _REGION.fullmatch(region) and _NAME.fullmatch(deployment)) or not isinstance(receipt,dict): raise KyvernoInputsError("selected deployment identity is invalid")
 if any(receipt.get(k)!=v for k,v in {"status":"verified","scope":"non-Vault OCI artifacts","aws_account_id":account,"aws_region":region,"deployment_name":deployment}.items()): raise KyvernoInputsError("full mirror receipt is not bound to selected deployment")
 rows=receipt.get("artifacts")
 if not isinstance(rows,list): raise KyvernoInputsError("full mirror receipt artifacts are invalid")
 expected=set(RUNTIME)|{"kyverno-chart"}; found={}
 for row in rows:
  if not isinstance(row,dict) or row.get("component") not in expected: continue
  key=row["component"]
  if key in found or set(row)!={"component","image_ref","tag","manifest_digest"}: raise KyvernoInputsError("Kyverno receipt artifact is duplicate or malformed")
  found[key]=row
 if set(found)!=expected: raise KyvernoInputsError("Kyverno receipt artifacts are missing or ambiguous")
 registry=f"{account}.dkr.ecr.{region}.amazonaws.com/"
 values={}
 def put(path,value):
  target=values
  for key in path.split(".")[:-1]: target=target.setdefault(key,{})
  target[path.split(".")[-1]]=value
 for component,path in RUNTIME.items():
  row=found[component]; digest=row["manifest_digest"]; ref=row["image_ref"]
  if not isinstance(digest,str) or _DIGEST.fullmatch(digest) is None or not isinstance(ref,str) or ref != registry+deployment+"-baseline-gitops-nodes@"+digest or not isinstance(row["tag"],str) or re.fullmatch(r"[a-f0-9]{64}",row["tag"]) is None: raise KyvernoInputsError("Kyverno runtime artifact does not match immutable private mirror")
  put(path,{"registry":registry[:-1],"repository":deployment+"-baseline-gitops-nodes","tag":row["tag"]+"@"+digest})
 chart=found["kyverno-chart"]; digest=chart["manifest_digest"]; ref=chart["image_ref"]
 if not isinstance(digest,str) or _DIGEST.fullmatch(digest) is None or not isinstance(ref,str) or ref != registry+deployment+"-baseline-gitops-charts@"+digest or not isinstance(chart["tag"],str) or _TAG.fullmatch(chart["tag"]) is None: raise KyvernoInputsError("Kyverno chart artifact does not match immutable private mirror")
 # Preserve the reviewed hardened settings; only image coordinates are dynamic.
 for controller in ("admissionController","backgroundController","cleanupController","reportsController"):
  values[controller]["podSecurityContext"]={"runAsNonRoot":True,"seccompProfile":{"type":"RuntimeDefault"}}
  values[controller]["securityContext"]={"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]},"runAsNonRoot":True}
 values["webhooksCleanup"]={"image":values["test"]["image"]}
 admission=values["admissionController"]
 admission["container"]["resources"]={"requests":{"cpu":"250m","memory":"256Mi"},"limits":{"cpu":"1","memory":"1Gi"}}
 admission["initContainer"]["resources"]={"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"250m","memory":"256Mi"}}
 admission["initContainer"]["securityContext"]={"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]},"runAsNonRoot":True}
 for controller in ("backgroundController","cleanupController","reportsController"):
  values[controller]["resources"]={"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"500m","memory":"512Mi"}}
 # Keep the approved chart's migration hook enabled for upgrades. Never fall
 # back to its public tag or silently disable migration for image checks.
 migration=values["crds"]["migration"]
 migration["enabled"]=True
 migration["podSecurityContext"]={"runAsNonRoot":True,"seccompProfile":{"type":"RuntimeDefault"}}
 migration["securityContext"]={"runAsUser":65534,"runAsGroup":65534,"runAsNonRoot":True,"privileged":False,"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}
 migration["podResources"]={"requests":{"cpu":"10m","memory":"64Mi"},"limits":{"cpu":"100m","memory":"256Mi"}}
 return {"chart_ref":"oci://"+ref,"values":values}
