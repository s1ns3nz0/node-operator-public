"""Match a nonce-bound Vault socket audit request in a Firehose archive."""
from __future__ import annotations
import importlib.util, json, re, secrets
from pathlib import Path

_path=Path(__file__).with_name("collect-hoodi-finalized-attestation-evidence.py")
_spec=importlib.util.spec_from_file_location("archive",_path); archive=importlib.util.module_from_spec(_spec); _spec.loader.exec_module(archive)
_HMAC=re.compile(r"hmac-sha256:[0-9a-f]{64}\Z"); _UUID=re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z"); _EVENT=re.compile(r"[A-Za-z0-9._:/+=,@-]{1,512}\Z")
class MatchError(ValueError): pass

def new_marker() -> str: return secrets.token_hex(32)
def match(blob: bytes, marker_hmac: str, after_ms: int, account: str, log_group: str, response_request_id: str|None=None) -> dict:
 if not isinstance(blob,bytes) or not _HMAC.fullmatch(marker_hmac) or type(after_ms) is not int or after_ms<0 or not re.fullmatch(r"[0-9]{12}",account) or not isinstance(log_group,str) or not re.fullmatch(r"/aws/eks/[a-z][a-z0-9-]{1,38}[a-z0-9]/validator-security",log_group) or response_request_id is not None and not _UUID.fullmatch(response_request_id): raise MatchError("invalid correlation")
 try: envelopes=archive.archive_envelopes(blob)
 except Exception as error: raise MatchError("invalid archive") from error
 found=[]
 for envelope in envelopes:
  if not isinstance(envelope,dict) or envelope.get("owner")!=account or envelope.get("logGroup")!=log_group or envelope.get("messageType")!="DATA_MESSAGE" or not isinstance(envelope.get("logEvents"),list): continue
  for event in envelope.get("logEvents",[]):
   if not isinstance(event,dict) or not _EVENT.fullmatch(event.get("id","")) or type(event.get("timestamp")) is not int or event["timestamp"]<after_ms or not isinstance(event.get("message"),str): continue
   try: outer=json.loads(event["message"]); line=outer["log"]
   except (ValueError,KeyError,TypeError): continue
   labels=outer.get("kubernetes") if isinstance(outer,dict) else None
   if not (isinstance(labels,dict) and labels.get("namespace_name")=="vault" and labels.get("container_name")=="vault-validator-audit-relay" and isinstance(line,str)): continue
   line=re.sub(r"^\d{4}-\d\d-\d\dT[^ ]+Z\s+(?:stdout|stderr)\s+[FP]\s+","",line)
   try: relay=json.loads(line); record=json.loads(relay["log"]); request=record["request"]
   except (ValueError,KeyError,TypeError): continue
   if not (isinstance(relay,dict) and set(relay)=={"schema_version","audit_source","log"} and relay.get("schema_version")==1 and relay.get("audit_source")=="socket" and isinstance(request,dict)): continue
   if record.get("type")=="request" and _UUID.fullmatch(request.get("id", "")) and request.get("operation")=="update" and request.get("path")=="sys/audit-hash/validator-socket" and request.get("data")=={"input":marker_hmac} and (response_request_id is None or request["id"]==response_request_id): found.append((event,request["id"]))
 if len(found)!=1: raise MatchError("archive lacks one exact socket audit request")
 return {"event_id":found[0][0].get("id"),"timestamp_ms":found[0][0]["timestamp"],"request_id":found[0][1]}
