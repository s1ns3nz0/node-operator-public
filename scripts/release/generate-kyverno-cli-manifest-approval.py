#!/usr/bin/env python3
"""Render a proposed catalog row from a locally revalidated Kyverno CLI record.

This never edits the approved catalog.  A reviewer must add the returned row
after checking the publication artifact and its release authorization.  The
caller must verify Cosign evidence before invoking this offline renderer.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
from kyverno_cli_publication_record import KyvernoPublicationRecordError, _read, create_record

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--source-root",type=Path,required=True); parser.add_argument("--record",type=Path,required=True); parser.add_argument("--risk-evidence-dir",type=Path); args=parser.parse_args()
    try:
        value=_read(args.record); target=value["target"]
        v2=value.get("schema_version") == 2
        if v2 and args.risk_evidence_dir is None:
            raise KyvernoPublicationRecordError("residual-risk Kyverno records require --risk-evidence-dir")
        if not v2 and args.risk_evidence_dir is not None:
            raise KyvernoPublicationRecordError("clean-scan Kyverno records do not accept risk evidence")
        decision=args.risk_evidence_dir/"risk-decision.json" if v2 else None
        expected=create_record(args.source_root, release_revision=value["release_revision"], image_ref=target["image_ref"], manifest_digest=target["manifest_digest"], run_id=str(value["publication"]["run_id"]), risk_decision=decision)
        if value != expected: raise KyvernoPublicationRecordError("record does not pass the local source binding")
        print(json.dumps({"source":target["image_ref"],"destination":"nodes","ecrTag":target["manifest_digest"].removeprefix("sha256:"),"purpose":"Reviewed Kyverno CLI "+value["source"]["tag"]+" built from "+value["source"]["commit"]},sort_keys=True))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, KyvernoPublicationRecordError) as error: parser.error(str(error))
    return 0
if __name__ == "__main__": raise SystemExit(main())
