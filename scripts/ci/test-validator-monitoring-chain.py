#!/usr/bin/env python3
# Check objective: Validate finalized-chain EMF rendering.
"""Offline contract tests for pure finalized-chain EMF rendering."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("chain", ROOT / "scripts/release/validator_monitoring_chain.py")
chain = importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(chain)

IDENTITY = {"validator_set":"hoodi-example", "validator_public_key":"0x" + "a" * 96, "validator_index":"123", "deployment_name":"node-operator", "release_revision":"b" * 40, "activation_slot":"300"}
CONTEXT = {"identity":IDENTITY, "aws_region":"ap-northeast-2"}

def result(epochs=("10", "11")):
    return {"schema_version":1, "identity":IDENTITY | {"private_beacon_url":"http://private.example", "public_beacon_url":"https://public.example", "workload_proof_path":"/safe/workload.json", "log_delivery_proof_path":"/safe/logs.json"}, "consecutive_finalized_epochs":list(epochs), "required_finalized_epochs":2, "complete":len(epochs) >= 2}

class ChainEmf(unittest.TestCase):
    def test_known_fresh_result_renders_only_bounded_dimensions_and_metrics(self):
        event = chain.render(CONTEXT, result(), True, 1_700_000_000_000)
        self.assertEqual(event["_aws"]["Timestamp"], 1_700_000_000_000)
        self.assertEqual(event["_aws"]["CloudWatchMetrics"][0]["Namespace"], "NodeOperator/Validator")
        self.assertEqual(event["_aws"]["CloudWatchMetrics"][0]["Dimensions"], [["Deployment","Network","ValidatorSet","Component"]])
        self.assertEqual(event["Component"], "chain-observer")
        self.assertEqual(event["VerifiedFinalizedEpochCount"], 2)
        self.assertEqual(event["LatestVerifiedAttestationEpoch"], 11)
        self.assertNotIn("validator_public_key", event)

    def test_identity_and_epoch_invariants_reject_untrusted_result(self):
        for mutate in (lambda x: x["identity"].__setitem__("validator_set", "other"),
                       lambda x: x.__setitem__("consecutive_finalized_epochs", ["10", "10"]),
                       lambda x: x.__setitem__("consecutive_finalized_epochs", ["8"]),
                       lambda x: x.__setitem__("complete", True)):
            value = result(("10",)); mutate(value)
            with self.assertRaises(chain.ChainMonitoringError): chain.render(CONTEXT, value, True, 1)

    def test_single_epoch_threshold_is_accepted_with_a_complete_single_proof(self):
        value = result(("10",)); value["required_finalized_epochs"] = 1; value["complete"] = True
        event = chain.render(CONTEXT, value, True, 1)
        self.assertEqual(event["VerifiedFinalizedEpochCount"], 1)

    def test_context_and_epoch_strings_are_canonical_and_activation_epoch_is_allowed(self):
        for context in ({"aws_region":"ap-northeast-2"}, CONTEXT | {"extra":"ignored"}):
            if "identity" not in context:
                with self.assertRaises(chain.ChainMonitoringError): chain.render(context, result(), True, 1)
            else:
                self.assertEqual(chain.render(context, result(), True, 1)["Component"], "chain-observer")
        for epoch in ("01", "١٠"):
            with self.assertRaises(chain.ChainMonitoringError): chain.render(CONTEXT, result((epoch,)), True, 1)
        same_epoch = result(("9",))
        self.assertEqual(chain.render(CONTEXT, same_epoch, True, 1)["LatestVerifiedAttestationEpoch"], 9)
        invalid_identity = dict(IDENTITY); invalid_identity["release_revision"] = "A" * 40
        with self.assertRaises(chain.ChainMonitoringError): chain.render({"identity":invalid_identity,"aws_region":"ap-northeast-2"}, result(), True, 1)

    def test_unavailable_never_emits_historical_proofs_or_health_metrics(self):
        event = chain.render(CONTEXT, result(), False, 1)
        self.assertEqual(event["ChainObservationAvailable"], 0)
        self.assertEqual(set(event) - {"_aws","Deployment","Network","ValidatorSet","Component","ChainObservationAvailable"}, set())
        self.assertEqual(event["_aws"]["CloudWatchMetrics"][0]["Metrics"], [{"Name":"ChainObservationAvailable","Unit":"Count"}])

    def test_strict_types_and_empty_pending_result(self):
        pending = result(())
        event = chain.render(CONTEXT, pending, True, 1)
        self.assertEqual(event["VerifiedFinalizedEpochCount"], 0); self.assertNotIn("LatestVerifiedAttestationEpoch", event)
        for available, timestamp in ((1, 1), (True, True), (False, "1")):
            with self.assertRaises(chain.ChainMonitoringError): chain.render(CONTEXT, result(), available, timestamp)

if __name__ == "__main__": unittest.main()
