#!/usr/bin/env python3
"""Internal-only Prometheus and CloudWatch Logs protocol stub for CI proof."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import gzip
import json
from pathlib import Path
import sys

RECORD = Path(sys.argv[1])
PUBLIC_KEY = "0x" + "a" * 96
OTHER_KEY = "0x" + "b" * 96
SCRAPES = 0
VALIDATOR_SCRAPES = 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        global SCRAPES, VALIDATOR_SCRAPES
        if self.path != "/metrics":
            self.send_error(404)
            return
        SCRAPES += 1
        host = self.headers.get("Host", "")
        if host.startswith("validator.stub:"):
            VALIDATOR_SCRAPES += 1
        counter = 10 + VALIDATOR_SCRAPES
        with RECORD.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"request": "scrape", "host": host, "validator_counter": counter}, sort_keys=True) + "\n")
        body = f"""# TYPE beacon_head_slot gauge
beacon_head_slot 100
# TYPE beacon_clock_time_slot gauge
beacon_clock_time_slot 101
# TYPE beacon_finalized_epoch gauge
beacon_finalized_epoch 2
# TYPE head_finalized_epoch gauge
head_finalized_epoch 2
# TYPE ethereum_blockchain_height gauge
ethereum_blockchain_height 200
# TYPE ethereum_best_known_block_number gauge
ethereum_best_known_block_number 201
# TYPE ethereum_peer_count gauge
ethereum_peer_count 5
# TYPE ethereum_peer_limit gauge
ethereum_peer_limit 50
# TYPE validator_balance gauge
validator_balance{{pubkey=\"{PUBLIC_KEY}\"}} 32
# TYPE validator_last_attested_slot gauge
validator_last_attested_slot{{pubkey=\"{PUBLIC_KEY}\"}} 99
# TYPE validator_correctly_voted_head gauge
validator_correctly_voted_head{{pubkey=\"{PUBLIC_KEY}\"}} 1
# TYPE validator_correctly_voted_source gauge
validator_correctly_voted_source{{pubkey=\"{PUBLIC_KEY}\"}} 1
# TYPE validator_correctly_voted_target gauge
validator_correctly_voted_target{{pubkey=\"{PUBLIC_KEY}\"}} 1
# TYPE validator_successful_attestations counter
validator_successful_attestations{{pubkey=\"{PUBLIC_KEY}\"}} {counter}
# TYPE validator_failed_attestations counter
validator_failed_attestations{{pubkey=\"{PUBLIC_KEY}\"}} {VALIDATOR_SCRAPES}
validator_balance{{pubkey=\"{OTHER_KEY}\"}} 999
validator_balance 777
unapproved_metric 666
""".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        target = self.headers.get("X-Amz-Target", "")
        encoding = self.headers.get("Content-Encoding", "")
        with RECORD.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"request": "post", "target": target, "encoding": encoding}, sort_keys=True) + "\n")
        if encoding.lower() == "gzip":
            try:
                payload = gzip.decompress(payload)
            except OSError:
                payload = b""
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {"unparsed": True}
        events = []
        for event in decoded.get("logEvents", []):
            try:
                events.append(json.loads(event.get("message", "")))
            except json.JSONDecodeError:
                events.append({"unparsed_message": True})
        with RECORD.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"target": target, "format": self.headers.get("x-amzn-logs-format", ""), "events": events}, sort_keys=True) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-amz-json-1.1")
        self.end_headers()
        if target.endswith("DescribeLogStreams"):
            self.wfile.write(b'{"logStreams":[]}')
        else:
            self.wfile.write(b'{}')


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
