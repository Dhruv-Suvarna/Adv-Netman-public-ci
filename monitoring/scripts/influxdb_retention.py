#!/usr/bin/env python3
"""Read or apply the 30-day policy to the existing NMAS bucket without recreating it."""
import argparse
from pathlib import Path
import requests

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--apply", action="store_true")
args = parser.parse_args()
env = dict(line.split("=", 1) for line in
           (Path(__file__).resolve().parents[1] / "runtime/monitoring.env").read_text().splitlines()
           if "=" in line and not line.startswith("#"))
session = requests.Session()
session.trust_env = False
session.headers["Authorization"] = "Token " + env["INFLUXDB_TOKEN"]
base = "http://127.0.0.1:8086/api/v2/buckets"
response = session.get(base, params={"org": env["INFLUXDB_ORG"], "name": env["INFLUXDB_BUCKET"]}, timeout=10)
response.raise_for_status()
buckets = response.json()["buckets"]
if len(buckets) != 1:
    raise SystemExit("Expected exactly one configured monitoring bucket")
bucket = buckets[0]
def correct(value):
    rules = value.get("retentionRules", [])
    return len(rules) == 1 and rules[0].get("type") == "expire" and rules[0].get("everySeconds") == 2592000
if args.apply and not correct(bucket):
    response = session.patch(base + "/" + bucket["id"], json={"retentionRules": [{"type": "expire", "everySeconds": 2592000}]}, timeout=10)
    response.raise_for_status()
response = session.get(base + "/" + bucket["id"], timeout=10)
response.raise_for_status()
bucket = response.json()
print("Bucket:", bucket["name"], "retention:", bucket["retentionRules"])
if not correct(bucket):
    raise SystemExit("FAIL: expected 30-day retention (2592000 seconds)")
