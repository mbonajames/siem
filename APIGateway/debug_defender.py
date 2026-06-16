"""
Run from the APIGateway directory:
    python debug_defender.py

Fetches up to 3 raw alerts from Graph API and prints the key fields
so you can verify the response shape before normalization.
"""
import json
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

from integrations.ms_defender import DefenderClient, normalize_alert

client = DefenderClient()

print("=== Defender client config ===")
print(f"  tenant_id     : {client.tenant_id}")
print(f"  client_id     : {client.client_id}")
print(f"  client_secret : {'SET' if client.client_secret else 'MISSING'}")
print(f"  configured    : {client.configured}")
print()

if not client.configured:
    print("ERROR: Missing credentials — check DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET in .env")
    raise SystemExit(1)

# --- Step 1: test auth ---
print("=== Step 1: Authenticate ===")
try:
    client._authenticate()
    print("  OK — token acquired")
except Exception as e:
    print(f"  FAILED: {e}")
    raise SystemExit(1)
print()

# --- Step 2: fetch raw alerts ---
since = (datetime.now(tz=timezone.utc) - timedelta(hours=168)).strftime("%Y-%m-%dT%H:%M:%SZ")
print(f"=== Step 2: Fetch alerts since {since} (top=3) ===")
try:
    alerts = client.get_alerts(since_iso=since, top=3)
    print(f"  total returned: {len(alerts)}")
except Exception as e:
    print(f"  FAILED: {e}")
    raise SystemExit(1)
print()

if not alerts:
    print("No alerts returned. Try a wider time window or check that the tenant has Defender alerts.")
    raise SystemExit(0)

# --- Step 3: inspect raw shape ---
print("=== Step 3: Raw alert shape (first alert) ===")
a = alerts[0]
print(f"  top-level keys : {sorted(a.keys())}")
print(f"  id             : {a.get('id')}")
print(f"  title          : {a.get('title')}")
print(f"  severity       : {a.get('severity')}")
print(f"  status         : {a.get('status')}")
print(f"  category       : {a.get('category')}")
print(f"  createdDateTime: {a.get('createdDateTime')}")
print(f"  incidentId     : {a.get('incidentId')}")
evidence = a.get("evidence") or []
comments = a.get("comments") or []
print(f"  evidence count : {len(evidence)}")
print(f"  comments count : {len(comments)}")
if evidence:
    print(f"  evidence types : {[e.get('@odata.type','?') for e in evidence]}")
print()

# --- Step 4: normalize first alert ---
print("=== Step 4: Normalize first alert ===")
try:
    doc_id, index_name, doc = normalize_alert(a)
    print(f"  doc_id     : {doc_id}")
    print(f"  index_name : {index_name}")
    print(f"  rule.level : {doc.get('rule', {}).get('level')}")
    d = doc.get("data", {}).get("defender", {})
    print(f"  title      : {d.get('title')}")
    print(f"  severity   : {d.get('severity')}")
    print(f"  evidence[] : {len(d.get('evidence') or [])}")
    print(f"  @timestamp : {doc.get('@timestamp')}")
except Exception as e:
    print(f"  FAILED: {e}")
    import traceback; traceback.print_exc()
print()

# --- Step 5: fetch incidents ---
print(f"=== Step 5: Fetch incidents (top=3) ===")
try:
    incidents = client.get_incidents(since_iso=since, top=3)
    print(f"  incident map size: {len(incidents)}")
    for iid, meta in list(incidents.items())[:2]:
        print(f"  [{iid}] title={meta.get('title')!r} severity={meta.get('severity')!r}")
except Exception as e:
    print(f"  FAILED: {e}")
print()


# --- Step 6: apply index template + remove stale indices, then ingest ---
print("=== Step 6: Apply index template and ingest ===")
from client import indexer_client
from integrations.ms_defender import ingest_alerts, ensure_index_template, delete_stale_indices

print("  Applying index template...")
ensure_index_template(indexer_client)
print("  Removing stale indices with wrong mapping...")
delete_stale_indices(indexer_client)

try:
    result = ingest_alerts(client, indexer_client, since_iso=since)
    print(f"  ingested : {result.get('ingested')}")
    print(f"  errors   : {result.get('errors')}")
    print(f"  since    : {result.get('since')}")
except Exception as e:
    print(f"  FAILED: {e}")
    import traceback; traceback.print_exc()
    raise SystemExit(1)
print()

# --- Step 7: search OpenSearch for the ingested document ---
print("=== Step 7: Search OpenSearch for ms-defender docs ===")
try:
    res = indexer_client.search(
        index="siem-defender-*",
        ignore_unavailable=True,
        body={
            "size": 3,
            "query": {"term": {"data.integration": "ms-defender"}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )
    total = res["hits"]["total"]["value"] if isinstance(res["hits"]["total"], dict) else res["hits"]["total"]
    print(f"  total docs in siem-defender-* : {total}")
    for hit in res["hits"]["hits"]:
        d = hit.get("_source", {}).get("data", {}).get("defender", {})
        print(f"  [{hit['_index']}] id={hit['_id'][:20]}… title={d.get('title')!r} sev={d.get('severity')}")
except Exception as e:
    print(f"  FAILED: {e}")
    import traceback; traceback.print_exc()
print()


# --- Step 8: check actual @timestamp range in OpenSearch ---
print("=== Step 8: @timestamp range in OpenSearch ===")
try:
    res = indexer_client.search(
        index="siem-defender-*",
        ignore_unavailable=True,
        body={
            "size": 0,
            "aggs": {
                "oldest": {"min": {"field": "@timestamp"}},
                "newest": {"max": {"field": "@timestamp"}},
            }
        },
    )
    aggs = res.get("aggregations", {})
    print(f"  oldest @timestamp : {aggs.get('oldest', {}).get('value_as_string', 'N/A')}")
    print(f"  newest @timestamp : {aggs.get('newest', {}).get('value_as_string', 'N/A')}")
    # Check how many docs fall in the last 24h
    res24 = indexer_client.search(
        index="siem-defender-*",
        ignore_unavailable=True,
        body={
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}}
        },
    )
    count24 = res24["hits"]["total"]["value"] if isinstance(res24["hits"]["total"], dict) else res24["hits"]["total"]
    print(f"  docs in last 24h  : {count24}")
    res7d = indexer_client.search(
        index="siem-defender-*",
        ignore_unavailable=True,
        body={
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}
        },
    )
    count7d = res7d["hits"]["total"]["value"] if isinstance(res7d["hits"]["total"], dict) else res7d["hits"]["total"]
    print(f"  docs in last 7d   : {count7d}")
except Exception as e:
    print(f"  FAILED: {e}")
print()

print("=== Done ===")
