from opensearchpy.exceptions import NotFoundError, RequestError

VULN_INDEX = "siem-vuln-scans"


def ensure_index(client) -> None:
    if client.indices.exists(index=VULN_INDEX):
        return
    client.indices.create(
        index=VULN_INDEX,
        body={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "scan_id":     {"type": "keyword"},
                    "mfi":         {"type": "keyword"},
                    "quarter":     {"type": "keyword"},
                    "year":        {"type": "integer"},
                    "scan_type":   {"type": "keyword"},   # "internal" | "external"
                    "uploaded_at": {"type": "date"},
                    "filename":    {"type": "keyword"},
                }
            },
        },
    )


def save_scan(client, scan: dict) -> None:
    # ensure_index is called once at startup; skip it here to avoid extra API calls per upload.
    # refresh=False — async indexing; the scan list will reflect the new document within ~1 s.
    client.index(index=VULN_INDEX, id=scan["scan_id"], body=scan, refresh=False)


def list_scans(client, mfi: str = None) -> list:
    query = {"match_all": {}} if not mfi else {"term": {"mfi": mfi}}
    try:
        res = client.search(
            index=VULN_INDEX,
            body={
                "size": 1000,
                "query": query,
                "_source": {"excludes": ["findings", "hosts"]},
                "sort": [
                    {"year":    {"order": "desc"}},
                    {"quarter": {"order": "desc"}},
                    {"scan_type": {"order": "asc"}},
                ],
            },
        )
    except (NotFoundError, RequestError):
        return []
    return [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]


def get_scan(client, scan_id: str) -> dict | None:
    try:
        res = client.get(index=VULN_INDEX, id=scan_id)
        return {"id": res["_id"], **res["_source"]}
    except NotFoundError:
        return None


def delete_scan(client, scan_id: str) -> bool:
    try:
        client.delete(index=VULN_INDEX, id=scan_id, refresh="wait_for")
        return True
    except NotFoundError:
        return False


def get_scans_for_report(client, mfi: str, year: int, quarter: str) -> list:
    """Return all full scan documents (including findings/hosts) for a given MFI/year/quarter."""
    try:
        res = client.search(
            index=VULN_INDEX,
            body={
                "size": 200,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"mfi":     mfi}},
                            {"term": {"year":    year}},
                            {"term": {"quarter": quarter}},
                        ]
                    }
                },
                "sort": [{"scan_type": {"order": "asc"}}, {"uploaded_at": {"order": "asc"}}],
            },
        )
    except (NotFoundError, RequestError):
        return []
    return [h["_source"] for h in res["hits"]["hits"]]


def get_trends(client) -> list:
    try:
        res = client.search(
            index=VULN_INDEX,
            body={
                "size": 1000,
                "_source": ["mfi", "quarter", "year", "scan_type", "summary"],
                "sort": [{"year": {"order": "asc"}}, {"quarter": {"order": "asc"}}],
            },
        )
    except (NotFoundError, RequestError):
        return []
    return [h["_source"] for h in res["hits"]["hits"]]
