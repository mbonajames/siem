"""
Sophos Central – device management business logic.
All functions take a SophosCentralClient instance as first argument.
"""


# ── Device listing & filtering ────────────────────────────────────────────────

def list_devices(
    client,
    health_status: str | None = None,
    device_type:   str | None = None,
    lockdown_status: str | None = None,
    page_size: int = 500,
) -> list[dict]:
    """
    Fetch all endpoints, following pagination automatically.

    health_status  : good | suspicious | bad
    device_type    : computer | server | securityVm
    lockdown_status: creatingWhitelist | installing | locked | notInstalled |
                     registering | starting | stopping | unavailable | uninstalled
    """
    params: dict = {"pageSize": page_size}
    if health_status:    params["healthStatus"]    = health_status
    if device_type:      params["type"]            = device_type
    if lockdown_status:  params["lockdownStatus"]  = lockdown_status

    devices: list[dict] = []
    while True:
        resp     = client.request("GET", "/endpoint/v1/endpoints", params=params)
        devices.extend(resp.get("items", []))
        next_key = resp.get("pages", {}).get("nextKey")
        if not next_key:
            break
        params["pageFromKey"] = next_key

    return devices


def get_device(client, endpoint_id: str) -> dict:
    return client.request("GET", f"/endpoint/v1/endpoints/{endpoint_id}")


# ── Isolation ─────────────────────────────────────────────────────────────────
# Correct Sophos API: POST /endpoint/v1/endpoints/isolation
# Body: {"enabled": true/false, "comment": "...", "ids": ["id"]}

def isolate_device(client, endpoint_id: str, comment: str = "Isolated via SIEM") -> dict:
    return client.request(
        "POST",
        "/endpoint/v1/endpoints/isolation",
        payload={"enabled": True, "comment": comment, "ids": [endpoint_id]},
    )


def unisolate_device(client, endpoint_id: str, comment: str = "Released via SIEM") -> dict:
    return client.request(
        "POST",
        "/endpoint/v1/endpoints/isolation",
        payload={"enabled": False, "comment": comment, "ids": [endpoint_id]},
    )


# ── Normalization ─────────────────────────────────────────────────────────────

def normalize_device(device: dict) -> dict:
    health   = device.get("health", {})
    os_info  = device.get("os", {})
    iso      = device.get("isolation", {})
    group    = device.get("group", {})

    os_name = " ".join(filter(None, [
        os_info.get("name"),
        str(os_info.get("majorVersion", "")) or None,
    ]))

    # assignedUser can be a list or a single object depending on the Sophos API version
    raw_user = device.get("assignedUser") or device.get("associatedPerson", {})
    if isinstance(raw_user, list):
        raw_user = raw_user[0] if raw_user else {}
    assigned_user = (
        raw_user.get("name")
        or raw_user.get("displayName")
        or raw_user.get("email")
        or raw_user.get("id")
    ) if isinstance(raw_user, dict) else None

    return {
        "endpoint_id":      device.get("id"),
        "hostname":         device.get("hostname"),
        "type":             device.get("type"),
        "ip_addresses":     device.get("ipv4Addresses", []),
        "mac_addresses":    device.get("macAddresses", []),
        "os":               os_name.strip() or None,
        "group":            group.get("name"),
        "assignedUser":     assigned_user,
        "health_overall":   health.get("overall"),
        "health_threats":   health.get("threats", {}).get("status"),
        "health_services":  health.get("services", {}).get("status"),
        "isolated":         iso.get("isolated", False),
        "tamper_protected": device.get("tamperProtectionEnabled", False),
        "last_seen":        device.get("lastSeenAt"),
        "products":         [p.get("code") for p in device.get("assignedProducts", [])],
    }
