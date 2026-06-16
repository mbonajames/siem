# Regular (non-nested) fields per entity type.
# These support term and match_phrase queries directly.
REGULAR_FIELDS = {
    "user": [
        "data.sophos.suser",             # Sophos
        "data.device.credentials",       # Darktrace model breach (device credentials)
        "data.recipients",               # Darktrace AGEMail recipients (array)
        "data.defender.user_upn",        # MS Defender user principal name
        "data.defender.user_account",    # MS Defender user account (fallback)
        "full_log",
    ],
    "host": [
        "data.sophos.dhost",
        "data.device.hostname",          # Darktrace
        "data.defender.device_hostname", # MS Defender
        "full_log",
    ],
    "ip": [
        "data.sophos.source_info.ip",
        "data.sourceIP",                 # Darktrace
        "data.device.ip",
        "data.ipAddress",
        "data.defender.device_ip",       # MS Defender endpoint IP
        "data.defender.remote_ip",       # MS Defender remote IP
        "full_log",
    ],
    "domain": [
        "data.sophos.name",
        "data.dest",                     # Darktrace model breach destination
        "data.link_hosts",               # Darktrace AGEMail link hosts (array)
        "full_log",
    ],
}

# MS Graph evidence fields (mapped as `nested` type at data.ms-graph.evidence).
# These MUST be wrapped in a `nested` query — regular queries skip nested objects.
# All sub-fields are keyword type, so use `term` (exact match).
MSGRAPH_EVIDENCE_FIELDS = {
    "user": [
        "data.ms-graph.evidence.primaryAddress",
        "data.ms-graph.evidence.userAccount.userPrincipalName",
        "data.ms-graph.evidence.recipientEmailAddress",
        "data.ms-graph.evidence.p1Sender.emailAddress",
        "data.ms-graph.evidence.p2Sender.emailAddress",
        "data.ms-graph.evidence.upn",
    ],
    "host": [],
    "ip": [
        "data.ms-graph.evidence.senderIp",
        "data.ms-graph.evidence.ipAddress",
    ],
    "domain": [
        "data.ms-graph.evidence.p1Sender.domainName",
        "data.ms-graph.evidence.p2Sender.domainName",
        "data.ms-graph.evidence.userAccount.domainName",
    ],
}

# Email address fields inside evidence — used for wildcard domain matching.
# e.g. domain "evil.com" → wildcard "*@evil.com" against these fields.
MSGRAPH_EVIDENCE_EMAIL_FIELDS = [
    "data.ms-graph.evidence.p1Sender.emailAddress",
    "data.ms-graph.evidence.p2Sender.emailAddress",
    "data.ms-graph.evidence.recipientEmailAddress",
    "data.ms-graph.evidence.primaryAddress",
    "data.ms-graph.evidence.userAccount.userPrincipalName",
]

MSGRAPH_NESTED_PATH = "data.ms-graph.evidence"

# Legacy alias kept so main.py import doesn't break during transition
FIELD_MAP = {
    k: REGULAR_FIELDS[k] + MSGRAPH_EVIDENCE_FIELDS[k]
    for k in REGULAR_FIELDS
}

# Darktrace

