import hashlib
import re
from urllib.parse import urlparse
import tldextract


# Maps the last segment of @odata.type to a human-readable section label
_EV_TYPE_LABEL = {
    "mailboxEvidence":          "mailbox",
    "mailMessageEvidence":      "email_message",
    "mailClusterEvidence":      "email_cluster",
    "ipEvidence":               "ip_entity",
    "urlEvidence":              "url_entity",
    "fileEvidence":             "file_entity",
    "processEvidence":          "process",
    "deviceEvidence":           "device",
    "userEvidence":             "user",
    "cloudApplicationEvidence": "cloud_app",
    "securityGroupEvidence":    "security_group",
}


class Normalizer:
    def normalize(self, hit: dict) -> dict:
        src = hit["_source"]

        category, event_class = self._classify_event(src)
        entities = self._extract_entities(src)
        severity = self._normalize_severity(src)

        return {
            "event_id":   self._generate_event_id(src),
            "time":       self._extract_time(src),
            "category":   category,
            "event_class": event_class,
            "severity":   severity,
            "summary":    self._extract_summary(src),
            "user":       entities.get("user"),
            "users":      entities.get("users"),
            "host":       entities.get("host"),
            "src_ip":     entities.get("src_ip"),
            "remote_ip":  entities.get("remote_ip"),
            "remote_port": entities.get("remote_port"),
            "domain":        entities.get("domain"),
            "sender_domain": entities.get("sender_domain"),
            "source":        self._detect_source(src),
            "mitre":      self._extract_mitre(src),
            "misp":       src.get("misp"),
            "raw":        self._build_raw(src),
        }

     # detect the source log 

    def _is_darktrace(self, src: dict) -> bool:
        groups   = src.get("rule", {}).get("groups", []) or []
        location = src.get("location") or src.get("data", {}).get("location") or ""
        return "darktrace" in groups or "darktrace" in location.lower()

    def _is_dt_agemail(self, src: dict) -> bool:
        """True when this is a Darktrace AGEMail (email analysis) alert."""
        data = src.get("data", {})
        return self._is_darktrace(src) and (
            "recipients" in data or "from" in data or "subject" in data
        )

    def _detect_source(self, src: dict) -> str:
        data = src.get("data", {})
        integ = data.get("integration")
        if integ:
            return integ
        if self._is_darktrace(src):
            return "darktrace"
        groups = src.get("rule", {}).get("groups", []) or []
        if "sophos" in groups:
            return "sophos-central"
        if "ms-graph" in groups:
            return "ms-graph"
        return "wazuh"

    
    def _generate_event_id(self, src):
        data = src.get("data", {})
        pbid = data.get("pbid")
        ts = self._extract_time(src)
        rule_id = src.get("rule", {}).get("id")
        base = f"{rule_id}-{pbid or ''}-{ts}"
        # base = f"{src.get('rule', {}).get('id')}-{src.get('timestamp')}"
        return hashlib.sha256(base.encode()).hexdigest()


    def _extract_time(self, src):
        return src.get("data", {}).get("timestamp") or src.get("timestamp") or src.get("@timestamp")


    def _extract_summary(self, src):
        if self._is_darktrace(src):
            data = src.get("data", {})
            if self._is_dt_agemail(src):
                subject = data.get("subject")
                sender  = data.get("from", "")
                if subject:
                    return f"AGEMail: {subject} (from {sender})" if sender else f"AGEMail: {subject}"
            model_name = (data.get("model") or {}).get("name")
            if model_name:
                return model_name
        if src.get("data", {}).get("integration") == "ms-defender":
            return src.get("data", {}).get("defender", {}).get("title") \
                or src.get("rule", {}).get("description", "No description")
        return src.get("rule", {}).get("description", "No description")


    def _classify_event(self, src):
        groups = src.get("rule", {}).get("groups", [])
        desc = src.get("rule", {}).get("description", "").lower()
        sophos_group = src.get("data", {}).get("sophos", {}).get("group",[])
        data = src.get("data", {})


        if "CONNECTIVITY" in sophos_group:
            return "CONNECTIVITY","Sophos"

        if "authentication" in groups or "login" in desc:
            return "Authentication", "Login Activity"

        if "systemd" in groups:
            return "Command execution","Local System"

        if "sophos" in groups:
            if "web" in desc:
                return "Endpoint Activity", "Web Control Violation"
            return "Endpoint Activity", "Endpoint Event"

        if data.get("integration") == "ms-defender":
            cat = (data.get("defender", {}).get("category") or "").strip()
            _MAP = {
                "advancedPersistenceThreat": ("Endpoint Activity",  "APT"),
                "commandAndControl":         ("Network Activity",   "C2 Communication"),
                "credentialAccess":          ("Authentication",     "Credential Access"),
                "defenseEvasion":            ("Endpoint Activity",  "Defense Evasion"),
                "discovery":                 ("Endpoint Activity",  "Discovery"),
                "execution":                 ("Endpoint Activity",  "Execution"),
                "exfiltration":              ("Network Activity",   "Exfiltration"),
                "exploit":                   ("Endpoint Activity",  "Exploit"),
                "generalMalware":            ("Endpoint Activity",  "Malware"),
                "impact":                    ("Endpoint Activity",  "Impact"),
                "initialAccess":             ("Endpoint Activity",  "Initial Access"),
                "lateralMovement":           ("Network Activity",   "Lateral Movement"),
                "maliciousActivity":         ("Endpoint Activity",  "Malicious Activity"),
                "phishing":                  ("Email Security",     "Phishing"),
                "persistence":               ("Endpoint Activity",  "Persistence"),
                "privilegeEscalation":       ("Endpoint Activity",  "Privilege Escalation"),
                "ransomware":                ("Endpoint Activity",  "Ransomware"),
                "suspiciousActivity":        ("Endpoint Activity",  "Suspicious Activity"),
            }
            return _MAP.get(cat, ("Endpoint Activity", "Security Alert"))

        if "ms-graph" in groups or data.get("integration") == "ms-graph":
            ms = data.get("ms-graph", {})
            return (ms.get("relationship", "unknown"),ms.get("category", "unknown"))


        if self._is_darktrace(src):
            if self._is_dt_agemail(src):
                tags = data.get("tags") or []
                tags_lower = [t.lower() for t in tags]
                if any("phish" in t for t in tags_lower):
                    return "Email Security", "Phishing"
                if any("malware" in t or "malicious" in t for t in tags_lower):
                    return "Email Security", "Malicious Email"
                return "Email Security", "Suspicious Email"
            model_name = (data.get("model") or {}).get("name", "")
            area = model_name.split("::")[0] if model_name else ""
            area_map = {
                "SaaS":              "SaaS Activity",
                "Device":            "Endpoint Activity",
                "Network":           "Network Activity",
                "User":              "User Activity",
                "Compliance":        "Compliance",
                "Email":             "Email Security",
                "Cyber AI Analyst":  "AI Analyst",
            }
            category   = area_map.get(area, "Network Activity")
            event_class = (data.get("model") or {}).get("category") or "Model Breach"
            return category, event_class

        return "Other", "Unknown Event"


    def _normalize_severity(self, src):
        if self._is_darktrace(src):
            # AGEMail: use anomaly_score (0–100) instead of model category
            if self._is_dt_agemail(src):
                try:
                    score = float(src.get("data", {}).get("anomaly_score") or 0)
                    if score >= 85: return "Critical"
                    if score >= 65: return "High"
                    if score >= 40: return "Medium"
                    return "Low"
                except (ValueError, TypeError):
                    pass
            return self._darktrace_severity(src)

        # Defender: explicit severity field stored in data.defender.severity
        if src.get("data", {}).get("integration") == "ms-defender":
            sev = (src.get("data", {}).get("defender", {}).get("severity") or "").lower()
            return {
                "high":          "High",
                "medium":        "Medium",
                "low":           "Low",
                "informational": "Low",
            }.get(sev, "Low")

        sophos_sev = src.get("data", {}).get("sophos", {}).get("severity")
        if sophos_sev:
            return sophos_sev.capitalize()

        level = src.get("rule", {}).get("level", 0)
        if level <= 6:
            return "Low"
        if level <= 11:
            return "Medium"
        if level <= 14:
            return "High"
        return "Critical"

    def _darktrace_severity(self, src: dict) -> str:
        data     = src.get("data", {})
        category = ((data.get("model") or {}).get("category") or "").lower()

        if "critical" in category:
            return "Critical"
        if "suspicious" in category:
            return "High"
        if "unusual" in category:
            return "Medium"
        if "compliance" in category:
            return "Medium"
        if "informational" in category:
            return "Low"

        # Fall back to percentScore (stored as string, e.g. "43")
        try:
            score = float(data.get("percentScore") or data.get("score", 0))
            if score >= 80:
                return "Critical"
            if score >= 60:
                return "High"
            if score >= 40:
                return "Medium"
            return "Low"
        except (ValueError, TypeError):
            pass

        # Final fallback: rule.level
        level = src.get("rule", {}).get("level", 0)
        if level <= 6:   return "Low"
        if level <= 11:  return "Medium"
        if level <= 14:  return "High"
        return "Critical"


    def _extract_entities(self, src):
        data   = src.get("data", {})
        sophos = data.get("sophos", {})
        ms     = data.get("ms-graph", {})
        win    = data.get("win", {})

        # ── Darktrace AGEMail ─────────────────────────────────────────────────
        if self._is_dt_agemail(src):
            recipients  = data.get("recipients") or []
            sender      = data.get("from") or ""
            link_hosts  = data.get("link_hosts") or []
            # Primary suspicious domain: first link_host, fallback to sender domain
            sender_dom  = sender.split("@")[1].strip() if "@" in sender else None
            raw_domain  = link_hosts[0] if link_hosts else sender_dom
            return {
                "user":          recipients[0] if recipients else None,
                "users":         recipients or [],
                "host":          None,
                "src_ip":        None,
                "remote_ip":     None,
                "remote_port":   None,
                "domain":        self._get_root_domain(raw_domain),
                "sender_domain": sender_dom,
            }

        # ── ms-defender (new direct integration) ─────────────────────────────
        if data.get("integration") == "ms-defender":
            d     = data.get("defender", {})
            user  = d.get("user_upn") or d.get("user_account")
            users = [user] if user else []
            # users list can also come from evidence
            for ev in (d.get("evidence") or []):
                if ev.get("type") == "user":
                    u = ev.get("upn") or ev.get("account")
                    if u and u not in users:
                        users.append(u)
            return {
                "user":        user,
                "users":       users or None,
                "host":        d.get("device_hostname") or src.get("agent", {}).get("name"),
                "src_ip":      d.get("device_ip"),
                "remote_ip":   d.get("remote_ip"),
                "remote_port": d.get("remote_port"),
                "domain":      self._get_root_domain(
                    (d.get("domains") or [None])[0] if d.get("domains") else None
                ),
            }

        # Safe first-evidence accessor — avoids IndexError on empty list
        ev0 = (ms.get("evidence") or [{}])[0]

        user = (
            sophos.get("suser")
            or ev0.get("primaryAddress")
            or ev0.get("userAccount", {}).get("userPrincipalName")
            # Wazuh Windows event fields
            or win.get("eventdata", {}).get("subjectUserName")
            or win.get("eventdata", {}).get("targetUserName")
            # Wazuh generic fields
            or data.get("srcuser")
            or data.get("dstuser")
            or data.get("user")
        )
        users = [user] if user else []


        host = (
            sophos.get("dhost")
            or data.get("device",{}).get("hostname")
            or src.get("agent", {}).get("name")
        )

        src_ip = (
            sophos.get("source_info", {}).get("ip")
            or data.get("src_ip")
            or data.get("ipAddress")
            or data.get("device",{}).get("ip")
        )

        ips_data    = sophos.get("ips_threat_data", {}) or {}
        remote_ip   = (
            ips_data.get("remoteIp")
            or self._extract_remote_ip(ms)
        )
        remote_port = (
            str(ips_data["remotePort"]) if ips_data.get("remotePort") else None
        )

        domain = (self._extract_domain(sophos.get("name", ""))
                  or self._extract_domain_from_email(ms))
        domain = domain.lower() if domain else None
        domain = self._get_root_domain(domain)

        entities = {
            "user":        user,
            "users":       users,
            "host":        host,
            "src_ip":      src_ip,
            "remote_ip":   remote_ip,
            "remote_port": remote_port,
            "domain":      domain,
        }

        if self._is_darktrace(src):
            dt_device = data.get("device", {}) or {}
            dt_users = dt_device.get("credentials") or []
            dt_users = list(dict.fromkeys([u for u in dt_users if str(u).strip()]))

            if dt_users:
                entities["users"] = list(set(entities.get("users", []) + dt_users))
                entities["user"] = dt_users[0]  # primary user
                
            if dt_device.get("hostname"):
                entities["host"] = dt_device.get("hostname")
            
            if data.get("sourceIP"):
                entities["src_ip"] = data.get("sourceIP")

            if data.get("dest"):
                entities["domain"] = self._get_root_domain(data.get("dest"))

            for comp in data.get("triggeredComponents", []) or []:
                for flt in comp.get("triggeredFilters", []) or []:
                    ftype = (flt.get("filterType") or "").lower()
                    trig = flt.get("trigger", {}) or {}
                    val = trig.get("value")
                    if not val:
                        continue
                    if ftype == "destination ip":
                        entities["remote_ip"] = str(val)

                    if ftype == "destination port":
                        entities["remote_port"] = str(val)
        return entities

    def _extract_domain(self, text: str) -> str | None: 
        if not text: 
            return None
        url_match = re.search(r"https?://[^\s'\"]+", text)
        if not url_match:
            return None
        url = url_match.group(0)
        parsed = urlparse(url)
        return parsed.hostname

    
    def _extract_domain_from_email(self, ms):
        for ev in ms.get("evidence", []):
            sender = ev.get("p1Sender", {}).get("emailAddress")
            if sender and "@" in sender:
                return sender.split("@")[1]
        return None


    def _build_raw(self, src):
        data = src.get("data", {})

        if data.get("integration") == "ms-defender":
            d   = data.get("defender", {})
            raw = {
                "alert_id":        d.get("alert_id"),
                "incident_id":     d.get("incident_id"),
                "title":           d.get("title"),
                "description":     d.get("description"),
                "severity":        d.get("severity"),
                "status":          d.get("status"),
                "category":        d.get("category"),
                "classification":  d.get("classification"),
                "determination":   d.get("determination"),
                "service_source":  d.get("service_source"),
                "detection_source": d.get("detection_source"),
                "threat_family":   d.get("threat_family"),
                "actor":           d.get("actor"),
                "alert_url":       d.get("alert_url"),
                "incident_url":    d.get("incident_url"),
                "assigned_to":     d.get("assigned_to"),
                "created":         d.get("created"),
                "first_activity":  d.get("first_activity"),
                "last_activity":   d.get("last_activity"),
            }
            # Evidence items — grouped by type
            type_counts: dict[str, int] = {}
            for ev in (d.get("evidence") or []):
                etype = ev.get("type", "evidence")
                count = type_counts.get(etype, 0) + 1
                type_counts[etype] = count
                key = etype if count == 1 else f"{etype}_{count}"
                raw[key] = {k: v for k, v in ev.items() if k != "type" and v not in (None, "", [])}
            # Analyst comments
            for i, c in enumerate(d.get("comments") or []):
                raw[f"comment_{i + 1}"] = f"{c.get('author', 'unknown')}: {c.get('text', '')}"
            return {k: v for k, v in raw.items() if v not in (None, "", {}, [])}

        if data.get("integration") == "sophos-central":
            sophos = data.get("sophos", {}) or {}
            _SKIP = (None, "", "n/a", "N/A", [], {})
            raw = {k: v for k, v in sophos.items() if v not in _SKIP}
            return raw
        if data.get("integration") == "ms-graph":
            ms = data.get("ms-graph", {})
            raw = {}
            for k, v in {
                "title":        ms.get("title") or ms.get("description"),
                "description":  ms.get("displayName"),
                "severity":     ms.get("severity"),
                "status":       ms.get("status"),
                "category":     ms.get("category"),
                "alert_id":     ms.get("id"),
                "incident_id":  ms.get("incidentId"),
                "alert_url":    ms.get("alertWebUrl"),
                "incident_url": ms.get("incidentWebUrl"),
                "created":      ms.get("createdDateTime"),
                "comment":      ms.get("resolvingComment"),
            }.items():
                if v is not None and str(v).strip():
                    raw[k] = v

            # Add each evidence item under a type-based label
            type_counts: dict[str, int] = {}
            for ev in ms.get("evidence", []):
                ev_type = ev.get("@odata", {}).get("type", "").split(".")[-1]
                label = _EV_TYPE_LABEL.get(ev_type, ev_type or "evidence")
                count = type_counts.get(label, 0) + 1
                type_counts[label] = count
                key = label if count == 1 else f"{label}_{count}"
                fields = self._flatten_evidence_item(ev)
                if fields:
                    raw[key] = fields

            return raw
        if self._is_darktrace(src):
            # ── AGEMail (email analysis) ──────────────────────────────────────
            if self._is_dt_agemail(src):
                _SKIP = (None, "", [], {})
                raw: dict = {
                    "subject":       data.get("subject"),
                    "from":          data.get("from"),
                    "direction":     data.get("direction"),
                    "recipients":    data.get("recipients"),
                    "anomaly_score": data.get("anomaly_score"),
                    "tags":          data.get("tags"),
                    "link_hosts":    data.get("link_hosts"),
                    "actions":       data.get("actions"),
                    "portal_url":    data.get("url"),
                }
                if data.get("attachment_names"):
                    raw["attachment_names"] = data["attachment_names"]
                if data.get("attachment_sha256s"):
                    raw["attachment_sha256"] = data["attachment_sha256s"]
                if data.get("attachment_sha1s"):
                    raw["attachment_sha1"] = data["attachment_sha1s"]
                return {k: v for k, v in raw.items() if v not in _SKIP}

            # ── AI Analyst / Model Breach ─────────────────────────────────────
            device          = data.get("device", {}) or {}
            first_ip        = (device.get("ips") or [{}])[0]
            first_tag       = (device.get("tags") or [{}])[0]
            first_component = (data.get("triggeredComponents") or [{}])[0]
            first_filter    = (first_component.get("triggeredFilters") or [{}])[0]
            mitre_list      = [
                {
                    "id":        t.get("techniqueID"),
                    "technique": t.get("technique"),
                    "tactics":   t.get("tactics"),
                }
                for t in (data.get("mitreTechniques") or [])
                if isinstance(t, dict)
            ]
            raw = {
                "time":             data.get("creationTime"),
                "model":            (data.get("model") or {}).get("name"),
                "score":            data.get("percentScore"),
                "category":         (data.get("model") or {}).get("category"),
                "breach_url":       data.get("breachUrl"),
                "pbid":             data.get("pbid"),
                "IP":               data.get("sourceIP"),
                "hostname":         device.get("hostname"),
                "subnet":           first_ip.get("subnet"),
                "tag":              first_tag.get("name"),
                "metric":           first_component.get("metric", {}).get("label"),
                "trigger_value":    first_filter.get("trigger", {}).get("value"),
                "mitre_techniques": mitre_list if mitre_list else None,
            }
            return {k: v for k, v in raw.items() if v is not None}
        return {}

    def _flatten_evidence_item(self, ev: dict) -> dict:
        out = {}
        ua = ev.get("userAccount", {})
        p1 = ev.get("p1Sender", {})

        def add(key, *vals):
            for v in vals:
                if v is not None and str(v).strip():
                    out[key] = str(v)
                    return

        add("verdict",           ev.get("verdict"))
        add("remediation",       ev.get("remediationStatus"))
        add("email",             ev.get("primaryAddress"))
        add("upn",               ua.get("userPrincipalName"), ev.get("upn"))
        add("display_name",      ev.get("displayName"), ua.get("displayName"))
        add("account",           ua.get("accountName"))
        add("account_domain",    ua.get("domainName"))
        add("subject",           ev.get("subject"))
        add("message_id",        ev.get("internetMessageId"))
        add("network_id",        ev.get("networkMessageId"))
        add("sender_ip",         ev.get("senderIp"))
        add("recipient",         ev.get("recipientEmailAddress"))
        add("delivery_action",   ev.get("deliveryAction"))
        add("delivery_location", ev.get("deliveryLocation"))
        add("attachments",       ev.get("attachmentsCount"))
        add("url_count",         ev.get("urlCount"))
        add("sender",            p1.get("emailAddress"))
        add("sender_domain",     p1.get("domainName"))
        add("sender_name",       p1.get("displayName"))
        add("ip",                ev.get("ipAddress"))
        add("url",               ev.get("url"))
        add("file",              ev.get("fileName"), ev.get("instanceName"))
        add("sha256",            ev.get("sha256"))
        return out
    
    
    def _extract_remote_ip(self, ms):
        for ev in ms.get("evidence", []):
            ip = ev.get("senderIp")
            if ip:
                return ip
        return None
    
    
    def _parse_ips_field(self, raw_data: str, key: str) -> str | None:
        for line in (raw_data or "").splitlines():
            if line.strip().lower().startswith(key.lower() + ":"):
                val = line.split(":", 1)[1].strip()
                return val if val else None
        return None

    def _extract_mitre(self, src: dict) -> list | None:
        data = src.get("data", {})
        # ms-defender stores under data.defender.mitreTechniques
        if data.get("integration") == "ms-defender":
            raw = data.get("defender", {}).get("mitreTechniques") or []
        else:
            raw = data.get("mitreTechniques") or []
        if not raw:
            return None
        result = []
        for t in raw:
            if not isinstance(t, dict):
                continue
            entry = {
                "id":        t.get("techniqueID"),
                "technique": t.get("technique"),
                "tactics":   t.get("tactics"),
            }
            if any(v for v in entry.values()):
                result.append(entry)
        return result or None


    # Darktrace methods
    def _darktrace_get_trigger_value(self, src: dict, filter_type: str):
        data = src.get("data", {})
        for comp in data.get("triggeredComponents", []) or []:
            for flt in comp.get("triggeredFilters", []) or []:
                if (flt.get("filterType") or "").lower() == filter_type.lower():
                    trig = flt.get("trigger", {}) or {}
                    val = trig.get("value")
                    if val is not None and str(val).strip():
                        return str(val)
        return None


    def _extract_darktrace_entities(self, src: dict):
        data = src.get("data", {})
        users = (data.get("device", {}) or {}).get("credentials") or []
        users = list(dict.fromkeys([u for u in users if str(u).strip()]))
        user = users[0] if users else None
        host = (data.get("device", {}) or {}).get("hostname")
        src_ip = data.get("sourceIP") or (data.get("device", {}) or {}).get("ip")
        domain = data.get("dest")
        remote_ip = self._darktrace_get_trigger_value(src, "Destination IP")
        remote_port = self._darktrace_get_trigger_value(src, "Destination port")
        return {
        "user": user,
        "users": users,
        "host": host,
        "src_ip": src_ip,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "domain": domain.lower() if isinstance(domain, str) else domain
    }
        
       
    def _get_root_domain(self, domain):
        if not domain or not isinstance(domain, str):
            return None
        if domain.startswith("http"):
            parsed = urlparse(domain)
            domain = parsed.hostname
        if not domain:
            return None

        ext = tldextract.extract(domain)

        if ext.domain and ext.suffix:
           return f"{ext.domain}.{ext.suffix}"

        return None
 
        