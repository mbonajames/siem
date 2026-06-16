from pydantic import BaseModel
from typing import Optional, Dict, Any,List

class MitreTechnique(BaseModel):
    id:        Optional[str] = None   # e.g. T1550.001
    technique: Optional[str] = None   # e.g. Application Access Token
    tactics:   Optional[List[str]] = None  # e.g. ["lateral-movement"]


class UnifiedEvent(BaseModel):
    event_id: str
    time: str
    category: str        # Authentication, Network, Findings
    event_class: str     # Authentication, Network Activity
    severity: str        # Low, Medium, High, Critical
    summary: str         # wazuh rule description
    user: Optional[str] = None
    users: Optional[List[str]] = None
    host: Optional[str] = None
    src_ip: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[str] = None
    domain: Optional[str] = None
    source: str
    mitre: Optional[List[MitreTechnique]] = None  # MITRE ATT&CK techniques (Darktrace + future)
    misp: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any]