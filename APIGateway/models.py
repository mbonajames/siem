from pydantic import BaseModel
from typing import Literal, Optional, Dict, Any, List

EntityType = Literal["user", "host", "ip", "domain"]
Severity = Literal["Low", "Medium", "High", "Critical"]


class AlertsPage(BaseModel):
    total:  int
    events: List[Dict[str, Any]]


class InvestigateRequest(BaseModel):
    entity_type: EntityType
    value: str
    start: Optional[str] = None
    end: Optional[str] = None
    severities: Optional[List[Severity]] = None
    sources: Optional[List[str]] = None
    limit: int = 100
    offset: int = 0
    

class InvestigateResponse(BaseModel):
    entity: Dict[str, str]
    summary: Dict[str, Any]
    related: Dict[str, List[str]]
    events: List[Dict[str, Any]]


class NessusExportRequest(BaseModel):
    format: Literal["csv", "html", "nessus"] = "csv"


class JiraBatchCheckRequest(BaseModel):
    event_ids: List[str]



class JiraAssignRequest(BaseModel):
    account_id: str


class JiraTicketRequest(BaseModel):
    event_id:  str
    time:      str
    severity:  str
    source:    str
    category:  str
    summary:   str
    user:      Optional[str]  = None
    host:      Optional[str]  = None
    src_ip:    Optional[str]  = None
    raw:       Optional[dict] = None   # full raw data dict (Defender-rich tickets)
    mitre:     Optional[list] = None   # [{id, technique, tactics}]


# ── Custom dashboards ─────────────────────────────────────────────────────────

class WidgetConfig(BaseModel):
    hours:    Optional[int] = 24
    limit:    Optional[int] = 20
    severity: Optional[str] = None
    source:   Optional[str] = None
    metric:   Optional[str] = None  # stat-card: total|critical|high|medium|low|ioc
    text:     Optional[str] = None  # text widget content

class DashboardWidget(BaseModel):
    id:     str
    type:   str
    title:  str
    size:   str = "half"  # quarter|half|three-quarter|full
    config: WidgetConfig = WidgetConfig()

class CreateDashboardRequest(BaseModel):
    name:        str
    description: Optional[str] = ""

class UpdateDashboardRequest(BaseModel):
    name:        Optional[str] = None
    description: Optional[str] = None
    shared:      Optional[bool] = None
    widgets:     Optional[List[Dict[str, Any]]] = None

class ShareDashboardRequest(BaseModel):
    shared: bool