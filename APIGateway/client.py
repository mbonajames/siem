from opensearchpy import OpenSearch
import os
import time
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SophosAPIError(Exception):
    def __init__(self, status_code: int, detail):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Sophos {status_code}: {detail}")

load_dotenv()

# ── Wazuh Indexer ─────────────────────────────────────────────────────────────
indexer_client = OpenSearch(
    hosts=[os.getenv("WAZUH_INDEXER_URL")],
    http_auth=(
        os.getenv("WAZUH_INDEXER_USER"),
        os.getenv("WAZUH_INDEXER_PASSWORD")
    ),
    use_ssl=True,
    verify_certs=False,
    timeout=120,
)

# ── Sophos Central ────────────────────────────────────────────────────────────
class SophosCentralClient:
    """
    Handles Sophos Central API auth and HTTP requests.

    Auth flow (required by Sophos):
      1. POST to id.sophos.com  → access_token
      2. GET  whoami            → tenant id + regional base URL
      3. All subsequent calls use the regional base URL + X-Tenant-ID header
    """
    _TOKEN_URL  = "https://id.sophos.com/api/v2/oauth2/token"
    _WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"

    # Refresh the token 60 s before it actually expires to avoid mid-request failures
    _TOKEN_BUFFER = 60

    def __init__(self):
        self.client_id     = os.getenv("SOPHOS_CLIENT_ID")
        self.client_secret = os.getenv("SOPHOS_CLIENT_SECRET")
        self.token         = None
        self.tenant_id     = None
        self.base_url      = None
        self._token_expiry = 0.0   # epoch seconds when token expires
        self._authenticate()

    def _authenticate(self):
        # Step 1 – get bearer token
        r = requests.post(self._TOKEN_URL, data={
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "token",
        })
        r.raise_for_status()
        data = r.json()
        self.token = data["access_token"]
        # Sophos returns expires_in (seconds); default to 3600 if missing
        expires_in = int(data.get("expires_in", 3600))
        self._token_expiry = time.monotonic() + expires_in

        # Step 2 – discover tenant id and regional API base URL (only needed once)
        if not self.tenant_id:
            whoami = requests.get(
                self._WHOAMI_URL,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            whoami.raise_for_status()
            info = whoami.json()
            self.tenant_id = info["id"]
            self.base_url  = info["apiHosts"]["dataRegion"]

    def _ensure_token(self):
        if time.monotonic() >= (self._token_expiry - self._TOKEN_BUFFER):
            self._authenticate()

    def _headers(self):
        return {
            "Authorization":  f"Bearer {self.token}",
            "X-Tenant-ID":    self.tenant_id,
            "Content-Type":   "application/json",
        }

    def request(self, method: str, endpoint: str, params=None, payload=None):
        self._ensure_token()
        url = f"{self.base_url}{endpoint}"
        r = requests.request(
            method, url,
            headers=self._headers(),
            params=params,
            json=payload,
        )
        # Retry once on 401 — token may have expired a moment before our check
        if r.status_code == 401:
            self._authenticate()
            r = requests.request(
                method, url,
                headers=self._headers(),
                params=params,
                json=payload,
            )
        if r.status_code >= 400:
            try:
                detail = r.json()
            except Exception:
                detail = r.text
            raise SophosAPIError(r.status_code, detail)
        try:
            return r.json() if r.text.strip() else {}
        except ValueError:
            return {}


# ── Nessus ────────────────────────────────────────────────────────────────────

class NessusClient:
    def __init__(self):
        self.base_url = os.getenv("NESSUS_URL", "https://localhost:8834")
        access_key    = os.getenv("NESSUS_ACCESS_KEY", "")
        secret_key    = os.getenv("NESSUS_SECRET_KEY", "")
        self._headers = {
            "X-ApiKeys":    f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }
        self._session         = requests.Session()
        self._session.verify  = False

    def get(self, path: str, params=None) -> dict:
        r = self._session.get(
            f"{self.base_url}{path}", headers=self._headers,
            params=params, timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def post(self, path: str, payload: dict | None = None) -> dict:
        r = self._session.post(
            f"{self.base_url}{path}", headers=self._headers,
            json=payload or {}, timeout=30,
        )
        if not r.ok:
            try:
                body = r.json()
            except Exception:
                body = r.text
            raise RuntimeError(f"Nessus {r.status_code}: {body}")
        return r.json() if r.text.strip() else {}

    def download(self, path: str) -> bytes:
        headers = {k: v for k, v in self._headers.items() if k != "Content-Type"}
        headers["Accept"] = "application/octet-stream"
        r = self._session.get(f"{self.base_url}{path}", headers=headers, timeout=60)
        if not r.ok:
            try:
                body = r.json()
            except Exception:
                body = r.text
            raise RuntimeError(f"Nessus {r.status_code}: {body}")
        return r.content


nessus_client = NessusClient()


# ── JIRA ─────────────────────────────────────────────────────────────────────

class JiraClient:
    def __init__(self):
        self.base_url = (os.getenv("JIRA_BASE_URL") or "").rstrip("/")
        self.project  = os.getenv("JIRA_PROJECT_KEY", "")
        email         = os.getenv("JIRA_EMAIL", "")
        api_token     = os.getenv("JIRA_API_TOKEN", "")
        self._session = requests.Session()
        self._session.auth = (email, api_token)
        self._session.headers.update({
            "Accept":       "application/json",
            "Content-Type": "application/json",
        })

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.project)

    def find_by_label(self, label: str) -> str | None:
        jql = f'project = "{self.project}" AND labels = "{label}" ORDER BY created DESC'
        r   = self._session.post(
            f"{self.base_url}/rest/api/3/search/jql",
            json={"jql": jql, "fields": ["key"], "maxResults": 1},
            timeout=15,
        )
        r.raise_for_status()
        issues = r.json().get("issues", [])
        return issues[0]["key"] if issues else None

    def create_issue(self, summary: str, description: dict, labels: list[str]) -> dict:
        payload = {
            "fields": {
                "project":     {"key": self.project},
                "summary":     summary,
                "description": description,
                "issuetype":   {"name": "Service Request"},
                "labels":      labels,
            }
        }
        r = self._session.post(
            f"{self.base_url}/rest/api/3/issue",
            json=payload,
            timeout=15,
        )
        if not r.ok:
            try:
                body = r.json()
            except Exception:
                body = r.text
            raise ValueError(f"JIRA {r.status_code}: {body}")
        return r.json()


jira_client = JiraClient()


# ── Wazuh Server API ──────────────────────────────────────────────────────────

class WazuhServerClient:
    """
    Client for the Wazuh Manager REST API (default port 55000).
    Auth: POST /security/user/authenticate with Basic credentials → JWT.
    Tokens expire in 900 s; we refresh 60 s before expiry to avoid mid-request failures.
    """
    _TOKEN_BUFFER = 60  # seconds before expiry to proactively refresh

    def __init__(self):
        self.base_url      = (os.getenv("WAZUH_API_URL") or "").rstrip("/")
        self._user         = os.getenv("WAZUH_API_USER", "wazuh-wui")
        self._password     = os.getenv("WAZUH_API_PASS", "")
        self._verify       = os.getenv("WAZUH_API_VERIFY_CERT", "false").lower() == "true"
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._session             = requests.Session()
        self._session.verify      = self._verify

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self._user and self._password)

    def _authenticate(self) -> None:
        try:
            r = self._session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self._user, self._password),
                timeout=10,
            )
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(f"SSL error connecting to Wazuh API at {self.base_url}: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(f"Cannot reach Wazuh Server API at {self.base_url} — is port 55000 open? ({exc})") from exc
        except requests.exceptions.Timeout:
            raise RuntimeError(f"Wazuh Server API authentication timed out ({self.base_url})") from None

        if not r.ok:
            try:
                body = r.json()
            except Exception:
                body = r.text[:300]
            raise RuntimeError(f"Wazuh auth failed HTTP {r.status_code}: {body}")

        try:
            self._token = r.json()["data"]["token"]
        except (KeyError, ValueError) as exc:
            raise RuntimeError(f"Unexpected Wazuh auth response (no data.token): {r.text[:200]}") from exc

        self._token_expiry = time.monotonic() + 900  # Wazuh default JWT lifetime

    def _ensure_token(self) -> None:
        if not self._token or time.monotonic() >= (self._token_expiry - self._TOKEN_BUFFER):
            self._authenticate()

    def get(self, path: str, params: dict | None = None) -> dict:
        self._ensure_token()
        r = self._session.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            params=params,
            timeout=15,
        )
        if r.status_code == 401:
            # Token may have been revoked — re-auth once and retry
            self._authenticate()
            r = self._session.get(
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                params=params,
                timeout=15,
            )
        if not r.ok:
            try:
                body = r.json()
            except Exception:
                body = r.text[:300]
            raise RuntimeError(f"Wazuh API {path} returned HTTP {r.status_code}: {body}")
        return r.json()


wazuh_server_client = WazuhServerClient()
