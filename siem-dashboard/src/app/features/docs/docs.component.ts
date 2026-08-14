import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';

interface KeyPath   { label: string; path: string; }
interface RunbookStep  { text: string; code?: string; }
interface RunbookBlock { heading: string; steps: RunbookStep[]; }

interface DocArticle {
  name:        string;
  icon:        string;
  color:       string;
  status:      'live' | 'planned';
  overview:    string;
  keyPaths?:   KeyPath[];
  runbook?:    RunbookBlock[];
  docsUrl?:    string;
  docsLabel?:  string;
  screenshot?: string;
}

interface DocSection {
  id:          string;
  title:       string;
  icon:        string;
  description: string;
  tools:       DocArticle[];
}

const SECTIONS: DocSection[] = [
  {
    id: 'sources', title: 'Data Sources', icon: 'sensors',
    description: 'Where raw security events originate before they reach the SIEM pipeline.',
    tools: [
      {
        name: 'Darktrace', icon: 'bubble_chart', color: '#60a5fa', status: 'live',
        overview: 'Network anomaly detection. Hope-Armor has no direct Darktrace API integration — Darktrace forwards its alerts to the Wazuh manager, which tags them with rule.groups: darktrace, and our API Gateway simply queries OpenSearch for that tag.',
        keyPaths: [
          { label: 'Env vars needed (Armor)', path: 'None — reuses WAZUH_INDEXER_URL / _USER / _PASSWORD' },
          { label: 'API Gateway endpoints', path: 'GET /darktrace/alerts/, /darktrace/summary-statistics/, /darktrace/devices/  (main.py)' },
          { label: 'OpenSearch filter used', path: '{"term": {"rule.groups": "darktrace"}}' },
          { label: 'Grafana datasource / index', path: 'darktrace-agemail → index "darktrace-index_deflector"' },
        ],
        runbook: [
          {
            heading: 'How this is actually wired up in Armor',
            steps: [
              { text: 'There’s no Darktrace client code in the API Gateway (no client_id/secret, no polling job). All Darktrace data already lives in OpenSearch by the time our backend touches it — Wazuh is the ingestion path.' },
              { text: 'Severity is read differently for Darktrace than everything else: every Darktrace-sourced Wazuh rule fires at rule.level=3 regardless of real severity, so main.py reads the actual severity from data.model.category instead of rule.level for these alerts (see build_alert_query in main.py).' },
              { text: 'If Darktrace events stop showing up on the Network Security tab, the fault is almost never Angular/FastAPI — check that events are still landing in the darktrace-index_deflector index in OpenSearch first (e.g. via Grafana’s Explore view on the darktrace-agemail datasource, or directly against the indexer).' },
            ],
          },
        ],
        docsUrl: 'https://customerportal.darktrace.com/', docsLabel: 'Darktrace Customer Portal (login required)',
        screenshot: 'darktrace-threat-visualizer.png',
      },
      {
        name: 'Sophos Central', icon: 'security', color: '#3fb950', status: 'live',
        overview: 'Endpoint protection. The API Gateway talks to Sophos Central directly via OAuth2 to list devices, pull alerts, and trigger isolation from the Endpoint Security tab.',
        keyPaths: [
          { label: 'Env vars (APIGateway/.env)', path: 'SOPHOS_CLIENT_ID, SOPHOS_CLIENT_SECRET' },
          { label: 'Client implementation', path: 'client.py → class SophosCentralClient' },
        ],
        runbook: [
          {
            heading: 'Auth flow this app actually performs',
            steps: [
              { text: 'On startup, SophosCentralClient runs a 3-step handshake required by Sophos’s API:' },
              { text: '1. POST client_id/client_secret (client_credentials grant) to id.sophos.com → bearer access token.', code: 'POST https://id.sophos.com/api/v2/oauth2/token' },
              { text: '2. GET whoami with that token → returns your tenant ID and the correct regional API base URL (Sophos routes tenants to different regions).', code: 'GET https://api.central.sophos.com/whoami/v1' },
              { text: '3. Every subsequent call uses that regional base URL plus an X-Tenant-ID header — the client refreshes the token itself 60 seconds before it expires.' },
            ],
          },
          {
            heading: 'If it stops working',
            steps: [
              { text: 'Test it live from the Connectors tab first — it calls the same client and will surface the actual HTTP error from Sophos rather than a generic failure.' },
              { text: 'A 401 at step 1 means the client ID/secret in .env is wrong or the API credential was revoked in Sophos Central; a failure at whoami with a valid token usually means the credential was created in the wrong Sophos Central region/tenant.' },
            ],
          },
        ],
        docsUrl: 'https://docs.sophos.com/central/Customer/help/en-us/index.html', docsLabel: 'Official Docs',
        screenshot: 'sophos-central-overview.png',
      },
      {
        name: 'Microsoft Defender', icon: 'verified_user', color: '#0078d4', status: 'live',
        overview: 'Defender for Endpoint and Defender for Office 365, pulled in via Microsoft Graph API by a background poller — this is the same Azure app registration used for Entra ID below.',
        keyPaths: [
          { label: 'Env vars (APIGateway/.env)', path: 'AZURE_TENANT_ID, DEFENDER_CLIENT_ID, DEFENDER_CLIENT_SECRET' },
          { label: 'Optional tuning', path: 'DEFENDER_POLL_SECS (default 300), DEFENDER_LOOKBACK_HOURS (default 24)' },
          { label: 'Client implementation', path: 'integrations/ms_defender.py → class DefenderClient' },
          { label: 'Destination index', path: 'siem-defender-* (feeds Endpoint Security and Email Security tabs)' },
        ],
        docsUrl: 'https://learn.microsoft.com/en-us/defender-endpoint/', docsLabel: 'Official Docs',
        screenshot: 'defender-incidents.png',
      },
    ],
  },
  {
    id: 'siem', title: 'SIEM Core — Wazuh Components', icon: 'hub',
    description: 'Log aggregation, indexing, storage, search, and enrichment — the backbone every other tab reads from.',
    tools: [
      {
        name: 'Wazuh', icon: 'shield', color: '#f59e0b', status: 'live',
        overview: 'Our core SIEM engine. The manager collects, decodes, and applies detection rules to every log/event, feeding results into the Wazuh Indexer (OpenSearch) for storage and search. Practically everything else in Hope-Armor builds on top of this.',
        keyPaths: [
          { label: 'Manager log (ossec.log)', path: '/var/ossec/logs/ossec.log' },
          { label: 'Custom rules (edit this)', path: '/var/ossec/etc/rules/local_rules.xml' },
          { label: 'Built-in rules (read-only)', path: '/var/ossec/ruleset/rules/' },
          { label: 'Custom decoders (edit this)', path: '/var/ossec/etc/decoders/local_decoder.xml' },
          { label: 'Built-in decoders (read-only)', path: '/var/ossec/ruleset/decoders/' },
          { label: 'Main config', path: '/var/ossec/etc/ossec.conf' },
        ],
        runbook: [
          {
            heading: 'Installation',
            steps: [
              { text: 'Download the official installation assistant:', code: 'curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh' },
              { text: 'Single all-in-one node (indexer + manager + dashboard together):', code: 'bash wazuh-install.sh -a' },
              { text: 'Or, for a multi-node/production deployment, install each component on its own target host instead:', code: 'bash wazuh-install.sh --wazuh-indexer <node-name>\nbash wazuh-install.sh --wazuh-server <node-name>\nbash wazuh-install.sh --wazuh-dashboard <node-name>' },
              { text: 'The installer prints the auto-generated admin password at the very end — save it immediately, it is not shown again.' },
            ],
          },
          {
            heading: 'How log normalization actually works, end to end',
            steps: [
              { text: 'A raw log line arrives (from an agent, syslog, or a forwarded source like Darktrace) with whatever format its source uses.' },
              { text: 'Decoders run first: they extract meaningful fields (srcip, user, dstport, action, etc.) out of that raw text into a common, structured set of fields — this is the "normalization" step. Two completely different log formats that both produce a srcip field can then be treated identically by rules.' },
              { text: 'Rules then match against those normalized fields (not the raw text) to decide severity, description, and MITRE ATT&CK mapping.' },
              { text: 'The result — raw log plus extracted fields plus the matched rule— is what actually gets written to the wazuh-alerts-* index that Grafana and this dashboard both read from.' },
              { text: 'Practical implication: if a new log source shows up with no useful fields on its alerts, the fix is almost always a missing/incorrect decoder, not a rule problem.' },
            ],
          },
          {
            heading: 'Writing custom decoders — normalizing fields across sources',
            steps: [
              { text: 'Add new decoders to local_decoder.xml, never edit the built-in ruleset directly. A decoder needs a prematch (or program_name) to identify which logs it applies to, then a child decoder with a regex plus an order attribute naming the fields each capture group extracts.' },
              { text: 'The real reason we write these: Darktrace, Sophos, and Defender each put the same concept (hostname, IP, username) under a completely different field name in their raw JSON — device.hostname vs sophos.dhost vs ms-graph.evidence.userAccount.displayName. Correlation rules can only compare "the same field" across sources (via same_field, below) once every source has been normalized into identical field names. That’s what these sibling decoders do — each one hangs off the source’s existing JSON decoder as a parent and re-decodes one already-parsed key into our common field names (src_hostname, srcip, srcuser):', code: '<!-- Darktrace: normalize hostname and IP -->\n<decoder name="darktrace-normalization">\n  <parent>darktrace-json</parent>\n  <regex field="device.hostname">^(\\S+)</regex>\n  <order>src_hostname</order>\n</decoder>\n\n<decoder name="darktrace-ip-normalization">\n  <parent>darktrace-json</parent>\n  <regex field="device.ip">^(\\S+)</regex>\n  <order>srcip</order>\n</decoder>\n\n<!-- Sophos: normalize hostname, IP, and user -->\n<decoder name="sophos-normalization">\n  <parent>json</parent>\n  <regex field="sophos.dhost">^(\\S+)</regex>\n  <order>src_hostname</order>\n</decoder>\n\n<decoder name="sophos-ip-normalization">\n  <parent>json</parent>\n  <regex field="sophos.source_info.ip">^(\\S+)</regex>\n  <order>srcip</order>\n</decoder>\n\n<decoder name="sophos-user-normalization">\n  <parent>json</parent>\n  <regex field="sophos.suser">^(\\S+)</regex>\n  <order>srcuser</order>\n</decoder>\n\n<!-- Defender: normalize user -->\n<decoder name="defender-user-normalization">\n  <parent>json-msgraph</parent>\n  <regex field="ms-graph.evidence.userAccount.displayName">^(\\S+)</regex>\n  <order>srcuser</order>\n</decoder>' },
              { text: 'The field="..." attribute on <regex> lets you re-decode a value that a parent JSON decoder already exposed as a key, instead of re-parsing the raw log text — that’s why these sibling decoders are so short.' },
              { text: 'Whatever field name you pick here must be spelled identically everywhere it’s used later in a same_field comparison — see the heads-up in Correlation rules below for exactly what goes wrong when it isn’t.' },
              { text: 'Test against a real sample log line before trusting it in production:', code: '/var/ossec/bin/wazuh-logtest' },
              { text: 'Restart to load it:', code: 'systemctl restart wazuh-manager' },
            ],
          },
          {
            heading: 'Configuring detection rules',
            steps: [
              { text: 'Never edit the built-in rule files directly — override or extend via local_rules.xml instead.' },
              { text: 'Custom rule IDs must start at 100000 or higher; Wazuh reserves 0–99999 for built-in rules.' },
              { text: 'After editing, test the rule/decoder logic against a sample log line before relying on it:', code: '/var/ossec/bin/wazuh-logtest' },
              { text: 'Reload the ruleset:', code: 'systemctl restart wazuh-manager' },
            ],
          },
          {
            heading: 'Correlation rules — cross-source detection',
            steps: [
              { text: 'These two directives are how a rule reaches across sources instead of just matching one log line: if_sid fires when any rule in a given ID list has already matched; if_matched_group fires when any rule tagged with a given group name has matched (used below to reach into Darktrace’s "model_breach"-tagged rules). field filters on one specific normalized field value (regex), and same_field requires that field to hold the identical value across the correlated events — this is exactly why the normalization decoders above exist.' },
              { text: 'Use case 1 — a Sophos EDR alert plus a simultaneous Darktrace ransomware-pattern MITRE technique on the same machine, within 5 minutes:', code: '<group name="correlated_alert,">\n  <rule id="300105" level="15" frequency="2" timeframe="300">\n    <if_sid>200701, 200702, 200703</if_sid> <!-- Any Sophos Alert -->\n    <if_matched_group>model_breach</if_matched_group> <!-- Darktrace alerts -->\n    <!-- Filter only for destructive actions in Darktrace -->\n    <field name="mitreTechniques.technique">Data Destruction|File Deletion</field>\n    <same_field>src_hostname</same_field>\n    <description>[Sophos-Darktrace Correlation]: Sophos alert accompanied by Darktrace Destructive MITRE Techniques on $(src_hostname)</description>\n    <mitre>\n      <id>T1485</id>\n      <id>T1070.004</id>\n    </mitre>\n    <group>darktrace,sophos</group>\n  </rule>' },
              { text: 'Use case 2 — a Defender for Office 365 phishing detection (T1566) followed by a Sophos alert from the same user within 15 minutes:', code: '  <rule id="300106" level="14" frequency="2" timeframe="900">\n    <field name="ms-graph.mitreTechniques">T1566</field> <!-- Defender Phishing -->\n    <if_sid>200701, 200702, 200703</if_sid> <!-- Sophos Alert -->\n    <same_field>srcuser</same_field>\n    <description>[Defender-Sophos Correlation]: Phishing Delivery Chain - Defender T1566 Phishing event followed by Sophos alert from user $(srcuser)</description>\n    <mitre>\n      <id>T1566</id>\n    </mitre>\n    <group>defender,sophos</group>\n  </rule>\n</group>' },
              { text: 'Heads up — a field-name mismatch will silently break this: our normalization decoders write the username into srcuser (no underscore), so rule 300106’s same_field must reference srcuser exactly. If it’s ever written as src_user (with an underscore) instead, same_field has nothing to compare against and the rule will never fire — no error, it just quietly never correlates. Worth a quick diff against whatever’s actually deployed on the manager.' },
              { text: '200701–200703 above are this deployment’s own Sophos alert-severity rule IDs (defined elsewhere in local_rules.xml, not built into Wazuh) — if those change, both correlation rules need updating to match.' },
              { text: 'Both examples use IDs in the 300000+ range to keep cross-source correlation rules visually separate from single-source custom rules (100000+) — not a Wazuh requirement, just this deployment’s own convention.' },
              { text: 'Same workflow as any other rule change: wazuh-logtest to verify, then restart to load it:', code: '/var/ossec/bin/wazuh-logtest\nsystemctl restart wazuh-manager' },
            ],
          },
          {
            heading: 'Troubleshooting: manager fails to (re)start',
            steps: [
              { text: 'Check the service status and the system journal first:', code: 'systemctl status wazuh-manager.service\njournalctl -xe -u wazuh-manager' },
              { text: 'Read the manager’s own log — this is almost always where the real error is:', code: 'tail -n 100 /var/ossec/logs/ossec.log' },
              { text: 'Common cause #1 — a config syntax error in ossec.conf (or a malformed local_rules.xml / local_decoder.xml). Fix the exact line the log points to.' },
              { text: 'Common cause #2 — a corrupted internal database socket:', code: 'sudo systemctl stop wazuh-manager\nsudo rm /var/ossec/queue/db/wdb\nsudo chown wazuh:wazuh /var/ossec/queue/db\nsudo chmod 750 /var/ossec/queue/db\nsudo systemctl start wazuh-manager' },
              { text: 'Common cause #3 — wrong file ownership under /var/ossec/. Everything there must be owned by the wazuh user, not root.' },
            ],
          },
        ],
        docsUrl: 'https://documentation.wazuh.com/current/', docsLabel: 'Official Docs',
        screenshot: 'wazuh-manager.png',
      },
      {
        name: 'Graylog', icon: 'list_alt', color: '#6b7280', status: 'planned',
        overview: 'Planned addition for centralized log normalization and correlation ahead of Wazuh ingestion. Registered as a connector but not yet configured — see the Connectors tab.',
        docsUrl: 'https://go2docs.graylog.org/', docsLabel: 'Official Docs',
      },
    ],
  },
  {
    id: 'intel', title: 'Threat Intelligence', icon: 'travel_explore',
    description: 'Enrichment sources used to score and contextualize alerts during investigation.',
    tools: [
      {
        name: 'VirusTotal', icon: 'gpp_bad', color: '#ef4444', status: 'live',
        overview: 'On-demand reputation lookups — called live during investigation, not part of any ingestion pipeline. No polling job and nothing gets stored ahead of time; a lookup only happens when an analyst asks for one.',
        keyPaths: [
          { label: 'Env vars (APIGateway/.env)', path: 'VT_API_KEY  (optional: VT_TIMEOUT, default 15s)' },
          { label: 'Implementation', path: 'integrations/virustotal.py → lookup_ip / lookup_domain / lookup_url / lookup_hash' },
        ],
        docsUrl: 'https://docs.virustotal.com/', docsLabel: 'Official Docs',
        screenshot: 'virustotal-lookup.png',
      },
      {
        name: 'MISP', icon: 'account_tree', color: '#c026d3', status: 'live',
        overview: 'Runs entirely on the Wazuh manager side, not in this API Gateway — there is no MISP env var or client code in Armor at all.',
        keyPaths: [
          { label: 'Env vars (APIGateway/.env)', path: 'None — configure directly on the Wazuh manager, not here' },
          { label: 'Integration script', path: '/var/ossec/integrations/custom-misp and custom-misp.py on the Wazuh manager' },
        ],
        runbook: [
          {
            heading: 'How this is actually wired up',
            steps: [
              { text: 'Wazuh calls custom-misp for every matching alert, which extracts IOCs from that alert and queries your MISP instance, then writes the results back onto the alert under a top-level misp key — that enriched alert is what eventually lands in OpenSearch.' },
              { text: 'To change MISP behavior (which rule groups trigger a lookup, the MISP URL/API key it queries), edit the integration config on the Wazuh manager itself (typically wired up under /etc/systemd/system/wazuh-manager.service.d/misp.conf) — this app has nothing to configure for it.' },
            ],
          },
        ],
        docsUrl: 'https://www.misp-project.org/documentation/', docsLabel: 'Official Docs',
      },
    ],
  },
  {
    id: 'vuln', title: 'Vulnerability Management', icon: 'radar',
    description: 'Scanning and compliance assessment across the network.',
    tools: [
      {
        name: 'Nessus / Tenable', icon: 'radar', color: '#a78bfa', status: 'live',
        overview: 'Scheduled and on-demand vulnerability scans. Results, executive summaries, and technical reports are available on the Vulnerability Detection tab.',
        keyPaths: [
          { label: 'Env vars (APIGateway/.env)', path: 'NESSUS_URL (defaults to https://localhost:8834), NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY' },
          { label: 'Implementation', path: 'client.py → class NessusClient' },
        ],
        docsUrl: 'https://docs.tenable.com/nessus/', docsLabel: 'Official Docs',
        screenshot: 'nessus-scan-results.png',
      },
    ],
  },
  {
    id: 'identity', title: 'Identity', icon: 'manage_accounts',
    description: 'Sign-in risk and identity protection signals.',
    tools: [
      {
        name: 'Microsoft Entra ID', icon: 'manage_accounts', color: '#0ea5e9', status: 'live',
        overview: 'Azure AD identity protection — risky sign-ins and risky users surface on the Identity Management tab. There is no separate Entra credential: this reuses the exact same Graph API app registration (DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET) as Microsoft Defender above, just against different Graph scopes/endpoints.',
        docsUrl: 'https://learn.microsoft.com/en-us/entra/id-protection/', docsLabel: 'Official Docs',
        screenshot: 'entra-id-protection.png',
      },
    ],
  },
  {
    id: 'middleware', title: 'Middleware', icon: 'api',
    description: 'The internal layer tying every integration above together.',
    tools: [
      {
        name: 'Armor API Gateway (FastAPI)', icon: 'api', color: '#1A3A5C', status: 'live',
        overview: 'Our own Python middleware — every request from this UI to any integration above passes through this API Gateway, which also handles auth, access control, and the Grafana dashboard permission overlay.',
        docsUrl: 'https://fastapi.tiangolo.com/', docsLabel: 'FastAPI Framework Docs',
      },
    ],
  },
  {
    id: 'viz', title: 'Visualizations', icon: 'bar_chart',
    description: 'Where the data actually gets looked at.',
    tools: [
      {
        name: 'Grafana', icon: 'bar_chart', color: '#f97316', status: 'live',
        overview: 'Dashboarding layer on top of our OpenSearch data. Build and share custom dashboards from the Visualizations tab; provisioned datasources point at the same indices Wazuh writes to.',
        keyPaths: [
          { label: 'Env vars (APIGateway/.env)', path: 'GRAFANA_URL, GRAFANA_API_KEY, GRAFANA_PUBLIC_URL' },
        ],
        runbook: [
          {
            heading: 'The three datasources this app provisions',
            steps: [
              { text: 'The "Provision Data Sources" button on the Visualizations tab calls POST /grafana/datasources/provision on the API Gateway, which creates or updates exactly these three OpenSearch datasources in Grafana with tlsSkipVerify=true (our indexer uses a self-signed cert):', code: 'wazuh-alerts       → index "wazuh-alerts-4.x-*"\nsiem-defender      → index "siem-defender-*"\ndarktrace-agemail  → index "darktrace-index_deflector"' },
              { text: 'All three point at the same WAZUH_INDEXER_URL — Grafana never talks to Sophos, Defender, or Darktrace directly, only to the one OpenSearch cluster everything already lands in.' },
              { text: 'Re-running the provision button is safe — existing datasources with the same name are updated in place (PATCH), not duplicated.' },
            ],
          },
        ],
        docsUrl: 'https://grafana.com/docs/grafana/latest/', docsLabel: 'Official Docs',
        screenshot: 'grafana-dashboard.png',
      },
      {
        name: 'Armor Custom UI', icon: 'dashboard_customize', color: '#F46A1F', status: 'live',
        overview: 'This application — the single pane of glass tying every integration above together. No external docs; for internal conventions, see the Connectors tab.',
      },
    ],
  },
  {
    id: 'incidents', title: 'Incident Management & Notifications', icon: 'confirmation_number',
    description: 'Turning an alert into a tracked, escalated response.',
    tools: [
      {
        name: 'Jira', icon: 'confirmation_number', color: '#818cf8', status: 'live',
        overview: 'Security incident ticketing. Alerts can be escalated directly to a Jira ticket from the Alerts Investigation tab.',
        keyPaths: [
          { label: 'Env vars (APIGateway/.env)', path: 'JIRA_BASE_URL, JIRA_PROJECT_KEY, JIRA_EMAIL, JIRA_API_TOKEN' },
          { label: 'Implementation', path: 'client.py → class JiraClient' },
        ],
        docsUrl: 'https://support.atlassian.com/jira-software-cloud/', docsLabel: 'Official Docs',
        screenshot: 'jira-ticket.png',
      },
      {
        name: 'Microsoft Teams', icon: 'forum', color: '#6264A7', status: 'live',
        overview: 'Critical/high-severity alerts are pushed to a Teams channel via webhook by a background poller.',
        keyPaths: [
          { label: 'Configured via', path: 'Settings tab (stored config) — falls back to env var TEAMS_WEBHOOK_URL if not set there' },
          { label: 'Default poll interval', path: '300 seconds (poll_interval_secs, editable on the Settings tab)' },
          { label: 'Implementation', path: 'routers/notifications.py' },
        ],
        docsUrl: 'https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/what-are-webhooks-and-connectors',
        docsLabel: 'Official Docs',
      },
    ],
  },
];

@Component({
  selector: 'app-docs',
  standalone: true,
  imports: [CommonModule, MatIconModule, MatTooltipModule],
  templateUrl: './docs.component.html',
  styleUrl: './docs.component.scss',
})
export class DocsComponent {
  readonly sections = SECTIONS;

  private expanded = new Set<string>();

  isExpanded(name: string): boolean {
    return this.expanded.has(name);
  }

  toggle(name: string): void {
    if (this.expanded.has(name)) this.expanded.delete(name);
    else this.expanded.add(name);
  }

  onImgError(event: Event): void {
    const img = event.target as HTMLImageElement;
    img.closest('.shot')?.classList.add('shot--missing');
  }

  copyCode(code: string, event: Event): void {
    event.stopPropagation();
    navigator.clipboard?.writeText(code);
    const btn = event.currentTarget as HTMLElement;
    const original = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = original; }, 1200);
  }
}
