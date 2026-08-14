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
        overview: 'Network anomaly detection — a physical appliance (or virtual vSensor) passively analyzes mirrored network traffic and flags anomalous behavior with unsupervised machine learning. No agent is needed on most devices; alerts land in our pipeline as Network Security events.',
        runbook: [
          {
            heading: 'How traffic actually reaches it',
            steps: [
              { text: 'Physical appliance: traffic is fed to it via a SPAN/mirror port configured on your core switch — Darktrace itself never touches the switch config.' },
              { text: 'Virtual environments: a Darktrace vSensor ingests mirrored VPC / virtual-switch traffic instead, then forwards extracted metadata to the master appliance.' },
              { text: 'Devices that can\u2019t be mirrored directly (printers, some IoT, videoconferencing units) can instead run a lightweight osSensor agent that forwards to a vSensor.' },
            ],
          },
          {
            heading: 'Where to investigate an alert',
            steps: [
              { text: 'All investigation happens in the Threat Visualizer (the 3D network view). Flagged anomalies show up there as "model breaches" — that\u2019s where you drill into the actual traffic/behavior that triggered one.' },
            ],
          },
          {
            heading: 'Troubleshooting: a network segment shows no traffic',
            steps: [
              { text: 'Confirm the relevant vSensor is actually listed and reporting under System Config \u2192 Probes in the Threat Visualizer. If it\u2019s missing or shows stale, the mirror/SPAN port config on the switch side is the usual culprit, not Darktrace itself.' },
              { text: 'For virtual/cloud deployments, double-check the traffic-mirroring session (VPC mirroring / vSwitch port mirroring) is actually forwarding to the vSensor\u2019s listening interface.' },
            ],
          },
        ],
        docsUrl: 'https://customerportal.darktrace.com/', docsLabel: 'Darktrace Customer Portal (login required)',
        screenshot: 'darktrace-threat-visualizer.png',
      },
      {
        name: 'Sophos Central', icon: 'security', color: '#3fb950', status: 'live',
        overview: 'Endpoint protection console — cloud-hosted, so there\u2019s no server to install. What actually gets installed is the Sophos agent on each protected endpoint. Alerts and device health feed the Endpoint Security tab, and analysts can isolate a device directly from Hope-Armor.',
        keyPaths: [
          { label: 'Windows agent logs', path: 'C:\\ProgramData\\Sophos\\Endpoint Defense\\Logs\\' },
          { label: 'Linux agent logs',   path: '/opt/sophos-spl/plugins/av/log/av.log' },
          { label: 'Linux install dir',  path: '/opt/sophos-spl' },
        ],
        runbook: [
          {
            heading: 'Installing the endpoint agent',
            steps: [
              { text: 'Windows / macOS: Sophos Central \u2192 My Devices \u2192 Protect Devices, download the customer-specific installer (it comes pre-bundled with your registration token), then run it on the endpoint.' },
              { text: 'Linux: Sophos Central \u2192 My Environment \u2192 Installers \u2192 download the Linux Server Installer, then on the target host:', code: 'wget <installer-download-link>\nchmod +x SophosSetup.sh\nsudo ./SophosSetup.sh' },
            ],
          },
          {
            heading: 'Troubleshooting: agent not reporting, or can\u2019t uninstall',
            steps: [
              { text: 'Check the endpoint is actually shown online in Sophos Central \u2192 Devices \u2014 a device that hasn\u2019t checked in recently usually means a network/proxy problem on that host, not a Sophos problem.' },
              { text: 'Check the agent log at the path for that OS above for the actual error.' },
              { text: 'If uninstall/reconfigure is blocked by Tamper Protection, turn Tamper Protection off first from Sophos Central \u2192 the device\u2019s page (an admin can also generate a one-time bypass). Don\u2019t try to force-kill the agent process \u2014 it\u2019s designed to resist exactly that.' },
            ],
          },
        ],
        docsUrl: 'https://docs.sophos.com/central/Customer/help/en-us/index.html', docsLabel: 'Official Docs',
        screenshot: 'sophos-central-overview.png',
      },
      {
        name: 'Microsoft Defender', icon: 'verified_user', color: '#0078d4', status: 'live',
        overview: 'Defender for Endpoint (device alerts) and Defender for Office 365 (email threats), pulled in via Microsoft Graph API. Powers the Email Security tab and contributes to Endpoint Security.',
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
          { label: 'Main config', path: '/var/ossec/etc/ossec.conf' },
        ],
        runbook: [
          {
            heading: 'Installation',
            steps: [
              { text: 'Download the official installation assistant:', code: 'curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh' },
              { text: 'Single all-in-one node (indexer + manager + dashboard together):', code: 'bash wazuh-install.sh -a' },
              { text: 'Or, for a multi-node/production deployment, install each component on its own target host instead:', code: 'bash wazuh-install.sh --wazuh-indexer <node-name>\nbash wazuh-install.sh --wazuh-server <node-name>\nbash wazuh-install.sh --wazuh-dashboard <node-name>' },
              { text: 'The installer prints the auto-generated admin password at the very end \u2014 save it immediately, it is not shown again.' },
            ],
          },
          {
            heading: 'Configuring detection rules',
            steps: [
              { text: 'Never edit the built-in rule files directly \u2014 override or extend via local_rules.xml instead.' },
              { text: 'Custom rule IDs must start at 100000 or higher; Wazuh reserves 0\u201399999 for built-in rules.' },
              { text: 'After editing, test the rule/decoder logic against a sample log line before relying on it:', code: '/var/ossec/bin/wazuh-logtest' },
              { text: 'Reload the ruleset:', code: 'systemctl restart wazuh-manager' },
            ],
          },
          {
            heading: 'Troubleshooting: manager fails to (re)start',
            steps: [
              { text: 'Check the service status and the system journal first:', code: 'systemctl status wazuh-manager.service\njournalctl -xe -u wazuh-manager' },
              { text: 'Read the manager\u2019s own log \u2014 this is almost always where the real error is:', code: 'tail -n 100 /var/ossec/logs/ossec.log' },
              { text: 'Common cause #1 \u2014 a config syntax error in ossec.conf. Fix the exact line the log points to.' },
              { text: 'Common cause #2 \u2014 a corrupted internal database socket:', code: 'sudo systemctl stop wazuh-manager\nsudo rm /var/ossec/queue/db/wdb\nsudo chown wazuh:wazuh /var/ossec/queue/db\nsudo chmod 750 /var/ossec/queue/db\nsudo systemctl start wazuh-manager' },
              { text: 'Common cause #3 \u2014 wrong file ownership under /var/ossec/. Everything there must be owned by the wazuh user, not root.' },
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
        overview: 'On-demand reputation lookups for IPs, domains, URLs, and file hashes — used during alert investigation and email threat triage.',
        docsUrl: 'https://docs.virustotal.com/', docsLabel: 'Official Docs',
        screenshot: 'virustotal-lookup.png',
      },
      {
        name: 'MISP', icon: 'account_tree', color: '#c026d3', status: 'live',
        overview: 'Runs as a Wazuh-side enrichment integration (custom-misp) — every matching Wazuh alert is automatically checked against our MISP instance for known indicators of compromise before it reaches the dashboard.',
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
        overview: 'Azure AD identity protection — risky sign-ins and risky users surface on the Identity Management tab.',
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
          { label: 'Config file', path: '/etc/grafana/grafana.ini' },
          { label: 'Log (Linux package install)', path: '/var/log/grafana/grafana.log' },
          { label: 'Log (manual/Windows install)', path: '<install_dir>/data/log/grafana.log' },
        ],
        runbook: [
          {
            heading: 'Installation (Linux, Debian/Ubuntu)',
            steps: [
              { text: 'Add the official Grafana APT repository and install:', code: 'sudo apt-get install -y software-properties-common\nsudo add-apt-repository "deb https://apt.grafana.com stable main"\nwget -q -O - https://apt.grafana.com/gpg.key | sudo apt-key add -\nsudo apt-get update\nsudo apt-get install grafana' },
              { text: 'Enable and start it:', code: 'sudo systemctl enable grafana-server\nsudo systemctl start grafana-server' },
              { text: 'Windows: download the installer/zip from the Grafana downloads page and run it directly — no package manager step needed.' },
            ],
          },
          {
            heading: 'Configuring datasources for Hope-Armor',
            steps: [
              { text: 'Don\u2019t hand-configure the OpenSearch datasources in Grafana\u2019s own UI. Use the "Provision Data Sources" button on the Visualizations tab instead — it calls the Armor API Gateway, which provisions all three (wazuh-alerts, siem-defender, darktrace-agemail) with the correct TLS-skip settings automatically.' },
            ],
          },
          {
            heading: 'Troubleshooting',
            steps: [
              { text: 'Check the service:', code: 'sudo systemctl status grafana-server' },
              { text: 'Check the log at the path above for the actual error.' },
              { text: 'For a deeper look, set level = debug under the [log] section in grafana.ini, restart, then revert it afterward — debug logging is very verbose.' },
              { text: 'If a dashboard panel loads but shows "no data", check the datasource itself first: Connections \u2192 Data sources \u2192 the OpenSearch source \u2192 Save & Test.' },
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
        docsUrl: 'https://support.atlassian.com/jira-software-cloud/', docsLabel: 'Official Docs',
        screenshot: 'jira-ticket.png',
      },
      {
        name: 'Microsoft Teams', icon: 'forum', color: '#6264A7', status: 'live',
        overview: 'Critical/high-severity alerts are pushed to a Teams channel via webhook. Configure the webhook URL and severity threshold on the Settings tab.',
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
