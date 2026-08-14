import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';

interface DocTool {
  name:        string;
  icon:        string;
  color:       string;
  status:      'live' | 'planned';
  context:     string;
  docsUrl?:    string;
  docsLabel?:  string;
  screenshot?: string;
}

interface DocSection {
  id:          string;
  title:       string;
  icon:        string;
  description: string;
  tools:       DocTool[];
}

const SECTIONS: DocSection[] = [
  {
    id: 'sources', title: 'Data Sources', icon: 'sensors',
    description: 'Where raw security events originate before they reach the SIEM pipeline.',
    tools: [
      {
        name: 'Darktrace', icon: 'bubble_chart', color: '#60a5fa', status: 'live',
        context: 'Network traffic analytics and AI-driven anomaly detection. Darktrace alerts land in our Wazuh/OpenSearch pipeline as network security events, surfaced on the Network Security tab.',
        docsUrl: 'https://customerportal.darktrace.com/', docsLabel: 'Darktrace Customer Portal (login required)',
        screenshot: 'darktrace-threat-visualizer.png',
      },
      {
        name: 'Sophos Central', icon: 'security', color: '#3fb950', status: 'live',
        context: 'Endpoint protection — antivirus, EDR, and device isolation. Alerts and device health feed the Endpoint Security tab, and analysts can trigger device isolation directly from Hope-Armor.',
        docsUrl: 'https://docs.sophos.com/central/Customer/help/en-us/index.html', docsLabel: 'Official Docs',
        screenshot: 'sophos-central-overview.png',
      },
      {
        name: 'Microsoft Defender', icon: 'verified_user', color: '#0078d4', status: 'live',
        context: 'Defender for Endpoint (device alerts) and Defender for Office 365 (email threats), pulled in via Microsoft Graph API. Powers the Email Security tab and contributes to Endpoint Security.',
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
        name: 'Wazuh Indexer (OpenSearch)', icon: 'storage', color: '#4e9af1', status: 'live',
        context: 'Stores and indexes every normalized security event. Every alert, log, and correlation query in Hope-Armor ultimately reads from this OpenSearch cluster.',
        docsUrl: 'https://documentation.wazuh.com/current/', docsLabel: 'Official Docs',
        screenshot: 'wazuh-indexer.png',
      },
      {
        name: 'Wazuh Manager', icon: 'shield', color: '#f59e0b', status: 'live',
        context: 'Agent management, correlation rules, decoders, and active response actions (e.g. isolating a host) run here. Also hosts the MISP enrichment integration below.',
        docsUrl: 'https://documentation.wazuh.com/current/user-manual/index.html', docsLabel: 'Official Docs',
        screenshot: 'wazuh-manager.png',
      },
      {
        name: 'Graylog', icon: 'list_alt', color: '#6b7280', status: 'planned',
        context: 'Planned addition for centralized log normalization and correlation ahead of Wazuh ingestion. Registered as a connector but not yet configured — see the Connectors tab.',
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
        context: 'On-demand reputation lookups for IPs, domains, URLs, and file hashes — used during alert investigation and email threat triage.',
        docsUrl: 'https://docs.virustotal.com/', docsLabel: 'Official Docs',
        screenshot: 'virustotal-lookup.png',
      },
      {
        name: 'MISP', icon: 'account_tree', color: '#c026d3', status: 'live',
        context: 'Runs as a Wazuh-side enrichment integration (custom-misp) — every matching Wazuh alert is automatically checked against our MISP instance for known indicators of compromise before it reaches the dashboard.',
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
        context: 'Scheduled and on-demand vulnerability scans. Results, executive summaries, and technical reports are available on the Vulnerability Detection tab.',
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
        context: 'Azure AD identity protection — risky sign-ins and risky users surface on the Identity Management tab.',
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
        context: 'Our own Python middleware — every request from this UI to any integration above passes through this API Gateway, which also handles auth, access control, and the Grafana dashboard permission overlay.',
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
        context: 'Dashboarding layer on top of our OpenSearch data. Build and share custom dashboards from the Visualizations tab; provisioned datasources point at the same indices Wazuh writes to.',
        docsUrl: 'https://grafana.com/docs/grafana/latest/', docsLabel: 'Official Docs',
        screenshot: 'grafana-dashboard.png',
      },
      {
        name: 'Armor Custom UI', icon: 'dashboard_customize', color: '#F46A1F', status: 'live',
        context: 'This application — the single pane of glass tying every integration above together. No external docs; for internal conventions, see the Connectors tab.',
      },
    ],
  },
  {
    id: 'incidents', title: 'Incident Management & Notifications', icon: 'confirmation_number',
    description: 'Turning an alert into a tracked, escalated response.',
    tools: [
      {
        name: 'Jira', icon: 'confirmation_number', color: '#818cf8', status: 'live',
        context: 'Security incident ticketing. Alerts can be escalated directly to a Jira ticket from the Alerts Investigation tab.',
        docsUrl: 'https://support.atlassian.com/jira-software-cloud/', docsLabel: 'Official Docs',
        screenshot: 'jira-ticket.png',
      },
      {
        name: 'Microsoft Teams', icon: 'forum', color: '#6264A7', status: 'live',
        context: 'Critical/high-severity alerts are pushed to a Teams channel via webhook. Configure the webhook URL and severity threshold on the Settings tab.',
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

  onImgError(event: Event): void {
    const img = event.target as HTMLImageElement;
    img.closest('.shot')?.classList.add('shot--missing');
  }
}
