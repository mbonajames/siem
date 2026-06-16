import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import { MsalService } from '@azure/msal-angular';

export type EntityType = 'user' | 'host' | 'ip' | 'domain';
export type SeverityLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export interface AlertFilter {
  limit?:    number;
  offset?:   number;
  source?:   string;
  severity?: SeverityLevel | SeverityLevel[];
  hours?:    number;
  q?:        string;
  ioc_only?: boolean;
}

export interface MispHit {
  date:            string;
  threat_level:    string;
  event_id:        string;
  org:             string;
  event_name:      string;
  ioc_value:       string;
  ioc_type:        string;
  event_uuid:      string;
  tags:            string[];
  published:       boolean;
  attribute_count?: number;
}

export interface MispData {
  enriched:       boolean;
  enriched_at:    string;
  hit_count:      number;
  severity_boost: number;
  hits:           MispHit[];
  iocs_checked: {
    hashes:  string[];
    domains: string[];
    ips:     string[];
    cves:    string[];
  };
}

export interface MitreTechnique {
  id?:        string;
  technique?: string;
  tactics?:   string[];
}

export interface UnifiedEvent {
  event_id: string;
  time: string;
  category: string;
  event_class: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  summary: string;
  user?: string;
  users?: string[];
  host?: string;
  src_ip?: string;
  remote_ip?: string;
  remote_port?: string;
  domain?: string;
  sender_domain?: string;
  source: string;
  mitre?: MitreTechnique[];
  misp?: MispData;
  raw: Record<string, any>;
}

export interface AlertsPage {
  total:  number;
  events: UnifiedEvent[];
}

export interface AlertStats {
  total:                number;
  by_severity:          Record<string, number>;
  by_source:            Record<string, number>;
  by_source_severity?:  Record<string, Record<string, number>>;
  ioc_count:            number;
}

export interface InvestigateRequest {
  entity_type: EntityType;
  value: string;
  start?: string;
  end?: string;
  limit?: number;
  offset?: number;
  severities?: SeverityLevel[];
}

export interface InvestigateResponse {
  entity: { type: EntityType; value: string };
  summary: {
    total: number;
    by_source: Record<string, number>;
    by_severity: Record<string, number>;
    timeline: { key_as_string: string; doc_count: number }[];
  };
  related: {
    users: string[];
    hosts: string[];
    ips: string[];
    domains: string[];
  };
  events: UnifiedEvent[];
}

export interface JiraAssignee {
  account_id:   string;
  display_name: string;
  avatar_url:   string;
}

export interface JiraTicket {
  key:             string;
  url:             string;
  summary:         string;
  status:          string;
  status_category: string;
  priority:        string;
  created:         string;
  assignee:        string;
  severity:        string;
  labels:          string[];
}

export interface JiraTicketsPage {
  total:   number;
  tickets: JiraTicket[];
}

export interface JiraTicketRequest {
  event_id: string;
  time:     string;
  severity: string;
  source:   string;
  category: string;
  summary:  string;
  user?:    string;
  host?:    string;
  src_ip?:  string;
  raw?:     Record<string, any>;
  mitre?:   { id?: string; technique?: string; tactics?: string[] }[];
}

export interface JiraTicketResult {
  key:     string;
  url:     string;
  created: boolean;
}

export interface SophosEndpointHealth {
  total:      number;
  good:       number;
  suspicious: number;
  bad:        number;
  unknown:    number;
}

// ── VirusTotal ────────────────────────────────────────────────────────────────

export interface VtStats {
  malicious:  number;
  suspicious: number;
  harmless:   number;
  undetected: number;
  timeout?:   number;
}

export interface VtDetection {
  engine:   string;
  category: string;
  result:   string;
}

export interface VtResult {
  ioc_type:  'ip' | 'domain' | 'hash';
  ioc_value: string;
  verdict:   'malicious' | 'suspicious' | 'clean' | 'unknown';
  stats:     VtStats;
  reputation?: number;
  // IP-specific
  country?:   string;
  asn?:       number;
  as_owner?:  string;
  network?:   string;
  // Domain-specific
  registrar?:       string;
  categories?:      string[];
  creation_date?:   number;
  last_update_date?: number;
  // Hash-specific
  meaningful_name?:  string;
  type_description?: string;
  size?:             number;
  sha256?:           string;
  sha1?:             string;
  md5?:              string;
  // Common
  tags?:              string[];
  whois?:             string;
  last_analysis_date?: number;
  top_detections:     VtDetection[];
  permalink:          string;
}

// ── Custom dashboards ─────────────────────────────────────────────────────────

export type WidgetType =
  | 'severity-tiles' | 'recent-alerts' | 'source-pie' | 'category-pie'
  | 'top-hosts'      | 'top-users'     | 'ioc-summary'
  | 'severity-bars'  | 'source-bars'   | 'stat-card'
  | 'divider'        | 'text';

export type WidgetSize = 'quarter' | 'half' | 'three-quarter' | 'full';

export interface WidgetConfig {
  hours?:    number;
  limit?:    number;
  severity?: string;
  source?:   string;
  metric?:   string;  // stat-card: total|critical|high|medium|low|ioc
  text?:     string;  // text widget content
  height?:   number;  // user-dragged height in px; undefined = use type default
}

export interface DashboardWidget {
  id:     string;
  type:   WidgetType;
  title:  string;
  size:   WidgetSize;
  config: WidgetConfig;
}

export interface CustomDashboard {
  id:          string;
  name:        string;
  description: string;
  owner:       string;
  shared:      boolean;
  created_at:  string;
  updated_at:  string;
  widgets:     DashboardWidget[];
}

export const WIDGET_CATALOG: { type: WidgetType; label: string; description: string; icon: string; defaultSize: WidgetSize }[] = [
  { type: 'severity-tiles', label: 'Severity Overview',   description: 'Critical / High / Medium / Low / IOC counts',      icon: 'bar_chart',        defaultSize: 'full'          },
  { type: 'stat-card',      label: 'Stat Card',           description: 'Single configurable metric (e.g. Critical today)', icon: 'speed',            defaultSize: 'quarter'       },
  { type: 'recent-alerts',  label: 'Recent Alerts Feed',  description: 'Live scrollable list of latest alerts',            icon: 'feed',             defaultSize: 'full'          },
  { type: 'severity-bars',  label: 'Severity Bars',       description: 'Horizontal bar chart of alerts by severity',       icon: 'stacked_bar_chart',defaultSize: 'half'          },
  { type: 'source-bars',    label: 'Source Bars',         description: 'Horizontal bar chart of alerts by source',         icon: 'devices_other',    defaultSize: 'half'          },
  { type: 'source-pie',     label: 'Source Breakdown',    description: 'Donut chart of alerts by source',                  icon: 'donut_large',      defaultSize: 'half'          },
  { type: 'category-pie',   label: 'Category Breakdown',  description: 'Donut chart of alerts by category',                icon: 'category',         defaultSize: 'half'          },
  { type: 'top-hosts',      label: 'Top Hosts',           description: 'Most-alerted endpoint hostnames',                  icon: 'computer',         defaultSize: 'half'          },
  { type: 'top-users',      label: 'Top Users',           description: 'Most-alerted user accounts',                       icon: 'person',           defaultSize: 'half'          },
  { type: 'ioc-summary',    label: 'IOC / MISP Summary',  description: 'Count of IOC-matched alerts + recent IOC hits',    icon: 'gpp_bad',          defaultSize: 'half'          },
  { type: 'divider',        label: 'Section Divider',     description: 'Visual separator — add a label to name the section', icon: 'horizontal_rule',  defaultSize: 'full'          },
  { type: 'text',           label: 'Text Block',          description: 'Free-form notes, context, or commentary',            icon: 'text_fields',      defaultSize: 'full'          },
];

@Injectable({ providedIn: 'root' })
export class GatewayService {
  constructor(private api: ApiService, private msal: MsalService) {}

  private ownerHeaders(): Record<string, string> {
    const username = this.msal.instance.getActiveAccount()?.username;
    return username ? { 'X-SIEM-Owner': username } : {};
  }

  getAlerts(filter: AlertFilter = {}): Observable<AlertsPage> {
    const params: Record<string, any> = {};
    if (filter.limit    != null) params['limit']    = filter.limit;
    if (filter.offset   != null) params['offset']   = filter.offset;
    if (filter.source)           params['source']   = filter.source;
    if (filter.severity)         params['severity'] = filter.severity;
    if (filter.hours    != null) params['hours']    = filter.hours;
    if (filter.q)                params['q']        = filter.q;
    if (filter.ioc_only)         params['ioc_only'] = true;
    return this.api.get<AlertsPage>('/alerts', params);
  }

  investigate(req: InvestigateRequest): Observable<InvestigateResponse> {
    return this.api.post<InvestigateResponse>('/investigate', req);
  }

  getStats(hours?: number): Observable<AlertStats> {
    const params: Record<string, any> = {};
    if (hours != null) params['hours'] = hours;
    return this.api.get<AlertStats>('/stats', params);
  }

  getSophosEndpointHealth(): Observable<SophosEndpointHealth> {
    return this.api.get<SophosEndpointHealth>('/endpoints/health/summary');
  }

  vtLookupIp(ip: string): Observable<VtResult> {
    return this.api.get<VtResult>(`/vt/ip/${encodeURIComponent(ip)}`);
  }

  vtLookupDomain(domain: string): Observable<VtResult> {
    return this.api.get<VtResult>(`/vt/domain/${encodeURIComponent(domain)}`);
  }

  vtLookupHash(hash: string): Observable<VtResult> {
    return this.api.get<VtResult>(`/vt/hash/${encodeURIComponent(hash)}`);
  }

  health(): Observable<any> {
    return this.api.get('/indexer/health');
  }

  createJiraTicket(req: JiraTicketRequest): Observable<JiraTicketResult> {
    return this.api.post<JiraTicketResult>('/jira/tickets', req);
  }

  batchCheckJiraTickets(eventIds: string[]): Observable<{ tickets: Record<string, { key: string; url: string }> }> {
    return this.api.post('/jira/tickets/batch-check', { event_ids: eventIds });
  }

  getJiraAssignees(): Observable<{ assignees: JiraAssignee[] }> {
    return this.api.get<{ assignees: JiraAssignee[] }>('/jira/assignees');
  }

  assignJiraTicket(key: string, accountId: string): Observable<{ key: string; assigned: boolean }> {
    return this.api.put<{ key: string; assigned: boolean }>(`/jira/tickets/${key}/assignee`, { account_id: accountId });
  }

  // ── Custom dashboards ──────────────────────────────────────────────────────
  listDashboards(): Observable<{ dashboards: CustomDashboard[] }> {
    return this.api.get('/custom-dashboards', undefined, this.ownerHeaders());
  }
  createDashboard(name: string, description = ''): Observable<CustomDashboard> {
    return this.api.post('/custom-dashboards', { name, description }, undefined, this.ownerHeaders());
  }
  getDashboard(id: string): Observable<CustomDashboard> {
    return this.api.get(`/custom-dashboards/${id}`, undefined, this.ownerHeaders());
  }
  saveDashboard(id: string, updates: Partial<Pick<CustomDashboard, 'name'|'description'|'widgets'>>): Observable<CustomDashboard> {
    return this.api.put(`/custom-dashboards/${id}`, updates, this.ownerHeaders());
  }
  deleteDashboard(id: string): Observable<void> {
    return this.api.delete(`/custom-dashboards/${id}`, this.ownerHeaders());
  }
  shareDashboard(id: string, shared: boolean): Observable<CustomDashboard> {
    return this.api.patch(`/custom-dashboards/${id}/share`, { shared }, this.ownerHeaders());
  }

  getJiraTickets(params: { status?: string; severity?: string; max_results?: number } = {}): Observable<JiraTicketsPage> {
    const p: Record<string, any> = {};
    if (params.status)      p['status']      = params.status;
    if (params.severity)    p['severity']    = params.severity;
    if (params.max_results) p['max_results'] = params.max_results;
    return this.api.get<JiraTicketsPage>('/jira/tickets', p);
  }
}
