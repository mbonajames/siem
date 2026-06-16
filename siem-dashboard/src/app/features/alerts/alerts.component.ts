import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatPaginatorModule, PageEvent } from '@angular/material/paginator';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import {
  GatewayService, UnifiedEvent, InvestigateRequest,
  InvestigateResponse, EntityType, SeverityLevel,
  JiraTicketRequest, JiraTicketResult, MispHit,
  VtResult,
} from '../../core/services/gateway.service';

type SeverityFilter = SeverityLevel | 'Critical,High' | '';

@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatProgressBarModule, MatButtonModule,
    MatIconModule, MatTooltipModule, MatPaginatorModule, MatSnackBarModule,
  ],
  templateUrl: './alerts.component.html',
  styleUrl: './alerts.component.scss'
})
export class AlertsComponent implements OnInit {
  alerts: UnifiedEvent[] = [];
  total   = 0;
  loading = false;
  expandedEvent: UnifiedEvent | null = null;

  // ── Pagination ────────────────────────────────────────────────────────────
  pageSize  = 50;
  pageIndex = 0;
  pageSizeOptions = [25, 50, 100];

  // ── Server-side filters ───────────────────────────────────────────────────
  selectedHours:    number         = 24;
  selectedSeverity: SeverityFilter = '';
  selectedSource:   string         = '';
  searchQuery = '';
  iocOnly     = false;
  private searchTimer: any;

  timeRanges = [
    { value: 1,   label: '1h'  },
    { value: 24,  label: '24h' },
    { value: 168, label: '7d'  },
    { value: 720, label: '30d' },
  ];

  severityOptions: { value: SeverityFilter; label: string }[] = [
    { value: '',             label: 'All Severities'  },
    { value: 'Critical,High', label: 'Critical & High' },
    { value: 'Critical',     label: 'Critical'        },
    { value: 'High',         label: 'High'            },
    { value: 'Medium',       label: 'Medium'          },
    { value: 'Low',          label: 'Low'             },
  ];

  sourceOptions = [
    { value: '',               label: 'All Sources'           },
    { value: 'wazuh',          label: 'Wazuh'                 },
    { value: 'sophos-central', label: 'Sophos'                },
    { value: 'ms-defender',    label: 'MS Defender (Direct)'  },
    { value: 'ms-graph',       label: 'MS Defender (Legacy)'  },
    { value: 'darktrace',      label: 'Darktrace'             },
  ];

  // ── JIRA ──────────────────────────────────────────────────────────────────
  jiraTickets:   Map<string, { key: string; url: string }> = new Map();
  creatingTicket: Set<string> = new Set();

  // ── Investigate panel ─────────────────────────────────────────────────────
  investigating      = false;
  loadingMore        = false;
  investigateError   = '';
  investigateResult: InvestigateResponse | null = null;
  investigateTarget: { type: EntityType; value: string } | null = null;
  invSeverity: SeverityLevel | '' = '';
  invExpandedEvents  = new Set<string>();

  invSeverityOptions: { value: SeverityLevel | ''; label: string }[] = [
    { value: '',         label: 'All'      },
    { value: 'Critical', label: 'Critical' },
    { value: 'High',     label: 'High'     },
    { value: 'Medium',   label: 'Medium'   },
    { value: 'Low',      label: 'Low'      },
  ];

  // ── VirusTotal panel ──────────────────────────────────────────────────────
  vtLoading  = false;
  vtError    = '';
  vtResult:  VtResult | null = null;
  vtTarget:  { type: string; value: string } | null = null;

  private readonly _PRIV = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/;

  constructor(
    private gateway:  GatewayService,
    private snackBar: MatSnackBar,
    private route:    ActivatedRoute,
  ) {}

  ngOnInit(): void {
    const qp = this.route.snapshot.queryParamMap;
    const sev = qp.get('severity');
    if (sev) this.selectedSeverity = sev as SeverityFilter;
    const src = qp.get('source');
    if (src) this.selectedSource = src;
    const hours = qp.get('hours');
    if (hours) this.selectedHours = +hours;
    if (qp.get('ioc_only') === 'true') this.iocOnly = true;
    this.loadAlerts();
  }

  loadAlerts(): void {
    this.loading = true;
    this.expandedEvent = null;
    this.investigateResult = null;

    const severityParam = this.selectedSeverity === 'Critical,High'
      ? (['Critical', 'High'] as SeverityLevel[])
      : (this.selectedSeverity as SeverityLevel) || undefined;

    this.gateway.getAlerts({
      limit:    this.pageSize,
      offset:   this.pageIndex * this.pageSize,
      hours:    this.selectedHours,
      severity: severityParam,
      source:   this.selectedSource    || undefined,
      q:        this.searchQuery.trim() || undefined,
      ioc_only: this.iocOnly           || undefined,
    }).subscribe({
      next: ({ total, events }) => {
        this.total   = total;
        this.alerts  = events;
        this.loading = false;

        const highSev = events.filter(ev => ev.severity === 'Critical' || ev.severity === 'High');
        if (!highSev.length) return;

        // Pre-populate map with any tickets already in JIRA, then auto-create for Critical
        this.gateway.batchCheckJiraTickets(highSev.map(ev => ev.event_id)).subscribe({
          next: ({ tickets }) => {
            for (const [id, ticket] of Object.entries(tickets)) {
              this.jiraTickets.set(id, ticket);
            }
            for (const ev of events) {
              if (ev.severity === 'Critical') this.createTicket(ev);
            }
          },
          error: () => {
            for (const ev of events) {
              if (ev.severity === 'Critical') this.createTicket(ev);
            }
          },
        });
      },
      error: (err) => {
        this.loading = false;
        const msg = err?.error?.detail ?? err?.message ?? 'Failed to reach the API Gateway.';
        this.snackBar.open(msg, 'Dismiss', { duration: 10000, panelClass: 'snack-error' });
      }
    });
  }

  onPage(e: PageEvent): void {
    this.pageIndex = e.pageIndex;
    this.pageSize  = e.pageSize;
    this.loadAlerts();
  }

  onTimeChange(): void   { this.pageIndex = 0; this.loadAlerts(); }
  onFilterChange(): void { this.pageIndex = 0; this.loadAlerts(); }
  toggleIocFilter(): void { this.iocOnly = !this.iocOnly; this.pageIndex = 0; this.loadAlerts(); }

  onSearchInput(): void {
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => {
      this.pageIndex = 0;
      this.loadAlerts();
    }, 400);
  }

  toggleRow(row: UnifiedEvent): void {
    this.expandedEvent = this.expandedEvent === row ? null : row;
    if (this.expandedEvent !== row) this.investigateResult = null;
  }

  // ── Investigate ───────────────────────────────────────────────────────────
  startInvestigate(type: EntityType, value: string, event: Event): void {
    event.stopPropagation();
    if (!value) return;
    this.investigateTarget = { type, value };
    this.investigating     = true;
    this.investigateError  = '';
    this.investigateResult = null;
    this.invSeverity       = '';
    this.invExpandedEvents.clear();

    const req: InvestigateRequest = {
      entity_type: type, value, limit: 100,
    };
    this.gateway.investigate(req).subscribe({
      next:  (res) => { this.investigateResult = res; this.investigating = false; },
      error: (err) => {
        this.investigateError = err?.error?.detail ?? err?.message ?? 'Investigation failed.';
        this.investigating = false;
      }
    });
  }

  onInvSeverityChange(): void {
    if (!this.investigateTarget) return;
    this.investigating     = true;
    this.investigateError  = '';
    this.investigateResult = null;
    this.invExpandedEvents.clear();

    const req: InvestigateRequest = {
      entity_type: this.investigateTarget.type,
      value:       this.investigateTarget.value,
      limit:       100,
      severities:  this.invSeverity ? [this.invSeverity] : undefined,
    };
    this.gateway.investigate(req).subscribe({
      next:  (res) => { this.investigateResult = res; this.investigating = false; },
      error: (err) => {
        this.investigateError = err?.error?.detail ?? err?.message ?? 'Investigation failed.';
        this.investigating = false;
      }
    });
  }

  loadMoreEvents(): void {
    if (!this.investigateTarget || !this.investigateResult) return;
    this.loadingMore = true;

    const req: InvestigateRequest = {
      entity_type: this.investigateTarget.type,
      value:       this.investigateTarget.value,
      limit:       100,
      offset:      this.investigateResult.events.length,
      severities:  this.invSeverity ? [this.invSeverity] : undefined,
    };
    this.gateway.investigate(req).subscribe({
      next: (res) => {
        this.investigateResult!.events.push(...res.events);
        this.loadingMore = false;
      },
      error: (err) => {
        this.investigateError = err?.error?.detail ?? err?.message ?? 'Load more failed.';
        this.loadingMore = false;
      }
    });
  }

  // ── JIRA ──────────────────────────────────────────────────────────────────
  createTicket(row: UnifiedEvent): void {
    if (this.creatingTicket.has(row.event_id) || this.jiraTickets.has(row.event_id)) return;
    this.creatingTicket.add(row.event_id);

    const req: JiraTicketRequest = {
      event_id: row.event_id,
      time:     row.time,
      severity: row.severity,
      source:   row.source,
      category: row.category,
      summary:  row.summary,
      user:     row.user,
      host:     row.host,
      src_ip:   row.src_ip,
      ...(row.source === 'ms-defender' ? { raw: row.raw, mitre: row.mitre } : {}),
    };

    this.gateway.createJiraTicket(req).subscribe({
      next: (res: JiraTicketResult) => {
        this.jiraTickets.set(row.event_id, { key: res.key, url: res.url });
        this.creatingTicket.delete(row.event_id);
        if (res.created) {
          const ref = this.snackBar.open(`JIRA ${res.key} created`, 'View', { duration: 6000 });
          ref.onAction().subscribe(() => window.open(res.url, '_blank'));
        }
      },
      error: (err) => {
        this.creatingTicket.delete(row.event_id);
        // Only show error toast for manual (High) actions; swallow silent Critical failures
        if (row.severity !== 'Critical') {
          this.snackBar.open(
            err?.error?.detail ?? 'Failed to create JIRA ticket',
            'Dismiss',
            { duration: 8000, panelClass: 'snack-error' },
          );
        }
      },
    });
  }

  ticketFor(eventId: string): { key: string; url: string } | undefined {
    return this.jiraTickets.get(eventId);
  }

  closeInvestigate(): void {
    this.investigateResult = null;
    this.investigateTarget = null;
  }

  // ── VirusTotal ────────────────────────────────────────────────────────────
  vtLookupTargets(row: UnifiedEvent): { iocType: 'ip' | 'domain' | 'hash'; value: string; label: string }[] {
    const targets: { iocType: 'ip' | 'domain' | 'hash'; value: string; label: string }[] = [];
    if (row.remote_ip && !this._PRIV.test(row.remote_ip)) {
      targets.push({ iocType: 'ip', value: row.remote_ip, label: `Remote IP: ${row.remote_ip}` });
    }
    if (row.src_ip && !this._PRIV.test(row.src_ip) && row.src_ip !== row.remote_ip) {
      targets.push({ iocType: 'ip', value: row.src_ip, label: `Src IP: ${row.src_ip}` });
    }
    if (row.domain) {
      targets.push({ iocType: 'domain', value: row.domain, label: `Domain: ${row.domain}` });
    }
    const raw = row.raw ?? {};
    // Top-level hash fields (Wazuh / ms-graph legacy)
    if (raw['sha256']) targets.push({ iocType: 'hash', value: raw['sha256'], label: `SHA256: ${String(raw['sha256']).slice(0, 14)}…` });
    if (raw['sha1'])   targets.push({ iocType: 'hash', value: raw['sha1'],   label: `SHA1: ${String(raw['sha1']).slice(0, 14)}…`   });
    if (raw['md5'])    targets.push({ iocType: 'hash', value: raw['md5'],    label: `MD5: ${String(raw['md5']).slice(0, 14)}…`     });

    // Darktrace AGEMail — link_hosts, sender domain, attachment hashes
    if (row.source === 'darktrace' && raw['link_hosts']) {
      const seen = new Set<string>(targets.map(t => t.value));
      const hosts: string[] = Array.isArray(raw['link_hosts']) ? raw['link_hosts'] : [];
      for (const h of hosts) {
        const v = String(h ?? '').trim();
        if (v && !seen.has(v)) { seen.add(v); targets.push({ iocType: 'domain', value: v, label: `Link: ${v}` }); }
      }
      // Sender domain (skip if already covered by row.domain)
      const fromField = String(raw['from'] ?? '');
      if (fromField.includes('@')) {
        const senderDom = fromField.split('@')[1]?.trim();
        if (senderDom && !seen.has(senderDom)) {
          seen.add(senderDom); targets.push({ iocType: 'domain', value: senderDom, label: `Sender: ${senderDom}` });
        }
      }
      // Attachment hashes
      const addHashes = (arr: any[], prefix: string) => {
        for (const h of (Array.isArray(arr) ? arr : [])) {
          const v = String(h ?? '').trim();
          if (v && !seen.has(v)) { seen.add(v); targets.push({ iocType: 'hash', value: v, label: `${prefix}: ${v.slice(0, 14)}…` }); }
        }
      };
      addHashes(raw['attachment_sha256'] ?? [], 'Attach SHA256');
      addHashes(raw['attachment_sha1']   ?? [], 'Attach SHA1');
    }

    // Defender evidence items — keys: file/file_2, process/process_2, network/network_2, ip, url, email
    if (row.source === 'ms-defender') {
      const seen = new Set<string>(targets.map(t => t.value));
      const addHash = (h: any, prefix: string) => {
        const v = String(h ?? '').trim();
        if (v && !seen.has(v)) { seen.add(v); targets.push({ iocType: 'hash', value: v, label: `${prefix}: ${v.slice(0, 14)}…` }); }
      };
      const addIp = (ip: any, prefix: string) => {
        const v = String(ip ?? '').trim();
        if (v && !this._PRIV.test(v) && !seen.has(v)) { seen.add(v); targets.push({ iocType: 'ip', value: v, label: `${prefix}: ${v}` }); }
      };
      const addDomain = (d: any, prefix: string) => {
        const v = String(d ?? '').trim();
        if (v && !seen.has(v)) { seen.add(v); targets.push({ iocType: 'domain', value: v, label: `${prefix}: ${v}` }); }
      };

      for (const [k, ev] of Object.entries(raw)) {
        if (!ev || typeof ev !== 'object' || Array.isArray(ev)) continue;
        const e = ev as Record<string, any>;
        if (/^file(_\d+)?$/.test(k)) {
          addHash(e['sha256'], 'File SHA256');
          addHash(e['sha1'],   'File SHA1');
          addHash(e['md5'],    'File MD5');
        } else if (/^process(_\d+)?$/.test(k)) {
          addHash(e['sha256'], 'Process SHA256');
        } else if (/^network(_\d+)?$/.test(k)) {
          addIp(e['remote_ip'], 'Network IP');
        } else if (/^ip(_\d+)?$/.test(k)) {
          addIp(e['ip'], 'IP');
        } else if (/^url(_\d+)?$/.test(k)) {
          try { const dom = new URL(String(e['url'] ?? '')).hostname; addDomain(dom, 'URL domain'); } catch {}
        } else if (/^email(_\d+)?$/.test(k)) {
          addDomain(e['sender_domain'], 'Email domain');
          addIp(e['sender_ip'], 'Sender IP');
        }
      }
    }
    return targets;
  }

  lookupVt(iocType: 'ip' | 'domain' | 'hash', value: string, event: Event): void {
    event.stopPropagation();
    this._runVtLookup(iocType, value);
  }

  private _runVtLookup(iocType: 'ip' | 'domain' | 'hash', value: string): void {
    if (!value) return;
    this.vtLoading = true;
    this.vtError   = '';
    this.vtResult  = null;
    this.vtTarget  = { type: iocType, value };

    const req$ = iocType === 'ip'     ? this.gateway.vtLookupIp(value)
               : iocType === 'domain' ? this.gateway.vtLookupDomain(value)
               :                        this.gateway.vtLookupHash(value);

    req$.subscribe({
      next:  r  => { this.vtResult = r; this.vtLoading = false; },
      error: e  => {
        this.vtError   = e?.error?.detail ?? e?.message ?? 'VirusTotal lookup failed';
        this.vtLoading = false;
      },
    });
  }

  closeVt(): void {
    this.vtResult = null;
    this.vtTarget = null;
    this.vtError  = '';
  }

  vtVerdictClass(verdict: string): string {
    return { malicious: 'vt-malicious', suspicious: 'vt-suspicious', clean: 'vt-clean', unknown: 'vt-unknown' }[verdict] ?? 'vt-unknown';
  }

  vtDetectionRatio(stats: VtResult['stats']): string {
    const mal = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
    const total = Object.values(stats).reduce((a, b) => a + (b ?? 0), 0);
    return `${mal} / ${total}`;
  }

  vtLastAnalysis(ts?: number): string {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  severityClass(sev: string): string {
    return ({ Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' } as Record<string, string>)[sev] ?? 'low';
  }

  sourceIcon(source: string): string {
    if (source.includes('sophos'))    return 'security';
    if (source.includes('defender') || source.includes('ms-graph')) return 'shield';
    if (source.includes('darktrace')) return 'radar';
    return 'monitor_heart';
  }

  entityPairs(event: UnifiedEvent): { type: EntityType; value: string }[] {
    const pairs: { type: EntityType; value: string }[] = [];
    if (event.user)   pairs.push({ type: 'user',   value: event.user   });
    if (event.host)   pairs.push({ type: 'host',   value: event.host   });
    if (event.src_ip) pairs.push({ type: 'ip',     value: event.src_ip });
    if (event.domain) pairs.push({ type: 'domain', value: event.domain });
    if (event.sender_domain && event.sender_domain !== event.domain)
      pairs.push({ type: 'domain', value: event.sender_domain });
    return pairs;
  }

  severityEntries(map: Record<string, number>): { sev: string; count: number }[] {
    return ['Critical', 'High', 'Medium', 'Low']
      .filter(s => map[s])
      .map(s => ({ sev: s, count: map[s] }));
  }

  iocTypeIcon(type: string): string {
    const m: Record<string, string> = { ip: 'router', cve: 'bug_report', domain: 'language', hash: 'fingerprint', url: 'link' };
    return m[type] ?? 'policy';
  }

  iocCheckedList(misp: NonNullable<UnifiedEvent['misp']>): { type: string; values: string[] }[] {
    const out: { type: string; values: string[] }[] = [];
    if (misp.iocs_checked.ips.length)     out.push({ type: 'ip',     values: misp.iocs_checked.ips });
    if (misp.iocs_checked.cves.length)    out.push({ type: 'cve',    values: misp.iocs_checked.cves });
    if (misp.iocs_checked.domains.length) out.push({ type: 'domain', values: misp.iocs_checked.domains });
    if (misp.iocs_checked.hashes.length)  out.push({ type: 'hash',   values: misp.iocs_checked.hashes });
    return out;
  }

  objectEntries(obj: Record<string, any>, prefix = ''): { key: string; val: string }[] {
    const result: { key: string; val: string }[] = [];
    for (const [k, v] of Object.entries(obj ?? {})) {
      const full = prefix ? `${prefix}.${k}` : k;
      if (v !== null && v !== undefined && typeof v === 'object' && !Array.isArray(v)) {
        result.push(...this.objectEntries(v, full));
      } else {
        const str = Array.isArray(v) ? JSON.stringify(v) : String(v ?? '');
        if (str) result.push({ key: full, val: str });
      }
    }
    return result;
  }

  // ── Investigation event expand ────────────────────────────────────────────
  toggleInvEvent(eventId: string): void {
    if (this.invExpandedEvents.has(eventId)) {
      this.invExpandedEvents.delete(eventId);
    } else {
      this.invExpandedEvents.add(eventId);
    }
  }

  invRawEntries(ev: UnifiedEvent): { key: string; val: string }[] {
    const entries = this.objectEntries(ev.raw ?? {});
    // Prepend entity fields so they always appear first
    const top: { key: string; val: string }[] = [];
    if (ev.user)      top.push({ key: 'user',      val: ev.user });
    if (ev.host)      top.push({ key: 'host',      val: ev.host });
    if (ev.src_ip)    top.push({ key: 'src_ip',    val: ev.src_ip });
    if (ev.domain)         top.push({ key: 'domain',         val: ev.domain });
    if (ev.sender_domain)  top.push({ key: 'sender_domain',  val: ev.sender_domain });
    if (ev.remote_ip)      top.push({ key: 'remote_ip',      val: ev.remote_ip });
    if (ev.mitre?.length) {
      top.push({ key: 'mitre', val: ev.mitre.map((m: any) => m.id ?? m).join(', ') });
    }
    return [...top, ...entries];
  }
}
