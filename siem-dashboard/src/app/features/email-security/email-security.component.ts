import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { MatExpansionModule } from '@angular/material/expansion';
import { of } from 'rxjs';
import { catchError, finalize } from 'rxjs/operators';
import {
  EmailSecurityService,
  EmailRecord,
  EmailDetail,
  EmailSearchFilters,
  MitreTechnique,
  VtResult,
  DefenderIncident,
  DefenderIncidentAlert,
  IncidentEvidence,
} from '../../core/services/email-security.service';

interface Toast { msg: string; type: 'ok' | 'err' | 'warn'; }

const DEFAULT_HUNT = `EmailEvents
| where Timestamp > ago(7d)
| where isnotempty(ThreatTypes)
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
| limit 50`;

@Component({
  selector: 'app-email-security',
  standalone: true,
  imports: [CommonModule, FormsModule, MatIconModule, MatExpansionModule],
  templateUrl: './email-security.component.html',
  styleUrl: './email-security.component.scss',
})
export class EmailSecurityComponent implements OnInit {
  // Data
  emails: EmailRecord[] = [];
  selectedEmail: EmailRecord | null = null;
  detail: EmailDetail | null = null;

  // UI state
  loading = false;
  detailLoading = false;
  activeTab: 'list' | 'incidents' | 'hunt' = 'list';
  apiError = '';
  permissionDenied = false;

  // Filters (days → API reload; severity/status → client-side)
  days = 7;
  filterSeverity = '';
  filterStatus = '';

  // Incidents — fetched directly from Graph API
  incidents: DefenderIncident[] = [];
  incidentsLoading = false;
  incidentsError = '';

  // Incidents tab expansion state
  expandedIncidentIds = new Set<string>();
  expandedAlertIds    = new Set<string>();

  // Hunting
  huntQuery = DEFAULT_HUNT;
  huntResults: any[] | null = null;
  huntSchema: any[] = [];
  huntLoading = false;
  huntError = '';

  // Action modal
  actionModal: { email: EmailRecord; action: string } | null = null;
  actionUserId = '';
  actionLoading = false;

  toast: Toast | null = null;
  private toastTimer: any;

  // VirusTotal state — keyed by "type:value"
  vtResults: Record<string, VtResult> = {};
  vtLoading = new Set<string>();

  constructor(private svc: EmailSecurityService) {}

  ngOnInit(): void {
    this.loadAll();
    this.loadIncidents();
  }

  setDays(d: number): void {
    this.days = d;
    this.loadAll();
    this.loadIncidents();
  }

  loadIncidents(): void {
    this.incidentsLoading = true;
    this.incidentsError = '';
    this.svc.getIncidents(this.days)
      .pipe(
        catchError(e => {
          this.incidentsError = e?.error?.detail || e?.message || 'Failed to load incidents';
          return of({ incidents: [], total: 0 });
        }),
        finalize(() => (this.incidentsLoading = false)),
      )
      .subscribe(r => {
        this.incidents = r.incidents || [];
      });
  }

  get filteredIncidents(): DefenderIncident[] {
    return this.incidents.filter(inc => {
      if (this.filterSeverity && inc.severity !== this.filterSeverity) return false;
      if (this.filterStatus  && inc.status.toLowerCase() !== this.filterStatus) return false;
      return true;
    });
  }

  get filteredEmails(): EmailRecord[] {
    return this.emails.filter(em => {
      if (this.filterSeverity && (em.Severity || '').toLowerCase() !== this.filterSeverity) return false;
      if (this.filterStatus && (em.Status || '').toLowerCase() !== this.filterStatus) return false;
      return true;
    });
  }

  loadAll(): void {
    this.loading = true;
    this.apiError = '';
    this.permissionDenied = false;
    this.svc.searchEmails({ days: this.days }).pipe(
      catchError(e => {
        const status = e?.status;
        const detail = e?.error?.detail || e?.message || 'API error';
        if (status === 403 || status === 503) {
          this.permissionDenied = true;
        } else {
          this.apiError = detail;
        }
        return of({ results: [] });
      }),
      finalize(() => (this.loading = false)),
    ).subscribe(r => {
      this.emails = (r as any).results || [];
    });
  }

  selectEmail(email: EmailRecord): void {
    this.selectedEmail = email;
    this.detail = null;
    this.detailLoading = true;
    this.svc.getDetail(email.NetworkMessageId)
      .pipe(catchError(() => of(null)), finalize(() => (this.detailLoading = false)))
      .subscribe(d => (this.detail = d));
  }

  closeDetail(): void {
    this.selectedEmail = null;
    this.detail = null;
  }

  runHunt(): void {
    if (!this.huntQuery.trim()) return;
    this.huntLoading = true;
    this.huntError = '';
    this.huntResults = null;
    this.svc.runHunt(this.huntQuery)
      .pipe(finalize(() => (this.huntLoading = false)))
      .subscribe({
        next: r => {
          this.huntResults = r.results || [];
          this.huntSchema  = r.schema  || [];
          if (this.huntResults.length === 0) this.huntError = 'Query returned no results.';
        },
        error: e => {
          const status = e?.status;
          if (status === 403 || status === 503) {
            this.huntError = 'PERMISSION_DENIED';
          } else {
            this.huntError = e?.error?.detail || e?.error?.error || 'Query failed';
          }
        },
      });
  }

  get huntColumns(): string[] {
    if (this.huntResults && this.huntResults.length) return Object.keys(this.huntResults[0]);
    if (this.huntSchema.length) return this.huntSchema.map((s: any) => s.name);
    return [];
  }

  openAction(email: EmailRecord, action: string): void {
    this.actionModal = { email, action };
    this.actionUserId = email.RecipientEmailAddress;
  }

  confirmAction(): void {
    if (!this.actionModal) return;
    this.actionLoading = true;
    this.svc.emailAction({
      user_id:              this.actionUserId,
      internet_message_id:  this.actionModal.email.InternetMessageId,
      action:               this.actionModal.action as any,
    }).pipe(finalize(() => (this.actionLoading = false)))
      .subscribe({
        next: () => {
          this.showToast(`Action '${this.actionModal!.action}' applied`, 'ok');
          this.actionModal = null;
          this.loadAll();
        },
        error: e => this.showToast(e?.error?.error || 'Action failed', 'err'),
      });
  }

  // ── Incidents ────────────────────────────────────────────────────────────────

  toggleIncident(id: string): void {
    if (this.expandedIncidentIds.has(id)) this.expandedIncidentIds.delete(id);
    else this.expandedIncidentIds.add(id);
  }

  toggleAlertRow(alertId: string): void {
    if (this.expandedAlertIds.has(alertId)) this.expandedAlertIds.delete(alertId);
    else this.expandedAlertIds.add(alertId);
  }

  incidentHighestSeverity(inc: DefenderIncident): string {
    const order = ['high', 'medium', 'low', 'informational'];
    for (const sev of order) {
      if (inc.alerts.some(a => (a.severity || '').toLowerCase() === sev)) return sev;
    }
    return (inc.severity || 'unknown').toLowerCase();
  }

  uniqueServices(inc: DefenderIncident): string[] {
    const SHORT: Record<string, string> = {
      microsoftDefenderForOffice365: 'Email',
      microsoftDefenderForEndpoint:  'Endpoint',
      microsoftDefenderForIdentity:  'Identity',
      microsoftCloudAppSecurity:     'Cloud Apps',
      azureAdIdentityProtection:     'AADIP',
      microsoftDefender:             'Defender',
    };
    return [...new Set(inc.alerts.map(a => SHORT[a.serviceSource] || a.serviceSource).filter(Boolean))];
  }

  uniqueCategories(inc: DefenderIncident): string[] {
    return [...new Set(inc.alerts.map(a => this.getThreatLabel(a.category)).filter(c => c !== 'Clean'))];
  }

  evidenceOf(ia: DefenderIncidentAlert, type: string): IncidentEvidence[] {
    return (ia.evidence || []).filter(e => e.type === type);
  }

  get incidentStats() {
    const incs = this.filteredIncidents;
    return {
      total:    incs.length,
      active:   incs.filter(i => ['active', 'inprogress'].includes((i.status || '').toLowerCase())).length,
      resolved: incs.filter(i => i.status?.toLowerCase() === 'resolved').length,
      high:     incs.filter(i => i.severity?.toLowerCase() === 'high').length,
    };
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  getThreatClass(threats: string): string {
    if (!threats) return '';
    const t = threats.toLowerCase();
    if (t.includes('phish')) return 'threat-phish';
    if (t.includes('malware')) return 'threat-malware';
    if (t.includes('businessemailcompromise')) return 'threat-bec';
    if (t.includes('spam')) return 'threat-spam';
    return 'threat-other';
  }

  getThreatLabel(threats: string): string {
    if (!threats) return 'Clean';
    const t = threats.toLowerCase();
    if (t.includes('phish'))  return 'Phishing';
    if (t.includes('malware')) return 'Malware';
    if (t.includes('businessemailcompromise')) return 'BEC';
    if (t.includes('spam'))   return 'Spam';
    return threats.split(',')[0].trim();
  }

  getDeliveryClass(action: string): string {
    const a = (action || '').toLowerCase();
    if (a === 'blocked')    return 'del-blocked';
    if (a === 'quarantined' || a === 'quarantine') return 'del-quarantine';
    if (a === 'delivered')  return 'del-delivered';
    return 'del-other';
  }

  getAuthResult(details: string, key: string): string {
    if (!details) return '?';
    try {
      const parsed = typeof details === 'string' ? JSON.parse(details) : details;
      return parsed[key] ?? '?';
    } catch {
      return '?';
    }
  }

  authClass(val: string): string {
    const v = (val || '').toLowerCase();
    if (v === 'pass') return 'auth-pass';
    if (v === 'fail') return 'auth-fail';
    return 'auth-none';
  }

  isUrlThreat(url: any): boolean {
    return !!(url.ThreatTypes && url.ThreatTypes.length) || url.Verdict === 'malicious';
  }

  verdictClass(verdict: string): string {
    const v = (verdict || '').toLowerCase();
    if (v === 'malicious')  return 'verdict-malicious';
    if (v === 'suspicious') return 'verdict-suspicious';
    if (v === 'clean')      return 'verdict-clean';
    return 'verdict-unknown';
  }

  severityClass(sev: string): string {
    const s = (sev || '').toLowerCase();
    if (s === 'high')          return 'sev-high';
    if (s === 'medium')        return 'sev-medium';
    if (s === 'low')           return 'sev-low';
    if (s === 'informational') return 'sev-info';
    return 'sev-unknown';
  }

  statusClass(status: string): string {
    const s = (status || '').toLowerCase();
    if (s === 'resolved')   return 'status-resolved';
    if (s === 'inprogress') return 'status-progress';
    if (s === 'new')        return 'status-new';
    return 'status-unknown';
  }

  mitreLabel(t: MitreTechnique): string {
    return t.id ? `${t.id} — ${t.technique}` : t.technique;
  }

  formatDate(ts: string): string {
    if (!ts) return '—';
    return new Date(ts).toLocaleString();
  }

  truncate(s: string, max = 60): string {
    if (!s) return '—';
    return s.length > max ? s.slice(0, max) + '…' : s;
  }

  showToast(msg: string, type: 'ok' | 'err' | 'warn'): void {
    clearTimeout(this.toastTimer);
    this.toast = { msg, type };
    this.toastTimer = setTimeout(() => (this.toast = null), 4000);
  }

  // ── VirusTotal helpers ──────────────────────────────────────────────────────

  queryVt(type: 'ip' | 'domain' | 'hash' | 'url', value: string): void {
    if (!value) return;
    const key = `${type}:${value}`;
    if (this.vtResults[key] !== undefined || this.vtLoading.has(key)) return;
    this.vtLoading.add(key);
    this.svc.vtLookup(type, value)
      .pipe(
        catchError(e => {
          const notFound = e?.status === 404;
          const errMsg   = e?.error?.detail || (notFound ? 'Not in VirusTotal' : 'VT lookup failed');
          const fallback = type === 'ip'
            ? `https://www.virustotal.com/gui/ip-address/${value}`
            : type === 'domain'
              ? `https://www.virustotal.com/gui/domain/${value}`
              : type === 'hash'
                ? `https://www.virustotal.com/gui/file/${value}`
                : `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
          return of({ _vtError: true, _notFound: notFound, error: errMsg, permalink: fallback } as any);
        }),
        finalize(() => this.vtLoading.delete(key))
      )
      .subscribe(r => (this.vtResults[key] = r));
  }

  vtGet(type: string, value: string): VtResult | null {
    return value ? (this.vtResults[`${type}:${value}`] ?? null) : null;
  }

  isVtLoading(type: string, value: string): boolean {
    return this.vtLoading.has(`${type}:${value}`);
  }

  vtTotal(r: VtResult): number {
    if (!r?.stats) return 0;
    const s = r.stats;
    return (s.malicious || 0) + (s.suspicious || 0) + (s.harmless || 0) + (s.undetected || 0) + (s.timeout || 0);
  }

  vtBadgeClass(r: VtResult | null): string {
    if (!r) return '';
    if ((r as any)._vtError) return 'vt-unknown';
    const v = (r.verdict || '').toLowerCase();
    if (v === 'malicious')  return 'vt-malicious';
    if (v === 'suspicious') return 'vt-suspicious';
    if (v === 'clean')      return 'vt-clean';
    return 'vt-unknown';
  }

  vtLabel(r: VtResult | null): string {
    if (!r) return '';
    if ((r as any)._vtError) return (r as any)._notFound ? '–' : '!';
    return `${r.stats?.malicious ?? 0}/${this.vtTotal(r)}`;
  }
}
