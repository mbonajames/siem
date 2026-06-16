import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { forkJoin, of } from 'rxjs';
import { catchError, finalize } from 'rxjs/operators';
import {
  EmailSecurityService,
  EmailRecord,
  EmailDetail,
  EmailStats,
  EmailSearchFilters,
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
  imports: [CommonModule, FormsModule, MatIconModule],
  templateUrl: './email-security.component.html',
  styleUrl: './email-security.component.scss',
})
export class EmailSecurityComponent implements OnInit {
  // Data
  emails: EmailRecord[] = [];
  stats: EmailStats = { Total: 0, Phishing: 0, Malware: 0, Spam: 0, BEC: 0, Blocked: 0, Delivered: 0, Quarantined: 0 };
  selectedEmail: EmailRecord | null = null;
  detail: EmailDetail | null = null;

  // Filters
  filters: EmailSearchFilters = { days: 7 };
  filterInputs = { sender: '', recipient: '', subject: '', threat_type: '', delivery_action: '', days: 7 };

  // UI state
  loading = false;
  detailLoading = false;
  activeTab: 'list' | 'hunt' = 'list';
  showFilterBar = true;

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

  constructor(private svc: EmailSecurityService) {}

  ngOnInit(): void {
    this.loadAll();
  }

  loadAll(): void {
    this.loading = true;
    forkJoin({
      emails: this.svc.searchEmails(this.filters).pipe(catchError(() => of({ results: [] }))),
      stats:  this.svc.getStats(this.filters.days ?? 7).pipe(catchError(() => of(null))),
    }).pipe(finalize(() => (this.loading = false))).subscribe(({ emails, stats }) => {
      this.emails = (emails as any).results || [];
      if (stats) this.stats = stats as EmailStats;
    });
  }

  applyFilters(): void {
    this.filters = {
      sender:          this.filterInputs.sender   || undefined,
      recipient:       this.filterInputs.recipient || undefined,
      subject:         this.filterInputs.subject   || undefined,
      threat_type:     this.filterInputs.threat_type || undefined,
      delivery_action: this.filterInputs.delivery_action || undefined,
      days:            this.filterInputs.days,
    };
    this.selectedEmail = null;
    this.detail = null;
    this.loadAll();
  }

  clearFilters(): void {
    this.filterInputs = { sender: '', recipient: '', subject: '', threat_type: '', delivery_action: '', days: 7 };
    this.applyFilters();
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
        error: e => (this.huntError = e?.error?.error || 'Query failed'),
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

  // Helpers
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
    return !!(url.ThreatTypes && url.ThreatTypes.length);
  }

  formatDate(ts: string): string {
    if (!ts) return '—';
    return new Date(ts).toLocaleString();
  }

  showToast(msg: string, type: 'ok' | 'err' | 'warn'): void {
    clearTimeout(this.toastTimer);
    this.toast = { msg, type };
    this.toastTimer = setTimeout(() => (this.toast = null), 4000);
  }
}
