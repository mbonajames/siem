import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { finalize } from 'rxjs/operators';
import {
  CorrelationService,
  CorrelationResult,
  CorrelatedEvent,
  Insight,
  EntityType,
  Source,
  Severity,
} from '../../core/services/correlation.service';
import { EmailSecurityService } from '../../core/services/email-security.service';
import { NessusService } from '../../core/services/nessus.service';

interface Toast { msg: string; type: 'ok' | 'err' | 'warn'; }

const SOURCE_META: Record<Source, { label: string; icon: string; color: string }> = {
  wazuh:     { label: 'Wazuh',      icon: 'shield',              color: '#f59e0b' },
  sophos:    { label: 'Sophos',     icon: 'security',            color: '#34d399' },
  darktrace: { label: 'Darktrace',  icon: 'bubble_chart',        color: '#60a5fa' },
  email:     { label: 'Email',      icon: 'mark_email_unread',   color: '#ef4444' },
  jira:      { label: 'Jira',       icon: 'confirmation_number', color: '#818cf8' },
};

@Component({
  selector: 'app-correlation',
  standalone: true,
  imports: [CommonModule, FormsModule, MatIconModule],
  templateUrl: './correlation.component.html',
  styleUrl: './correlation.component.scss',
})
export class CorrelationComponent {
  // Search inputs
  entityType: EntityType = 'user';
  entityValue = '';
  days = 7;

  // Results
  result: CorrelationResult | null = null;
  loading = false;
  error = '';

  // UI
  activeFilter: Source | 'all' = 'all';
  activeSeverity: Severity | 'all' = 'all';
  expandedId: string | null = null;
  highlightedIds = new Set<string>();

  // Ticket modal
  ticketModal = false;
  ticketNotes = '';
  ticketPriority = 'High';
  ticketLoading = false;

  // Remediation
  remModal: { event: CorrelatedEvent; action: string } | null = null;
  remUserId = '';
  remLoading = false;

  toast: Toast | null = null;
  private toastTimer: any;

  readonly sources = Object.keys(SOURCE_META) as Source[];
  readonly sourceMeta = SOURCE_META;
  readonly entityTypes: { value: EntityType; label: string; placeholder: string; icon: string }[] = [
    { value: 'user',   label: 'User',        placeholder: 'user@hope.org',         icon: 'person' },
    { value: 'device', label: 'Device',      placeholder: 'HOPE-PC-001',            icon: 'computer' },
    { value: 'ip',     label: 'IP Address',  placeholder: '192.168.1.100',          icon: 'router' },
    { value: 'hash',   label: 'File Hash',   placeholder: 'SHA256 hash…',           icon: 'fingerprint' },
  ];

  constructor(private svc: CorrelationService) {}

  get currentEntityMeta() {
    return this.entityTypes.find(e => e.value === this.entityType)!;
  }

  investigate(): void {
    if (!this.entityValue.trim()) return;
    this.loading = true;
    this.error = '';
    this.result = null;
    this.activeFilter = 'all';
    this.activeSeverity = 'all';
    this.highlightedIds.clear();
    this.svc.investigate({ entity_type: this.entityType, entity_value: this.entityValue.trim(), days: this.days })
      .pipe(finalize(() => (this.loading = false)))
      .subscribe({
        next: r => (this.result = r),
        error: e => (this.error = e?.error?.error || 'Investigation failed'),
      });
  }

  get filteredEvents(): CorrelatedEvent[] {
    if (!this.result) return [];
    return this.result.events.filter(e => {
      const srcOk = this.activeFilter === 'all' || e.source === this.activeFilter;
      const sevOk = this.activeSeverity === 'all' || e.severity === this.activeSeverity;
      return srcOk && sevOk;
    });
  }

  get sevCounts(): Record<string, number> {
    const events = this.result?.events || [];
    return {
      critical: events.filter(e => e.severity === 'critical').length,
      high:     events.filter(e => e.severity === 'high').length,
      medium:   events.filter(e => e.severity === 'medium').length,
      low:      events.filter(e => e.severity === 'low').length,
      info:     events.filter(e => e.severity === 'info').length,
    };
  }

  highlightInsight(insight: Insight): void {
    this.highlightedIds = new Set(insight.related_ids);
    this.activeFilter = 'all';
    this.activeSeverity = 'all';
  }

  clearHighlight(): void {
    this.highlightedIds.clear();
  }

  toggleExpand(id: string): void {
    this.expandedId = this.expandedId === id ? null : id;
  }

  openTicketModal(): void {
    this.ticketNotes = '';
    this.ticketPriority = this.result?.insights.some(i => i.severity === 'critical') ? 'High' : 'Medium';
    this.ticketModal = true;
  }

  submitTicket(): void {
    if (!this.result) return;
    this.ticketLoading = true;
    this.svc.createTicket({
      entity_type:  this.result.entity.type,
      entity_value: this.result.entity.value,
      total:        this.result.total,
      insights:     this.result.insights,
      days:         this.result.entity.days,
      priority:     this.ticketPriority,
      notes:        this.ticketNotes,
    }).pipe(finalize(() => (this.ticketLoading = false)))
      .subscribe({
        next: (r: any) => {
          this.ticketModal = false;
          this.showToast(`Jira ticket ${r.key} created`, 'ok');
        },
        error: e => this.showToast(e?.error?.error || 'Ticket creation failed', 'err'),
      });
  }

  // Source-level isolation: re-run filter
  sourceCount(src: Source): number {
    return this.result?.source_stats?.[src]?.count ?? 0;
  }

  // Helpers
  srcLabel(src: Source)  { return SOURCE_META[src]?.label ?? src; }
  srcIcon(src: Source)   { return SOURCE_META[src]?.icon  ?? 'circle'; }
  srcColor(src: Source)  { return SOURCE_META[src]?.color ?? '#fff'; }

  sevClass(sev: string)   { return `sev-${sev}`; }
  insightClass(sev: string) { return `insight-${sev}`; }

  isHighlighted(event: CorrelatedEvent): boolean {
    return this.highlightedIds.size > 0 && this.highlightedIds.has(event.id);
  }

  isDimmed(event: CorrelatedEvent): boolean {
    return this.highlightedIds.size > 0 && !this.highlightedIds.has(event.id);
  }

  formatDate(ts: string): string {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleString(); } catch { return ts; }
  }

  formatRelative(ts: string): string {
    if (!ts) return '';
    try {
      const diff = Date.now() - new Date(ts).getTime();
      const m = Math.floor(diff / 60000);
      if (m < 60) return `${m}m ago`;
      const h = Math.floor(m / 60);
      if (h < 24) return `${h}h ago`;
      return `${Math.floor(h / 24)}d ago`;
    } catch { return ''; }
  }

  showToast(msg: string, type: 'ok' | 'err' | 'warn'): void {
    clearTimeout(this.toastTimer);
    this.toast = { msg, type };
    this.toastTimer = setTimeout(() => (this.toast = null), 4000);
  }
}
