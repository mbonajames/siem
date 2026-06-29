import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { forkJoin, of, Subject } from 'rxjs';
import { catchError, finalize, takeUntil } from 'rxjs/operators';
import { GatewayService, UnifiedEvent, AlertsPage } from '../../core/services/gateway.service';
import { DarktraceService } from '../../core/services/darktrace.service';

interface SeverityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

@Component({
  selector: 'app-network-security',
  standalone: true,
  imports: [CommonModule, FormsModule, MatIconModule],
  templateUrl: './network-security.component.html',
  styleUrl: './network-security.component.scss',
})
export class NetworkSecurityComponent implements OnInit, OnDestroy {
  alerts: UnifiedEvent[] = [];
  total = 0;
  stats: SeverityStats = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  summaryStats: any = null;

  selected: UnifiedEvent | null = null;

  // Filters
  filterSeverity = '';
  filterHours = 24;
  filterQ = '';
  activeFilter = '';

  loading = false;
  private destroy$ = new Subject<void>();

  constructor(
    private gateway: GatewayService,
    private darktrace: DarktraceService,
  ) {}

  ngOnInit(): void {
    this.load();
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  load(): void {
    this.loading = true;
    this.selected = null;

    forkJoin({
      alerts: this.gateway.getAlerts({
        source: 'darktrace',
        severity: (this.activeFilter || this.filterSeverity || undefined) as any,
        hours: this.filterHours,
        q: this.filterQ || undefined,
        limit: 100,
      }).pipe(catchError(() => of<AlertsPage>({ total: 0, events: [] }))),
      summary: this.darktrace.getSummaryStatistics()
        .pipe(catchError(() => of(null))),
    })
      .pipe(finalize(() => (this.loading = false)), takeUntil(this.destroy$))
      .subscribe(({ alerts, summary }) => {
        this.alerts = (alerts as AlertsPage).events || [];
        this.total = (alerts as AlertsPage).total || 0;
        this.summaryStats = summary;
        this.computeStats();
      });
  }

  private computeStats(): void {
    const s: SeverityStats = { total: this.total, critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of this.alerts) {
      if (a.severity === 'Critical') s.critical++;
      else if (a.severity === 'High') s.high++;
      else if (a.severity === 'Medium') s.medium++;
      else s.low++;
    }
    this.stats = s;
  }

  filterBySeverity(sev: string): void {
    this.activeFilter = this.activeFilter === sev ? '' : sev;
    this.load();
  }

  applyFilters(): void {
    this.activeFilter = '';
    this.load();
  }

  clearFilters(): void {
    this.filterSeverity = '';
    this.filterHours = 24;
    this.filterQ = '';
    this.activeFilter = '';
    this.load();
  }

  select(alert: UnifiedEvent): void {
    this.selected = this.selected?.event_id === alert.event_id ? null : alert;
  }

  severityClass(sev: string): string {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'sev-critical';
    if (s === 'high')     return 'sev-high';
    if (s === 'medium')   return 'sev-medium';
    return 'sev-low';
  }

  formatDate(ts: string): string {
    if (!ts) return '—';
    return new Date(ts).toLocaleString();
  }

  rawKeys(event: UnifiedEvent): string[] {
    return Object.keys(event.raw || {}).slice(0, 20);
  }

  rawVal(event: UnifiedEvent, key: string): string {
    const v = (event.raw || {})[key];
    if (v === null || v === undefined) return '—';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }
}
