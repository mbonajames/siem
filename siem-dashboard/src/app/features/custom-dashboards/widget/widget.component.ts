import { Component, Input, Output, EventEmitter, OnInit, OnChanges, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { CdkDragHandle } from '@angular/cdk/drag-drop';
import { FormsModule } from '@angular/forms';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import {
  GatewayService, DashboardWidget, WidgetConfig,
  AlertStats, UnifiedEvent,
} from '../../../core/services/gateway.service';

interface BarItem { label: string; val: number; pct: number; color: string; }
interface PieSlice { dash: number; offset: number; color: string; label: string; val: number; pct: number; }

const PIE_C = +(2 * Math.PI * 40).toFixed(4);
const PIE_COLORS = ['#F46A1F','#58a6ff','#3fb950','#7F77DD','#d29922','#da3633','#79c0ff','#ff9a5c'];

const SEV_COLORS: Record<string, string> = {
  Critical: '#da3633', High: '#d29922', Medium: '#58a6ff', Low: '#3fb950',
};
const METRIC_LABEL: Record<string, string> = {
  total: 'Total', critical: 'Critical', high: 'High',
  medium: 'Medium', low: 'Low', ioc: 'IOC Alerts',
};
const METRIC_COLOR: Record<string, string> = {
  total: '#F46A1F', critical: '#da3633', high: '#d29922',
  medium: '#58a6ff', low: '#3fb950', ioc: '#7F77DD',
};

@Component({
  selector: 'app-widget',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatIconModule, MatTooltipModule, MatProgressSpinnerModule,
    CdkDragHandle,
  ],
  templateUrl: './widget.component.html',
  styleUrl: './widget.component.scss',
})
export class WidgetComponent implements OnInit, OnChanges {
  @Input() widget!: DashboardWidget;
  @Input() editMode = false;
  @Input() isOwner  = false;
  @Output() removed    = new EventEmitter<string>();
  @Output() configured = new EventEmitter<DashboardWidget>();

  loading = true;
  error   = '';

  // Data pools (populated based on type)
  stats:        AlertStats | null = null;
  events:       UnifiedEvent[]    = [];
  iocEvents:    UnifiedEvent[]    = [];
  bars:         BarItem[]         = [];
  pieSlices:    PieSlice[]        = [];
  metricVal     = 0;
  metricLabel   = '';
  metricColor   = '#F46A1F';

  readonly PIE_C = PIE_C;

  constructor(private gateway: GatewayService) {}

  ngOnInit(): void {
    this.loadData();
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['hours'] && !changes['hours'].firstChange) {
      if (this.widget.type !== 'divider' && this.widget.type !== 'text') {
        this.loadData();
      }
    }
  }

  @Input() hours = 24;

  private cfg(): WidgetConfig { return this.widget.config ?? {}; }
  private limit(): number { return this.cfg().limit ?? 20;  }

  loadData(): void {
    this.loading = true;
    this.error   = '';
    const type = this.widget.type;

    if (type === 'divider' || type === 'text') {
      this.loading = false;
      return;
    }

    if (type === 'severity-tiles' || type === 'severity-bars' || type === 'source-bars' || type === 'stat-card') {
      this.gateway.getStats(this.hours).pipe(catchError(() => of(null))).subscribe(s => {
        this.stats = s;
        if (s) {
          if (type === 'severity-bars') this.buildSevBars(s);
          if (type === 'source-bars')   this.buildSourceBars(s);
          if (type === 'stat-card')     this.buildStatCard(s);
        }
        this.loading = false;
      });
      return;
    }

    if (type === 'recent-alerts') {
      this.gateway.getAlerts({ limit: this.limit(), hours: this.hours, severity: (this.cfg().severity as any) || undefined })
        .pipe(catchError(() => of(null))).subscribe(p => {
          this.events  = p?.events ?? [];
          this.loading = false;
        });
      return;
    }

    if (type === 'source-pie' || type === 'category-pie' || type === 'top-hosts' || type === 'top-users') {
      this.gateway.getAlerts({ limit: 200, hours: this.hours }).pipe(catchError(() => of(null))).subscribe(p => {
        const evs = p?.events ?? [];
        if      (type === 'source-pie')   this.buildPie(evs, e => e.source);
        else if (type === 'category-pie') this.buildPie(evs, e => e.category);
        else if (type === 'top-hosts')    this.buildEntityBars(evs.filter(e => e.host),   e => e.host!,   '#3fb950');
        else if (type === 'top-users')    this.buildEntityBars(evs.filter(e => e.user),   e => e.user!,   '#7F77DD');
        this.loading = false;
      });
      return;
    }

    if (type === 'ioc-summary') {
      forkJoin({
        stats: this.gateway.getStats(this.hours).pipe(catchError(() => of(null))),
        ioc:   this.gateway.getAlerts({ limit: 10, hours: this.hours, ioc_only: true }).pipe(catchError(() => of(null))),
      }).subscribe(({ stats, ioc }) => {
        this.stats     = stats;
        this.iocEvents = ioc?.events ?? [];
        this.loading   = false;
      });
      return;
    }

    this.loading = false;
  }

  private buildSevBars(s: AlertStats): void {
    const meta = [
      { key: 'Critical', color: '#da3633' },
      { key: 'High',     color: '#d29922' },
      { key: 'Medium',   color: '#58a6ff' },
      { key: 'Low',      color: '#3fb950' },
    ];
    const max = Math.max(...meta.map(m => s.by_severity[m.key] ?? 0), 1);
    this.bars = meta.map(m => {
      const val = s.by_severity[m.key] ?? 0;
      return { label: m.key, val, pct: Math.round(val / max * 100), color: m.color };
    });
  }

  private buildSourceBars(s: AlertStats): void {
    const entries = Object.entries(s.by_source).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max = entries[0]?.[1] ?? 1;
    this.bars = entries.map(([label, val]) => ({
      label, val, pct: Math.round(val / max * 100), color: this.srcColor(label),
    }));
  }

  private buildStatCard(s: AlertStats): void {
    const metric = this.cfg().metric ?? 'total';
    const map: Record<string, number> = {
      total:    s.total,
      critical: s.by_severity['Critical'] ?? 0,
      high:     s.by_severity['High']     ?? 0,
      medium:   s.by_severity['Medium']   ?? 0,
      low:      s.by_severity['Low']      ?? 0,
      ioc:      s.ioc_count               ?? 0,
    };
    this.metricVal   = map[metric] ?? 0;
    this.metricLabel = METRIC_LABEL[metric] ?? metric;
    this.metricColor = METRIC_COLOR[metric] ?? '#F46A1F';
  }

  private buildPie(evs: UnifiedEvent[], key: (e: UnifiedEvent) => string): void {
    const counts: Record<string, number> = {};
    evs.forEach(e => { const k = key(e); counts[k] = (counts[k] ?? 0) + 1; });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const total  = sorted.reduce((s, [, v]) => s + v, 0);
    if (!total) return;
    let cumLen = 0;
    this.pieSlices = sorted.map(([label, val], i) => {
      const dash   = (val / total) * PIE_C;
      const offset = PIE_C - cumLen;
      cumLen += dash;
      return { dash, offset, color: PIE_COLORS[i % PIE_COLORS.length], label, val, pct: Math.round(val / total * 100) };
    });
  }

  private buildEntityBars(evs: UnifiedEvent[], key: (e: UnifiedEvent) => string, color: string): void {
    const counts: Record<string, number> = {};
    evs.forEach(e => { const k = key(e); counts[k] = (counts[k] ?? 0) + 1; });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max = sorted[0]?.[1] ?? 1;
    this.bars = sorted.map(([label, val]) => ({
      label, val, pct: Math.round(val / max * 100), color,
    }));
  }

  sevClass(sev: string): string {
    return ({ Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' } as Record<string, string>)[sev] ?? 'low';
  }

  srcColor(src: string): string {
    const m: Record<string, string> = {
      wazuh: '#F46A1F', 'sophos-central': '#0072C6', 'ms-graph': '#00B4F0', darktrace: '#7F77DD',
    };
    return m[src] ?? '#8b949e';
  }

  sevColor(sev: string): string { return SEV_COLORS[sev] ?? '#8b949e'; }

  relativeTime(ts: string): string {
    const m = Math.floor((Date.now() - new Date(ts).getTime()) / 60000);
    if (m < 1)  return 'just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }

  statVal(key: string): number {
    return this.stats
      ? (key === 'ioc' ? (this.stats.ioc_count ?? 0) : (this.stats.by_severity[key] ?? 0))
      : 0;
  }
}
