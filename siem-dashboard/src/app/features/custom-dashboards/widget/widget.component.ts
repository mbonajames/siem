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

interface BarItem    { label: string; val: number; pct: number; color: string; }
interface PieSlice   { dash: number; offset: number; color: string; label: string; val: number; pct: number; }
interface WgtTimePoint { label: string; total: number; bySev: Record<string, number>; }
interface WgtSeries  { key: string; label: string; color: string; linePath: string; areaPath: string; }
interface WgtHeatCell{ day: number; hour: number; count: number; norm: number; }

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

  // ── Grafana-style widgets ─────────────────────────────────────────────────
  readonly TS_W = 540; readonly TS_H = 150;
  readonly TS_PL = 40; readonly TS_PT = 8; readonly TS_PR = 8; readonly TS_PB = 26;
  timePoints:  WgtTimePoint[] = [];
  tsSeries:    WgtSeries[]    = [];
  tsBucketXs:  number[]       = [];
  tsMaxY = 1;
  tsCursorActive = false;
  tsCursorX = 0;
  tsCursorSnapIdx = -1;
  tsTip: { visible: boolean; left: number; top: number; label: string; rows: { label: string; val: number; color: string }[] }
       = { visible: false, left: 0, top: 0, label: '', rows: [] };

  heatCells: WgtHeatCell[] = [];
  heatMax = 1;
  heatTip: { visible: boolean; left: number; top: number; day: string; hour: number; count: number }
          = { visible: false, left: 0, top: 0, day: '', hour: 0, count: 0 };
  readonly HEAT_DAYS  = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  readonly HEAT_HOURS = Array.from({ length: 24 }, (_, i) => i);

  topCatBars: BarItem[] = [];

  // tool-tiles
  toolTiles: { label: string; key: string; count: number; color: string; icon: string }[] = [];

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

    if (type === 'tool-tiles') {
      this.gateway.getStats(this.hours).pipe(catchError(() => of(null))).subscribe(s => {
        this.stats = s;
        if (s) this.buildToolTiles(s);
        this.loading = false;
      });
      return;
    }

    if (type === 'alerts-timeline' || type === 'activity-heatmap' || type === 'top-categories') {
      this.gateway.getAlerts({ limit: 200, hours: this.hours }).pipe(catchError(() => of(null))).subscribe(p => {
        const evs = p?.events ?? [];
        if (type === 'alerts-timeline')   this.buildTimeline(evs);
        if (type === 'activity-heatmap')  this.buildHeatmap(evs);
        if (type === 'top-categories')    this.buildTopCategories(evs);
        this.loading = false;
      });
      return;
    }

    this.loading = false;
  }

  // ── Alerts timeline ───────────────────────────────────────────────────────

  private buildTimeline(events: UnifiedEvent[]): void {
    const N   = this.hours <= 24 ? 24 : this.hours <= 168 ? 7 : 30;
    const ms  = this.hours <= 24 ? 3_600_000 : 86_400_000;
    const now = new Date();

    const buckets: WgtTimePoint[] = Array.from({ length: N }, (_, ii) => {
      const d = new Date(now.getTime() - (N - 1 - ii) * ms);
      const label = ms === 3_600_000
        ? d.getHours().toString().padStart(2, '0') + ':00'
        : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
      return { label, total: 0, bySev: { Critical: 0, High: 0, Medium: 0, Low: 0 } };
    });

    events.forEach(ev => {
      const age  = now.getTime() - new Date(ev.time).getTime();
      const slot = N - 1 - Math.floor(age / ms);
      if (slot >= 0 && slot < N) {
        buckets[slot].total++;
        const s = ev.severity as string;
        if (s in buckets[slot].bySev) buckets[slot].bySev[s]++;
      }
    });

    this.timePoints = buckets;
    this.tsMaxY     = Math.max(...buckets.map(b => b.total), 1);

    const pw = this.TS_W - this.TS_PL - this.TS_PR;
    const ph = this.TS_H - this.TS_PT - this.TS_PB;
    const bot = this.TS_PT + ph;
    const xAt = (i: number) => this.TS_PL + (N <= 1 ? pw / 2 : (i / (N - 1)) * pw);
    const yAt = (v: number) => this.TS_PT + (1 - v / this.tsMaxY) * ph;

    this.tsBucketXs = buckets.map((_, i) => xAt(i));

    const mkSeries = (key: string, label: string, color: string, vals: number[]): WgtSeries => {
      if (!vals.some(v => v > 0)) return { key, label, color, linePath: '', areaPath: '' };
      const pts      = vals.map((v, i) => `${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`);
      const linePath = 'M' + pts.join('L');
      const areaPath = `M${xAt(0).toFixed(1)},${bot}` + pts.map(p => 'L' + p).join('') + `L${xAt(N-1).toFixed(1)},${bot}Z`;
      return { key, label, color, linePath, areaPath };
    };

    this.tsSeries = [
      mkSeries('Total',    'Total',    '#2a78d6', buckets.map(b => b.total)),
      mkSeries('Critical', 'Critical', '#d03b3b', buckets.map(b => b.bySev['Critical'])),
      mkSeries('High',     'High',     '#eda100', buckets.map(b => b.bySev['High'])),
    ].filter(s => s.linePath !== '');
  }

  // ── Heatmap ───────────────────────────────────────────────────────────────

  private buildHeatmap(events: UnifiedEvent[]): void {
    const grid: number[][] = Array.from({ length: 7 }, () => new Array(24).fill(0));
    events.forEach(ev => {
      const d   = new Date(ev.time);
      const dow = (d.getDay() + 6) % 7;
      grid[dow][d.getHours()]++;
    });
    this.heatMax   = Math.max(1, ...grid.flat());
    this.heatCells = [];
    for (let day = 0; day < 7; day++)
      for (let hour = 0; hour < 24; hour++)
        this.heatCells.push({ day, hour, count: grid[day][hour], norm: grid[day][hour] / this.heatMax });
  }

  // ── Top categories ────────────────────────────────────────────────────────

  private buildTopCategories(events: UnifiedEvent[]): void {
    const counts: Record<string, number> = {};
    events.forEach(e => {
      const k = (e.event_class || e.category || '').trim();
      if (k && k !== 'unknown') counts[k] = (counts[k] ?? 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const max    = sorted[0]?.[1] ?? 1;
    this.topCatBars = sorted.map(([label, val]) => ({
      label, val, pct: Math.round(val / max * 100), color: '#2a78d6',
    }));
  }

  // ── Timeline interaction ──────────────────────────────────────────────────

  onTsMove(ev: MouseEvent): void {
    if (!this.timePoints.length) return;
    const rect  = (ev.currentTarget as SVGSVGElement).getBoundingClientRect();
    const svgX  = (ev.clientX - rect.left) * (this.TS_W / rect.width);
    let nearest = 0, minDist = Infinity;
    this.tsBucketXs.forEach((bx, i) => {
      const d = Math.abs(bx - svgX);
      if (d < minDist) { minDist = d; nearest = i; }
    });
    const pt = this.timePoints[nearest];
    if (!pt) return;
    this.tsCursorActive  = true;
    this.tsCursorX       = this.tsBucketXs[nearest];
    this.tsCursorSnapIdx = nearest;
    this.tsTip = {
      visible: true, left: ev.clientX + 14, top: ev.clientY - 72, label: pt.label,
      rows: [
        { label: 'Total',    val: pt.total,                  color: '#2a78d6' },
        { label: 'Critical', val: pt.bySev['Critical'] ?? 0, color: '#d03b3b' },
        { label: 'High',     val: pt.bySev['High']     ?? 0, color: '#eda100' },
        { label: 'Medium',   val: pt.bySev['Medium']   ?? 0, color: '#86b6ef' },
        { label: 'Low',      val: pt.bySev['Low']      ?? 0, color: '#3fb950' },
      ],
    };
  }

  onTsLeave(): void {
    this.tsCursorActive = false;
    this.tsTip = { ...this.tsTip, visible: false };
  }

  tsYTicks(): { y: number; label: string }[] {
    const ph = this.TS_H - this.TS_PT - this.TS_PB;
    return [0, 1, 2, 3, 4].map(i => {
      const v = Math.round((i / 4) * this.tsMaxY);
      return { y: this.TS_PT + (1 - i / 4) * ph, label: v >= 1000 ? (v / 1000).toFixed(1) + 'k' : '' + v };
    });
  }

  tsXLabels(): { label: string; x: number }[] {
    const N = this.timePoints.length;
    if (!N) return [];
    const skip = N <= 7 ? 1 : N <= 24 ? 4 : 5;
    return this.timePoints
      .map((p, i) => ({ label: p.label, x: this.tsBucketXs[i] }))
      .filter((_, i) => i % skip === 0 || i === N - 1);
  }

  tsSnapY(s: WgtSeries): number {
    const idx = this.tsCursorSnapIdx;
    if (idx < 0 || !this.timePoints[idx]) return this.TS_PT;
    const bySev = this.timePoints[idx].bySev;
    const v = s.key === 'Total' ? this.timePoints[idx].total
            : s.key === 'Critical' ? (bySev['Critical'] ?? 0)
            : s.key === 'High'     ? (bySev['High']     ?? 0)
            : 0;
    return this.TS_PT + (1 - v / this.tsMaxY) * (this.TS_H - this.TS_PT - this.TS_PB);
  }

  // ── Heatmap interaction ───────────────────────────────────────────────────

  onHeatEnter(ev: MouseEvent, cell: WgtHeatCell): void {
    this.heatTip = {
      visible: true, left: ev.clientX + 14, top: ev.clientY - 52,
      day: this.HEAT_DAYS[cell.day], hour: cell.hour, count: cell.count,
    };
  }

  onHeatLeave(): void { this.heatTip = { ...this.heatTip, visible: false }; }

  private buildToolTiles(s: AlertStats): void {
    const TOOL_META = [
      { key: 'wazuh',          label: 'Wazuh',     color: '#F46A1F', icon: 'security'      },
      { key: 'sophos-central', label: 'Sophos',    color: '#0072C6', icon: 'shield'        },
      { key: 'ms-graph',       label: 'Defender',  color: '#00B4F0', icon: 'cloud'         },
      { key: 'darktrace',      label: 'Darktrace', color: '#7F77DD', icon: 'psychology'    },
    ];
    const known = new Set(TOOL_META.map(t => t.key));
    const tiles: { key: string; label: string; color: string; icon: string; count: number }[] =
      TOOL_META.map(m => ({ ...m, count: s.by_source[m.key] ?? 0 }));
    Object.entries(s.by_source).forEach(([key, count]) => {
      if (!known.has(key)) tiles.push({ key, label: key, color: '#8b949e', icon: 'devices_other', count });
    });
    this.toolTiles = tiles.sort((a, b) => b.count - a.count);
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
