import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink } from '@angular/router';
import { forkJoin, interval, Subject, of } from 'rxjs';
import { catchError, takeUntil } from 'rxjs/operators';
import { GatewayService, UnifiedEvent, AlertStats, AlertsPage, SophosEndpointHealth } from '../../core/services/gateway.service';

interface BarItem { label: string; val: number; max: number; color: string; }
interface SevBar  { label: string; count: number; color: string; pct: number; }

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, MatIconModule, MatProgressBarModule, MatSnackBarModule, MatTooltipModule, RouterLink],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss'
})
export class DashboardComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();

  loading = false;
  now     = new Date();
  range    = '24h';

  // Tiles — from /stats (accurate counts over full index)
  stats = { critical: 0, high: 0, medium: 0, low: 0, total: 0, iocCount: 0 };

  // Charts — from /alerts (sample for distribution pies)
  sourceItems:   BarItem[] = [];
  categoryItems: BarItem[] = [];
  hostItems:     BarItem[] = [];
  userItems:     BarItem[] = [];

  // Recent alerts feed
  recentEvents: UnifiedEvent[] = [];
  // Distribution bars — driven from /stats (accurate full-window totals, not sample)
  sevBars:    SevBar[] = [];
  sourceBars: SevBar[] = [];

  // Sophos endpoint security — totals from /stats, breakdown from sample
  sophosTotal:    number = 0;
  sophosEvents:   UnifiedEvent[] = [];
  sophosSevBars:  SevBar[] = [];
  sophosTopHosts: BarItem[] = [];
  sophosHealth:   SophosEndpointHealth | null = null;
  sophosHealthLoading = false;

  // MS Defender (direct pipeline) — totals from /stats, breakdown from sample
  defenderTotal:      number = 0;
  defenderEvents:     UnifiedEvent[] = [];
  defenderSevBars:    SevBar[] = [];
  defenderCatBars:    SevBar[] = [];
  defenderTopDevices: BarItem[] = [];
  defenderTopUsers:   BarItem[] = [];

  // Darktrace — totals from /stats, breakdown from dedicated call
  darktraceTotal:    number = 0;
  darktraceEvents:   UnifiedEvent[] = [];
  darktraceSevBars:  SevBar[] = [];
  darktraceCatBars:  SevBar[] = [];
  darktraceTopDevices: BarItem[] = [];

  readonly PIE_R = 40;
  readonly PIE_C = +(2 * Math.PI * 40).toFixed(4);
  readonly PIE_COLORS = [
    '#F46A1F', '#58a6ff', '#3fb950', '#7F77DD',
    '#d29922', '#da3633', '#79c0ff', '#ff9a5c',
  ];

  getPieSlices(items: BarItem[]): { dash: number; offset: number; color: string; label: string; val: number; pct: number }[] {
    const total = items.reduce((s, i) => s + i.val, 0);
    if (!total) return [];
    let cumLen = 0;
    return items.map((item, idx) => {
      const dash   = (item.val / total) * this.PIE_C;
      const offset = this.PIE_C - cumLen;
      cumLen += dash;
      return {
        dash, offset,
        color: this.PIE_COLORS[idx % this.PIE_COLORS.length],
        label: item.label, val: item.val,
        pct: Math.round(item.val / total * 100)
      };
    });
  }

  get clockStr(): string {
    return this.now.toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: 'short' })
      + ' · '
      + this.now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      + ' UTC';
  }

  get currentHours(): number {
    return this.range === '7d' ? 168 : this.range === '30d' ? 720 : 24;
  }

  private rangeToHours(): number { return this.currentHours; }

  constructor(private gateway: GatewayService, private snackBar: MatSnackBar) {}

  ngOnInit(): void {
    this.load();
    interval(1000).pipe(takeUntil(this.destroy$)).subscribe(() => { this.now = new Date(); });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  setRange(r: string): void { this.range = r; this.load(); }

  load(): void {
    this.loading = true;
    const hours  = this.rangeToHours();

    forkJoin({
      stats:      this.gateway.getStats(hours).pipe(catchError(() => of(null))),
      page:       this.gateway.getAlerts({ limit: 200, hours }).pipe(catchError(() => of(null))),
      sophos:     this.gateway.getAlerts({ source: 'sophos-central', limit: 200, hours }).pipe(catchError(() => of(null))),
      defender:   this.gateway.getAlerts({ source: 'ms-defender',    limit: 200, hours }).pipe(catchError(() => of(null))),
      darktrace:  this.gateway.getAlerts({ source: 'darktrace',      limit: 200, hours }).pipe(catchError(() => of(null))),
    }).subscribe({
      next: ({ stats, page, sophos, defender, darktrace }) => {
        this.processEvents((page       as AlertsPage | null)?.events ?? []);
        this.processSophosEvents((sophos     as AlertsPage | null)?.events ?? []);
        this.processDefenderEvents((defender   as AlertsPage | null)?.events ?? []);
        this.processDarktraceEvents((darktrace  as AlertsPage | null)?.events ?? []);
        if (stats) this.processStats(stats);   // runs last — accurate aggs override sample-based bars
        this.loading = false;
      },
      error: (err) => {
        this.loading = false;
        const msg = err?.error?.detail ?? err?.message ?? 'Failed to reach the API Gateway.';
        this.snackBar.open(msg, 'Dismiss', { duration: 10000, panelClass: 'snack-error' });
      }
    });

    // Endpoint health runs separately — Sophos API can be slow, don't block main data
    this.sophosHealthLoading = true;
    this.gateway.getSophosEndpointHealth()
      .pipe(catchError(() => of(null)), takeUntil(this.destroy$))
      .subscribe(h => {
        this.sophosHealth        = h as SophosEndpointHealth | null;
        this.sophosHealthLoading = false;
      });
  }

  private processStats(s: AlertStats): void {
    this.stats.total    = s.total;
    this.stats.critical = s.by_severity['Critical'] ?? 0;
    this.stats.high     = s.by_severity['High']     ?? 0;
    this.stats.medium   = s.by_severity['Medium']   ?? 0;
    this.stats.low      = s.by_severity['Low']      ?? 0;
    this.stats.iocCount = s.ioc_count               ?? 0;
    this.sophosTotal    = s.by_source['sophos-central'] ?? 0;
    this.defenderTotal  = s.by_source['ms-defender']    ?? 0;
    this.darktraceTotal = s.by_source['darktrace']      ?? 0;
    this.buildSevBars(s);
    this.buildSourceBars(s);

    // Use accurate server-side aggregations when available
    const bss = s.by_source_severity;
    if (bss?.['sophos-central'])  this.sophosSevBars   = this.buildSevBarsFromMap(bss['sophos-central']);
    if (bss?.['ms-defender'])     this.defenderSevBars = this.buildSevBarsFromMap(bss['ms-defender']);
  }

  private processEvents(events: UnifiedEvent[]): void {
    this.sourceItems   = this.topN(events, e => e.source,   '#F46A1F', 8);
    this.categoryItems = this.topN(events, e => e.category, '#58a6ff', 8);
    this.hostItems     = this.topN(events.filter(e => e.host), e => e.host!, '#3fb950', 7);
    this.userItems     = this.topN(events.filter(e => e.user), e => e.user!, '#7F77DD', 7);
    this.recentEvents  = events.slice(0, 50);
  }

  private processSophosEvents(events: UnifiedEvent[]): void {
    this.sophosEvents   = events.slice(0, 25);
    this.sophosSevBars  = this.buildSevBarsFromEvents(events);
    this.sophosTopHosts = this.topN(events.filter(e => e.host), e => e.host!, '#0072C6', 5);
  }

  private processDefenderEvents(events: UnifiedEvent[]): void {
    this.defenderEvents     = events.slice(0, 25);
    this.defenderSevBars    = this.buildSevBarsFromEvents(events);
    this.defenderCatBars    = this.buildDefenderCatBars(events);
    this.defenderTopDevices = this.topN(events.filter(e => e.host), e => e.host!, '#00B4F0', 5);
    this.defenderTopUsers   = this.topN(events.filter(e => e.user), e => e.user!, '#7cb8e8', 5);
  }

  private buildDefenderCatBars(events: UnifiedEvent[]): SevBar[] {
    // Colour map for known Defender MITRE-based attack categories
    const COLOR: Record<string, string> = {
      'Malware':              '#da3633',
      'Ransomware':           '#da3633',
      'Phishing':             '#d29922',
      'C2 Communication':     '#8b949e',
      'Lateral Movement':     '#7F77DD',
      'Credential Access':    '#58a6ff',
      'Privilege Escalation': '#F46A1F',
      'Defense Evasion':      '#3fb950',
      'Initial Access':       '#d29922',
      'Execution':            '#00B4F0',
      'Exploit':              '#da3633',
      'Discovery':            '#79c0ff',
      'Exfiltration':         '#ff9a5c',
    };
    const counts: Record<string, number> = {};
    events.forEach(e => {
      const cat = e.event_class;
      if (cat && cat !== 'unknown' && cat !== 'Security Alert') {
        counts[cat] = (counts[cat] ?? 0) + 1;
      }
    });
    if (!Object.keys(counts).length) return [];
    const max = Math.max(...Object.values(counts), 1);
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([label, count]) => ({
        label, count,
        color: COLOR[label] ?? '#8b949e',
        pct:   Math.round(count / max * 100),
      }));
  }

  private processDarktraceEvents(events: UnifiedEvent[]): void {
    this.darktraceEvents      = events.slice(0, 25);
    this.darktraceSevBars     = this.buildSevBarsFromEvents(events);
    this.darktraceCatBars     = this.buildCatBarsFromEvents(events);
    this.darktraceTopDevices  = this.topN(events.filter(e => e.host), e => e.host!, '#7F77DD', 5);
  }

  private buildCatBarsFromEvents(events: UnifiedEvent[]): SevBar[] {
    const CATS = [
      { label: 'Suspicious',       color: '#d29922' },
      { label: 'Critical',         color: '#da3633' },
      { label: 'Unusual Activity', color: '#58a6ff' },
      { label: 'Compliance',       color: '#7F77DD' },
      { label: 'Informational',    color: '#3fb950' },
    ];
    const counts: Record<string, number> = {};
    events.forEach(e => { counts[e.event_class] = (counts[e.event_class] ?? 0) + 1; });
    const allKeys = Object.keys(counts);
    const known = new Set(CATS.map(c => c.label));
    // Add any unlisted categories
    allKeys.filter(k => !known.has(k)).forEach(k => CATS.push({ label: k, color: '#8b949e' }));
    const max = Math.max(...CATS.map(c => counts[c.label] ?? 0), 1);
    return CATS
      .filter(c => (counts[c.label] ?? 0) > 0)
      .map(c => ({ label: c.label, color: c.color, count: counts[c.label] ?? 0, pct: Math.round((counts[c.label] ?? 0) / max * 100) }));
  }

  private buildSevBarsFromEvents(events: UnifiedEvent[]): SevBar[] {
    const counts: Record<string, number> = {};
    events.forEach(e => { counts[e.severity] = (counts[e.severity] ?? 0) + 1; });
    return this.buildSevBarsFromMap(counts);
  }

  private buildSevBarsFromMap(map: Record<string, number>): SevBar[] {
    const META = [
      { label: 'Critical', color: '#da3633' },
      { label: 'High',     color: '#d29922' },
      { label: 'Medium',   color: '#58a6ff' },
      { label: 'Low',      color: '#3fb950' },
    ];
    const max = Math.max(...META.map(m => map[m.label] ?? 0), 1);
    return META.map(m => {
      const count = map[m.label] ?? 0;
      return { label: m.label, color: m.color, count, pct: Math.round(count / max * 100) };
    });
  }

  private buildSevBars(s: AlertStats): void {
    const META: { label: string; key: string; color: string }[] = [
      { label: 'Critical', key: 'Critical', color: '#da3633' },
      { label: 'High',     key: 'High',     color: '#d29922' },
      { label: 'Medium',   key: 'Medium',   color: '#58a6ff' },
      { label: 'Low',      key: 'Low',      color: '#3fb950' },
    ];
    const max = Math.max(...META.map(m => s.by_severity[m.key] ?? 0), 1);
    this.sevBars = META.map(m => {
      const count = s.by_severity[m.key] ?? 0;
      return { label: m.label, color: m.color, count, pct: Math.round(count / max * 100) };
    });
  }

  private buildSourceBars(s: AlertStats): void {
    const entries = Object.entries(s.by_source).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const max = entries[0]?.[1] ?? 1;
    this.sourceBars = entries.map(([label, count]) => ({
      label, count, color: this.sourceColor(label), pct: Math.round(count / max * 100)
    }));
  }

  relativeTime(ts: string): string {
    const diff = this.now.getTime() - new Date(ts).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1)   return 'just now';
    if (m < 60)  return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24)  return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }

  sevClass(sev: string): string {
    const map: Record<string, string> = {
      Critical: 'sev-crit', High: 'sev-high', Medium: 'sev-med', Low: 'sev-low'
    };
    return map[sev] ?? 'sev-low';
  }

  sourceColor(src: string): string {
    const map: Record<string, string> = {
      'wazuh':          '#F46A1F',
      'sophos-central': '#0072C6',
      'ms-graph':       '#00B4F0',
      'ms-defender':    '#00B4F0',
      'darktrace':      '#7F77DD',
    };
    return map[src] ?? '#8b949e';
  }

  private topN(events: UnifiedEvent[], key: (e: UnifiedEvent) => string, color: string, n: number): BarItem[] {
    const counts: Record<string, number> = {};
    events.forEach(e => { const k = key(e); counts[k] = (counts[k] ?? 0) + 1; });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, n);
    const max = sorted[0]?.[1] ?? 1;
    return sorted.map(([label, val]) => ({ label, val, max, color }));
  }
}
