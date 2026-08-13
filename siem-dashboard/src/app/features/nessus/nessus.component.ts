import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { BaseChartDirective } from 'ng2-charts';
import { Chart, registerables, ChartData, ChartOptions } from 'chart.js';
import { of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import {
  NessusService,
  VulnScanSummary, VulnScan, VulnFinding, VulnTrendPoint, ScanGroup,
} from '../../core/services/nessus.service';
import { AuthService } from '../../core/services/auth.service';

Chart.register(...registerables);

const QUARTERS     = ['Q1', 'Q2', 'Q3', 'Q4'];
const QUARTER_ORDER: Record<string, number> = { Q1: 1, Q2: 2, Q3: 3, Q4: 4 };

interface AggTrendPoint {
  quarter: string; year: number;
  critical: number; high: number; medium: number; low: number;
}
interface Toast { id: number; msg: string; type: 'ok' | 'err'; }

@Component({
  selector: 'app-nessus',
  standalone: true,
  imports: [CommonModule, FormsModule, MatIconModule, BaseChartDirective],
  templateUrl: './nessus.component.html',
  styleUrl: './nessus.component.scss',
})
export class NessusComponent implements OnInit, OnDestroy {
  readonly quarters = QUARTERS;

  // ── Tab ───────────────────────────────────────────────────────────────────
  activeTab: 'scans' | 'analysis' | 'trends' = 'scans';

  // ── Scan list ─────────────────────────────────────────────────────────────
  scans:       VulnScanSummary[] = [];
  scanGroups:  ScanGroup[]       = [];
  scansLoading = false;
  filterQ      = '';
  filterYear   = '';

  // ── Upload ────────────────────────────────────────────────────────────────
  showUpload   = false;
  uploadQ      = 'Q1';
  uploadYear   = new Date().getFullYear();
  uploadType: 'internal' | 'external' = 'internal';
  uploadBranch = '';
  uploadFiles: File[] = [];
  uploading    = false;

  // ── Edit modal ────────────────────────────────────────────────────────────
  showEdit   = false;
  editTarget: VulnScanSummary | null = null;
  editBranch = '';
  editQ      = 'Q1';
  editYear   = new Date().getFullYear();
  editType: 'internal' | 'external' = 'internal';
  editSaving = false;

  // ── Analysis ──────────────────────────────────────────────────────────────
  selectedScan:    VulnScan | null = null;
  analysisLoading  = false;
  sevFilter: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info' = 'all';
  expandedFinding: string | null = null;

  // ── Trends ────────────────────────────────────────────────────────────────
  trendsLoading  = false;
  rawTrends:     AggTrendPoint[] = [];
  trendYears:    number[]        = [];
  trendYear      = new Date().getFullYear();
  trendChart:    ChartData<'line'> | null = null;

  // ── Toasts / errors ───────────────────────────────────────────────────────
  toast:  Toast | null = null;
  errors: Toast[]      = [];
  private _id = 0;
  private toastTimer: any;

  readonly lineOpts: ChartOptions<'line'> = {
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top', labels: { color: '#9ca3af', boxWidth: 12, font: { size: 11 } } },
      tooltip: { mode: 'index', intersect: false },
    },
    scales: {
      x: { ticks: { color: '#9ca3af', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,.06)' } },
      y: { ticks: { color: '#9ca3af', font: { size: 11 }, stepSize: 1 },
           grid: { color: 'rgba(255,255,255,.06)' }, beginAtZero: true },
    },
  };

  get isSocAdmin(): boolean { return this.auth.isAdmin(); }

  constructor(private svc: NessusService, private auth: AuthService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void  { this.loadScans(); }
  ngOnDestroy(): void { clearTimeout(this.toastTimer); }

  onReuse(): void {
    if (!this.scans.length || this.scansLoading) this.loadScans();
  }

  // ── Navigation ────────────────────────────────────────────────────────────
  openTab(tab: typeof this.activeTab): void {
    this.activeTab = tab;
    if (tab === 'trends' && !this.rawTrends.length) this.loadTrends();
  }

  // ── Scan list ─────────────────────────────────────────────────────────────
  loadScans(): void {
    this.scansLoading = true;
    this.svc.listScans().pipe(catchError(e => {
      this.pushError(this.extractErr(e)); return of({ scans: [] });
    })).subscribe(r => {
      this.scans      = r.scans ?? [];
      this.scanGroups = NessusService.groupScans(this.scans);
      this.scansLoading = false;
      this.cdr.detectChanges();
    });
  }

  get filteredGroups(): ScanGroup[] {
    return this.scanGroups.filter(g =>
      (!this.filterQ    || g.quarter === this.filterQ)   &&
      (!this.filterYear || g.year    === +this.filterYear)
    );
  }

  get uniqueYears(): number[] { return [...new Set(this.scans.map(s => s.year))].sort((a,b) => b - a); }

  selectScan(s: VulnScanSummary): void {
    this.analysisLoading = true;
    this.activeTab       = 'analysis';
    this.sevFilter       = 'all';
    this.expandedFinding = null;
    this.svc.getScan(s.scan_id).pipe(catchError(e => {
      this.pushError(this.extractErr(e)); this.analysisLoading = false; return of(null);
    })).subscribe(scan => { this.selectedScan = scan; this.analysisLoading = false; this.cdr.detectChanges(); });
  }

  openEditModal(s: VulnScanSummary, e: Event): void {
    e.stopPropagation();
    this.editTarget = s;
    this.editBranch = s.branch ?? '';
    this.editQ      = s.quarter;
    this.editYear   = s.year;
    this.editType   = s.scan_type;
    this.showEdit   = true;
  }

  submitEdit(): void {
    if (!this.editTarget || this.editSaving) return;
    this.editSaving = true;
    this.svc.updateScanMeta(this.editTarget.scan_id, {
      branch:    this.editBranch || undefined,
      quarter:   this.editQ,
      year:      this.editYear,
      scan_type: this.editType,
    }).pipe(catchError(e => {
      this.pushError(this.extractErr(e)); this.editSaving = false; return of(null);
    })).subscribe(updated => {
      this.editSaving = false;
      if (!updated) { this.cdr.detectChanges(); return; }
      this.showEdit  = false;
      this.scans      = this.scans.map(s => s.scan_id === updated.scan_id ? updated : s);
      this.scanGroups = NessusService.groupScans(this.scans);
      if (this.selectedScan?.scan_id === updated.scan_id) {
        this.selectedScan = { ...this.selectedScan, ...updated };
      }
      this.rawTrends = [];
      this.showOk('Scan updated');
      this.cdr.detectChanges();
    });
  }

  deleteScan(s: VulnScanSummary, event: Event): void {
    event.stopPropagation();
    if (!confirm(`Delete "${s.filename}" (${s.quarter} ${s.year} ${s.scan_type})?`)) return;
    this.svc.deleteScan(s.scan_id).pipe(catchError(e => {
      this.pushError(this.extractErr(e)); return of(null);
    })).subscribe(() => {
      this.scans      = this.scans.filter(x => x.scan_id !== s.scan_id);
      this.scanGroups = NessusService.groupScans(this.scans);
      if (this.selectedScan?.scan_id === s.scan_id) this.selectedScan = null;
      this.rawTrends  = [];
      this.showOk('Scan deleted');
      this.cdr.detectChanges();
    });
  }

  // ── Upload ────────────────────────────────────────────────────────────────
  onFileChange(event: Event): void {
    const inp = event.target as HTMLInputElement;
    this.uploadFiles = inp.files ? Array.from(inp.files) : [];
  }

  removeFile(i: number): void {
    this.uploadFiles = this.uploadFiles.filter((_, idx) => idx !== i);
  }

  submitUpload(): void {
    if (!this.uploadFiles.length || this.uploading) return;
    this.uploading = true;
    this.svc.uploadScans(this.uploadFiles, this.uploadQ,
                         this.uploadYear, this.uploadType, this.uploadBranch || undefined)
      .pipe(catchError(e => { this.pushError(this.extractErr(e)); this.uploading = false; return of(null); }))
      .subscribe(res => {
        this.uploading  = false;
        this.showUpload = false;
        this.uploadFiles = [];
        if (!res) { this.cdr.detectChanges(); return; }

        for (const err of (res.errors ?? [])) {
          this.pushError(`${err.filename}: ${err.error}`);
        }

        const newScans = res.uploaded ?? [];
        if (newScans.length) {
          this.scans        = [...newScans, ...this.scans];
          this.scanGroups   = NessusService.groupScans(this.scans);
          this.rawTrends    = [];
          this.uploadBranch = '';
          this.showOk(`Uploaded ${newScans.length} file(s)` +
            (res.errors?.length ? ` (${res.errors.length} failed)` : ''));
        }
        this.cdr.detectChanges();
      });
  }

  // ── Report download ───────────────────────────────────────────────────────
  downloadReport(g: ScanGroup, type: 'technical' | 'executive'): void {
    window.open(this.svc.reportUrl(g.year, g.quarter, type), '_blank');
  }

  // ── Analysis ──────────────────────────────────────────────────────────────
  get vulnSummary() {
    const s = this.selectedScan?.summary;
    if (!s) return { critical:0, high:0, medium:0, low:0, info:0, total:0, pct: (_:number)=>0 };
    const total = s.critical + s.high + s.medium + s.low + s.info;
    return { ...s, total, pct: (n: number) => total ? Math.round((n / total) * 100) : 0 };
  }

  get filteredFindings(): VulnFinding[] {
    const findings = this.selectedScan?.findings ?? [];
    const sorted   = [...findings].sort((a, b) => b.severity_num - a.severity_num);
    return this.sevFilter === 'all' ? sorted : sorted.filter(f => f.severity === this.sevFilter);
  }

  toggleFinding(id: string): void {
    this.expandedFinding = this.expandedFinding === id ? null : id;
  }

  sevClass(sev: string): string { return `sev-${sev}`; }

  // ── Trends ────────────────────────────────────────────────────────────────
  loadTrends(): void {
    this.trendsLoading = true;
    this.svc.getTrends().pipe(catchError(e => {
      this.pushError(this.extractErr(e)); return of({ trends: [] });
    })).subscribe(r => {
      this.rawTrends  = this._aggregate(r.trends ?? []);
      this.trendYears = [...new Set(this.rawTrends.map(t => t.year))].sort((a,b) => b - a);
      if (this.trendYears.length) this.trendYear = this.trendYears[0];
      this._buildChart();
      this.trendsLoading = false;
      this.cdr.detectChanges();
    });
  }

  get hasData(): boolean { return this.rawTrends.length > 0; }

  private _buildChart(): void {
    const pts = [...this.rawTrends]
      .sort((a, b) => a.year !== b.year
        ? a.year - b.year : QUARTER_ORDER[a.quarter] - QUARTER_ORDER[b.quarter]);

    const labels = pts.map(p => `${p.quarter} ${p.year}`);
    this.trendChart = {
      labels,
      datasets: [
        { label: 'Critical', data: pts.map(p => p.critical), borderColor: '#ef4444', backgroundColor: '#ef444422', tension: 0.35, pointRadius: 4, fill: false },
        { label: 'High',     data: pts.map(p => p.high),     borderColor: '#f59e0b', backgroundColor: '#f59e0b22', tension: 0.35, pointRadius: 4, fill: false },
        { label: 'Medium',   data: pts.map(p => p.medium),   borderColor: '#3b82f6', backgroundColor: '#3b82f622', tension: 0.35, pointRadius: 4, fill: false },
      ],
    } as ChartData<'line'>;
  }

  private _aggregate(raw: VulnTrendPoint[]): AggTrendPoint[] {
    const map = new Map<string, AggTrendPoint>();
    for (const t of raw) {
      const key = `${t.quarter}||${t.year}`;
      const cur = map.get(key) ??
        { quarter: t.quarter, year: t.year, critical: 0, high: 0, medium: 0, low: 0 };
      cur.critical += t.summary.critical;
      cur.high     += t.summary.high;
      cur.medium   += t.summary.medium;
      cur.low      += t.summary.low;
      map.set(key, cur);
    }
    return [...map.values()];
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  extractErr(e: any): string {
    return e?.error?.detail ?? e?.error?.error ?? e?.message ?? 'Unknown error';
  }

  showOk(msg: string): void {
    clearTimeout(this.toastTimer);
    this.toast      = { id: ++this._id, msg, type: 'ok' };
    this.toastTimer = setTimeout(() => (this.toast = null), 3500);
  }

  pushError(msg: string): void {
    const str = typeof msg === 'string' ? msg : JSON.stringify(msg);
    if (!this.errors.some(e => e.msg === str))
      this.errors = [{ id: ++this._id, msg: str, type: 'err' }, ...this.errors];
  }

  dismissError(id: number): void { this.errors = this.errors.filter(e => e.id !== id); }
  dismissAllErrors(): void        { this.errors = []; }

  formatDate(iso: string): string {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  groupKey(g: ScanGroup): string { return `${g.year}|${g.quarter}`; }

  totalCritical(g: ScanGroup): number {
    return [...g.internal, ...g.external].reduce((s, x) => s + (x.summary.critical ?? 0), 0);
  }
  totalHigh(g: ScanGroup): number {
    return [...g.internal, ...g.external].reduce((s, x) => s + (x.summary.high ?? 0), 0);
  }
  totalMedium(g: ScanGroup): number {
    return [...g.internal, ...g.external].reduce((s, x) => s + (x.summary.medium ?? 0), 0);
  }
  totalLow(g: ScanGroup): number {
    return [...g.internal, ...g.external].reduce((s, x) => s + (x.summary.low ?? 0), 0);
  }
}
