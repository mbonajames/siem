import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { of, interval, Subscription } from 'rxjs';
import { catchError, startWith } from 'rxjs/operators';
import {
  NessusService, NessusScan, NessusScanDetail,
  NessusVuln, NessusFolder, NessusHistoryEntry,
} from '../../core/services/nessus.service';

interface Toast    { id: number; msg: string; type: 'ok' | 'err'; }
interface ErrEntry { id: number; msg: string; }

const RUNNING_STATUSES = new Set(['running', 'pending', 'resuming']);

@Component({
  selector: 'app-nessus',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, MatIconModule],
  templateUrl: './nessus.component.html',
  styleUrl: './nessus.component.scss',
})
export class NessusComponent implements OnInit, OnDestroy {
  folders: NessusFolder[]  = [];
  selectedFolder: NessusFolder | null = null;
  selectedScan: NessusScanDetail | null = null;
  selectedScanId:     number | null = null;
  selectedHistoryId:  number | null = null;
  loading       = false;
  detailLoading = false;

  exportFormat: 'csv' | 'html' | 'nessus' = 'csv';
  exporting = false;

  showHistory = false;
  vulnFilter: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info' = 'all';
  toast: Toast | null = null;
  errors: ErrEntry[]  = [];

  private toastTimer: any;
  private _nextId  = 0;
  private pollSub: Subscription | null = null;

  constructor(private nessus: NessusService) {}

  ngOnInit(): void {
    this.load();
    this.pollSub = interval(30_000).pipe(startWith(0)).subscribe(() => this.silentRefresh());
  }

  ngOnDestroy(): void {
    this.pollSub?.unsubscribe();
    clearTimeout(this.toastTimer);
  }

  load(): void {
    this.loading = true;
    this.nessus.getFolders().pipe(
      catchError(e => { this.showToast(this.extractError(e), 'err'); return of({ folders: [] }); })
    ).subscribe(r => {
      this.folders = r.folders ?? [];
      if (!this.selectedFolder && this.folders.length) {
        this.selectedFolder = this.folders.find(f => f.type !== 'trash') ?? this.folders[0];
      }
      this.loading = false;
    });
  }

  silentRefresh(): void {
    if (this.errors.length) return;
    this.nessus.getFolders().pipe(
      catchError(e => { this.showToast(this.extractError(e), 'err'); return of({ folders: [] }); })
    ).subscribe(r => {
      this.folders = r.folders ?? [];
      if (this.selectedFolder) {
        this.selectedFolder = this.folders.find(f => f.id === this.selectedFolder!.id) ?? null;
      }
      if (this.selectedScanId) this.loadDetail(this.selectedScanId, this.selectedHistoryId ?? undefined);
    });
  }

  extractError(e: any): string {
    return e?.error?.error ?? e?.error?.detail ?? e?.message ?? 'Could not reach Nessus — check API keys';
  }

  selectFolder(folder: NessusFolder): void {
    this.selectedFolder    = folder;
    this.selectedScan      = null;
    this.selectedScanId    = null;
    this.selectedHistoryId = null;
    this.showHistory       = false;
    this.vulnFilter        = 'all';
  }

  loadDetail(id: number, historyId?: number): void {
    this.selectedScanId    = id;
    this.selectedHistoryId = historyId ?? null;
    this.detailLoading     = true;
    this.nessus.getScan(id, historyId).pipe(catchError(() => of(null))).subscribe(detail => {
      this.selectedScan  = detail;
      this.detailLoading = false;
    });
  }

  loadHistory(entry: NessusHistoryEntry): void {
    if (!this.selectedScanId) return;
    // clicking the already-active entry returns to latest
    if (this.selectedHistoryId === entry.history_id) {
      this.loadDetail(this.selectedScanId);
    } else {
      this.loadDetail(this.selectedScanId, entry.history_id);
    }
  }

  closeDetail(): void {
    this.selectedScan      = null;
    this.selectedScanId    = null;
    this.selectedHistoryId = null;
    this.showHistory       = false;
  }

  exportScan(event: Event): void {
    event.stopPropagation();
    if (!this.selectedScanId || this.exporting) return;
    this.exporting = true;
    this.nessus.exportScan(this.selectedScanId, this.exportFormat).subscribe({
      next: (blob) => {
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `scan_${this.selectedScanId}.${this.exportFormat}`;
        a.click();
        URL.revokeObjectURL(url);
        this.exporting = false;
        this.showToast('Export downloaded', 'ok');
      },
      error: () => {
        this.exporting = false;
        this.showToast('Export failed', 'err');
      },
    });
  }

  isRunning(s: NessusScan): boolean { return RUNNING_STATUSES.has(s.status); }

  get allScans(): NessusScan[] {
    return this.folders.flatMap(f => f.scans);
  }

  get stats() {
    const all = this.allScans;
    return {
      total:     all.length,
      running:   all.filter(s => RUNNING_STATUSES.has(s.status)).length,
      completed: all.filter(s => s.status === 'completed').length,
      folders:   this.folders.length,
    };
  }

  get vulnStats() {
    const vulns = this.selectedScan?.vulnerabilities ?? [];
    const c     = (sev: number) => vulns.filter(v => v.severity === sev).reduce((a, v) => a + v.count, 0);
    const critical = c(4), high = c(3), medium = c(2), low = c(1), info = c(0);
    const total    = critical + high + medium + low + info;
    const pct      = (n: number) => total ? Math.round((n / total) * 100) : 0;
    return { critical, high, medium, low, info, total,
             critPct: pct(critical), highPct: pct(high), medPct: pct(medium),
             lowPct: pct(low), infoPct: pct(info) };
  }

  get filteredVulns(): NessusVuln[] {
    const vulns = this.selectedScan?.vulnerabilities ?? [];
    return this.vulnFilter === 'all' ? vulns : vulns.filter(v => v.severity_label === this.vulnFilter);
  }

  getSevClass(label: string): string { return `sev-${label}`; }
  getStatusClass(s: string): string  { return `status-${s}`; }

  formatDate(ts: number | null): string {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleString();
  }

  showToast(msg: string, type: 'ok' | 'err'): void {
    if (type === 'err') {
      if (!this.errors.some(e => e.msg === msg)) {
        this.errors = [{ id: ++this._nextId, msg }, ...this.errors];
      }
      return;
    }
    clearTimeout(this.toastTimer);
    this.toast      = { id: ++this._nextId, msg, type };
    this.toastTimer = setTimeout(() => (this.toast = null), 2500);
  }

  dismissError(id: number): void    { this.errors = this.errors.filter(e => e.id !== id); }
  dismissAllErrors(): void           { this.errors = []; }
}
