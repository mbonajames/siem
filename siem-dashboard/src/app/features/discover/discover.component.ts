import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import {
  WazuhDashboardService,
  DiscoverHit,
  DiscoverResult,
} from '../../core/services/wazuh-dashboard.service';

interface Source {
  id:    string;
  label: string;
  query: string;
  color: string;
}

interface TimeRange {
  label: string;
  from:  string;
}

interface QuickSearch {
  label: string;
  query: string;
  icon:  string;
}

const DEFAULT_COLUMNS = ['@timestamp', 'agent.name', 'rule.level', 'rule.description', 'rule.groups'];

@Component({
  selector: 'app-discover',
  standalone: true,
  imports: [CommonModule, FormsModule, MatIconModule, MatTooltipModule, MatProgressSpinnerModule],
  templateUrl: './discover.component.html',
  styleUrl: './discover.component.scss',
})
export class DiscoverComponent implements OnInit {
  // Search state
  result:      DiscoverResult | null = null;
  loading      = false;
  error        = '';
  page         = 0;
  PAGE_SIZE    = 50;
  expandedRow: number | null = null;

  // Filters
  customQuery  = '';
  activeSource = 'all';
  activeTime   = 'now-24h';

  // Field sidebar
  allFields:       string[] = [];
  filteredFields:  string[] = [];
  selectedColumns: string[] = [...DEFAULT_COLUMNS];
  fieldSearch      = '';
  fieldsLoading    = true;
  sidebarCollapsed = false;

  sources: Source[] = [
    { id: 'all',       label: 'All Sources',  query: '',                                              color: '#F46A1F' },
    { id: 'sophos',    label: 'Sophos',       query: 'rule.groups:sophos',                            color: '#16a34a' },
    { id: 'defender',  label: 'Defender',     query: 'data.integration:"ms-defender"',                color: '#dc2626' },
    { id: 'darktrace', label: 'Darktrace',    query: 'rule.groups:darktrace',                         color: '#7c3aed' },
    { id: 'wazuh',     label: 'Wazuh Native', query: 'NOT rule.groups:sophos AND NOT rule.groups:darktrace AND NOT data.integration:"ms-defender"', color: '#d97706' },
  ];

  timeRanges: TimeRange[] = [
    { label: '1h',  from: 'now-1h'  },
    { label: '6h',  from: 'now-6h'  },
    { label: '24h', from: 'now-24h' },
    { label: '7d',  from: 'now-7d'  },
    { label: '30d', from: 'now-30d' },
  ];

  quickSearches: QuickSearch[] = [
    { label: 'High Severity',  query: 'rule.level:[12 TO 15]',                                           icon: 'priority_high'  },
    { label: 'DLP Violations', query: 'data.sophos.group:"DATA_LOSS_PREVENTION"',                        icon: 'file_copy'      },
    { label: 'Threats',        query: 'data.sophos.group:"THREAT"',                                      icon: 'bug_report'     },
    { label: 'IOC Hits',       query: 'rule.groups:misp OR rule.groups:ioc OR rule.groups:threat_intel',  icon: 'gpp_bad'        },
    { label: 'Auth Events',    query: 'rule.groups:authentication_success OR rule.groups:authentication_failed', icon: 'login'   },
    { label: 'File Changes',   query: 'rule.groups:syscheck',                                            icon: 'folder_open'    },
    { label: 'Config Changes', query: 'rule.groups:config_changed',                                      icon: 'tune'           },
    { label: 'Phishing',       query: 'anomaly_score:[65 TO 100]',                                       icon: 'phishing'       },
  ];

  constructor(private svc: WazuhDashboardService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadFields();
    this.search();
  }

  onReuse(): void {
    if (!this.result || this.loading || this.error) {
      this.search();
    }
  }

  // ── Field sidebar ──────────────────────────────────────────────────────────

  loadFields(): void {
    this.fieldsLoading = true;
    this.svc.getFields().subscribe({
      next: r => {
        this.allFields      = r.fields;
        this.fieldsLoading  = false;
        this.applyFieldSearch();
        this.cdr.detectChanges();
      },
      error: () => { this.fieldsLoading = false; this.cdr.detectChanges(); },
    });
  }

  applyFieldSearch(): void {
    const q = this.fieldSearch.toLowerCase();
    this.filteredFields = q
      ? this.allFields.filter(f => f.toLowerCase().includes(q))
      : this.allFields;
  }

  isSelected(field: string): boolean {
    return this.selectedColumns.includes(field);
  }

  toggleField(field: string): void {
    if (this.isSelected(field)) {
      if (this.selectedColumns.length === 1) return; // keep at least one
      this.selectedColumns = this.selectedColumns.filter(f => f !== field);
    } else {
      this.selectedColumns = [...this.selectedColumns, field];
    }
  }

  removeColumn(field: string): void {
    if (this.selectedColumns.length === 1) return;
    this.selectedColumns = this.selectedColumns.filter(f => f !== field);
  }

  resetColumns(): void {
    this.selectedColumns = [...DEFAULT_COLUMNS];
  }

  get availableFields(): string[] {
    return this.filteredFields.filter(f => !this.isSelected(f));
  }

  // ── Search ─────────────────────────────────────────────────────────────────

  setSource(id: string): void {
    this.activeSource = id;
    this.customQuery  = '';
    this.page         = 0;
    this.search();
  }

  setTime(from: string): void {
    this.activeTime = from;
    this.page       = 0;
    this.search();
  }

  runQuick(q: QuickSearch): void {
    this.customQuery  = q.query;
    this.activeSource = 'all';
    this.page         = 0;
    this.search();
  }

  apply(): void {
    this.activeSource = 'all';
    this.page         = 0;
    this.search();
  }

  nextPage(): void { this.page++; this.search(); }
  prevPage(): void { if (this.page > 0) { this.page--; this.search(); } }

  toggleRow(i: number): void {
    this.expandedRow = this.expandedRow === i ? null : i;
  }

  search(): void {
    const effectiveQuery = this.customQuery.trim()
      || (this.sources.find(s => s.id === this.activeSource)?.query ?? '');

    this.loading     = true;
    this.error       = '';
    this.expandedRow = null;

    this.svc.search({
      query:     effectiveQuery,
      time_from: this.activeTime,
      size:      this.PAGE_SIZE,
      offset:    this.page * this.PAGE_SIZE,
    }).subscribe({
      next:  r  => { this.result = r; this.loading = false; this.cdr.detectChanges(); },
      error: e  => { this.error = e?.error?.detail ?? 'Search failed'; this.loading = false; this.cdr.detectChanges(); },
    });
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  get totalPages(): number {
    return Math.ceil((this.result?.total ?? 0) / this.PAGE_SIZE);
  }

  get startIndex(): number { return this.page * this.PAGE_SIZE + 1; }
  get endIndex():   number { return Math.min((this.page + 1) * this.PAGE_SIZE, this.result?.total ?? 0); }

  levelClass(level: number | undefined): string {
    if (!level)      return 'lvl-low';
    if (level >= 12) return 'lvl-critical';
    if (level >= 7)  return 'lvl-high';
    if (level >= 4)  return 'lvl-medium';
    return 'lvl-low';
  }

  fmt(ts: string | undefined): string {
    if (!ts) return '—';
    return new Date(ts).toLocaleString('en-GB', { hour12: false });
  }

  cellValue(hit: DiscoverHit, field: string): string {
    const parts = field.split('.');
    let val: any = hit;
    for (const p of parts) {
      if (val == null) return '—';
      val = val[p];
    }
    if (val == null) return '—';
    if (Array.isArray(val)) return val.slice(0, 2).join(', ');
    return String(val);
  }

  json(hit: DiscoverHit): string {
    return JSON.stringify(hit, null, 2);
  }

  colLabel(field: string): string {
    const last = field.split('.').pop() ?? field;
    return last.replace(/_/g, ' ');
  }
}
