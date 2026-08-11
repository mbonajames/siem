import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { GrafanaService, GrafanaDashboard, GrafanaFolder, GrafanaConfig } from '../../core/services/grafana.service';

@Component({
  selector: 'app-custom-dashboards',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatIconModule, MatTooltipModule, MatProgressSpinnerModule, MatSnackBarModule,
  ],
  templateUrl: './custom-dashboards.component.html',
  styleUrl: './custom-dashboards.component.scss',
})
export class CustomDashboardsComponent implements OnInit {
  config:     GrafanaConfig | null = null;
  dashboards: GrafanaDashboard[]   = [];
  folderList: GrafanaFolder[]      = [];
  loading     = true;
  searchQuery = '';
  private searchTimer: any;

  // ── Datasource provisioning ───────────────────────────────────────────────
  provisioning     = false;
  provisionResults: any[] | null = null;

  // ── Create form state ─────────────────────────────────────────────────────
  showCreate  = false;
  newTitle    = '';
  newFolderUid = '';
  creating    = false;
  createError = '';

  constructor(
    private grafana: GrafanaService,
    private router:  Router,
    private snack:   MatSnackBar,
  ) {}

  ngOnInit(): void {
    this.grafana.getConfig().subscribe({
      next:  cfg => { this.config = cfg; if (cfg.configured) { this.load(); this.loadFolders(); } else { this.loading = false; } },
      error: ()  => { this.loading = false; },
    });
  }

  load(q?: string): void {
    this.loading = true;
    this.grafana.listDashboards(q).subscribe({
      next:  d  => { this.dashboards = d; this.loading = false; },
      error: () => { this.loading = false; },
    });
  }

  loadFolders(): void {
    this.grafana.listFolders().subscribe({
      next:  f  => { this.folderList = f; },
      error: () => {},
    });
  }

  onSearch(): void {
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.load(this.searchQuery.trim() || undefined), 350);
  }

  open(d: GrafanaDashboard): void {
    this.router.navigate(['/my-dashboards', d.uid]);
  }

  folders(): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const d of this.dashboards) {
      const f = d.folderTitle ?? 'General';
      if (!seen.has(f)) { seen.add(f); out.push(f); }
    }
    return out;
  }

  byFolder(folder: string): GrafanaDashboard[] {
    return this.dashboards.filter(d => (d.folderTitle ?? 'General') === folder);
  }

  openInGrafana(d: GrafanaDashboard, e: Event): void {
    e.stopPropagation();
    if (this.config?.public_url) {
      window.open(`${this.config.public_url}${d.url}`, '_blank');
    }
  }

  // ── Datasource provisioning ───────────────────────────────────────────────
  provisionDatasources(): void {
    this.provisioning     = true;
    this.provisionResults = null;
    this.grafana.provisionDatasources().subscribe({
      next: res => {
        this.provisioning     = false;
        this.provisionResults = res.results;
        this.snack.open('Data sources provisioned — ready to use in dashboards', '', { duration: 4000 });
      },
      error: err => {
        this.provisioning     = false;
        this.provisionResults = err?.error?.detail ?? null;
        this.snack.open(
          'Provisioning failed — check the result details',
          'Dismiss', { duration: 6000 },
        );
      },
    });
  }

  // ── Create dashboard ──────────────────────────────────────────────────────
  toggleCreate(): void {
    this.showCreate = !this.showCreate;
    if (this.showCreate) {
      this.newTitle    = '';
      this.newFolderUid = '';
      this.createError = '';
    }
  }

  cancelCreate(): void {
    this.showCreate  = false;
    this.createError = '';
  }

  confirmCreate(): void {
    const title = this.newTitle.trim();
    if (!title) { this.createError = 'Dashboard title is required.'; return; }

    this.creating    = true;
    this.createError = '';

    const payload: any = {
      dashboard: {
        id: null, uid: null,
        title,
        tags: [],
        timezone: 'browser',
        schemaVersion: 39,
        panels: [],
        refresh: '1m',
      },
      overwrite: false,
      message: 'Created via Hope-Armor SIEM',
    };
    if (this.newFolderUid) { payload.folderUid = this.newFolderUid; }

    this.grafana.saveDashboard(payload).subscribe({
      next: result => {
        this.creating   = false;
        this.showCreate = false;
        this.snack.open(`Dashboard "${title}" created`, '', { duration: 3000 });
        // Open in edit mode so the user can add panels right away
        this.router.navigate(['/my-dashboards', result.uid], { queryParams: { edit: '1' } });
      },
      error: err => {
        this.creating    = false;
        this.createError = err?.error?.detail ?? 'Failed to create dashboard. Check API Gateway logs.';
      },
    });
  }
}
