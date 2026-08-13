import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { GrafanaService, GrafanaDashboard, GrafanaFolder, GrafanaConfig } from '../../core/services/grafana.service';
import { ApiService } from '../../core/services/api.service';
import { debounceTime, distinctUntilChanged, Subject, takeUntil } from 'rxjs';

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
export class CustomDashboardsComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();

  config:     GrafanaConfig | null = null;
  dashboards: GrafanaDashboard[]   = [];
  folderList: GrafanaFolder[]      = [];
  loading     = true;
  searchQuery = '';
  private searchTimer: any;

  // ── Current user ──────────────────────────────────────────────────────────
  currentUser = '';

  // ── Datasource provisioning ───────────────────────────────────────────────
  provisioning     = false;
  provisionResults: any[] | null = null;

  // ── Create form state ─────────────────────────────────────────────────────
  showCreate   = false;
  newTitle     = '';
  newFolderUid = '';
  creating     = false;
  createError  = '';

  // ── Share dialog state ────────────────────────────────────────────────────
  showShare:      boolean            = false;
  shareTarget:    GrafanaDashboard | null = null;
  shareList:      string[]           = [];  // current shared_with working copy
  userQuery       = '';
  userResults:    string[]           = [];
  userSearching   = false;
  sharing         = false;
  private userSearch$ = new Subject<string>();

  constructor(
    private grafana: GrafanaService,
    private api:     ApiService,
    private router:  Router,
    private snack:   MatSnackBar,
    private cdr:     ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.api.get<{ email: string }>('/auth/me')
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next:  me  => { this.currentUser = me.email ?? ''; this.cdr.detectChanges(); },
        error: ()  => {},
      });

    this.grafana.getConfig()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: cfg => {
          this.config  = cfg;
          if (cfg.configured) { this.load(); this.loadFolders(); }
          else                { this.loading = false; }
          this.cdr.detectChanges();
        },
        error: () => { this.loading = false; this.cdr.detectChanges(); },
      });

    this.userSearch$.pipe(debounceTime(300), distinctUntilChanged(), takeUntil(this.destroy$)).subscribe(q => {
      this.fetchUsers(q);
    });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  // ── Dashboard list ────────────────────────────────────────────────────────

  load(q?: string): void {
    this.loading = true;
    this.grafana.listDashboards(q)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next:  d  => { this.dashboards = d ?? []; this.loading = false; this.cdr.detectChanges(); },
        error: () => { this.loading = false; this.cdr.detectChanges(); },
      });
  }

  // Called by ShellComponent when this component is re-activated via KEEP_ALIVE.
  onReuse(): void {
    // Reload if data is absent OR if the spinner was frozen when the component was stored.
    if (this.config?.configured && (!this.dashboards.length || this.loading)) {
      this.load();
    }
  }

  loadFolders(): void {
    this.grafana.listFolders()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next:  f  => { this.folderList = f ?? []; this.cdr.detectChanges(); },
        error: () => {},
      });
  }

  onSearch(): void {
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.load(this.searchQuery.trim() || undefined), 350);
  }

  open(d: GrafanaDashboard): void {
    if (!d.accessible) {
      this.snack.open('You do not have access to this dashboard', '', { duration: 3000 });
      return;
    }
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

  // ── Access helpers ────────────────────────────────────────────────────────

  isOwner(d: GrafanaDashboard): boolean {
    return !!this.currentUser && d.owner === this.currentUser;
  }

  canDelete(d: GrafanaDashboard): boolean {
    return this.isOwner(d);
  }

  // ── Delete ────────────────────────────────────────────────────────────────

  deleteDashboard(d: GrafanaDashboard, e: Event): void {
    e.stopPropagation();
    if (!confirm(`Delete "${d.title}"? This cannot be undone.`)) return;
    this.grafana.deleteDashboard(d.uid).subscribe({
      next: () => {
        this.snack.open(`"${d.title}" deleted`, '', { duration: 3000 });
        this.dashboards = this.dashboards.filter(x => x.uid !== d.uid);
        this.cdr.detectChanges();
      },
      error: err => {
        this.snack.open(err?.error?.detail ?? 'Delete failed', 'Dismiss', { duration: 6000 });
        this.cdr.detectChanges();
      },
    });
  }

  // ── Share dialog ──────────────────────────────────────────────────────────

  openShareDialog(d: GrafanaDashboard, e: Event): void {
    e.stopPropagation();
    this.shareTarget  = d;
    this.shareList    = [...(d.shared_with ?? [])];
    this.userQuery    = '';
    this.userResults  = [];
    this.sharing      = false;
    this.showShare    = true;
  }

  closeShareDialog(): void {
    this.showShare   = false;
    this.shareTarget = null;
  }

  onUserQueryChange(): void {
    this.userSearch$.next(this.userQuery.trim());
  }

  private fetchUsers(q: string): void {
    if (!q) { this.userResults = []; return; }
    this.userSearching = true;
    this.grafana.listUsers(q).subscribe({
      next:  res => { this.userSearching = false; this.userResults = res.users.filter(u => !this.shareList.includes(u)); this.cdr.detectChanges(); },
      error: ()  => { this.userSearching = false; this.userResults = []; this.cdr.detectChanges(); },
    });
  }

  addToShare(email: string): void {
    if (!this.shareList.includes(email)) {
      this.shareList = [...this.shareList, email];
    }
    this.userResults = this.userResults.filter(u => u !== email);
    this.userQuery   = '';
  }

  removeFromShare(email: string): void {
    this.shareList = this.shareList.filter(u => u !== email);
  }

  confirmShare(): void {
    if (!this.shareTarget) return;
    this.sharing = true;
    this.grafana.shareDashboard(this.shareTarget.uid, this.shareList).subscribe({
      next: result => {
        this.sharing = false;
        // Update local state
        const d = this.dashboards.find(x => x.uid === this.shareTarget!.uid);
        if (d) { d.shared_with = result.shared_with; }
        this.snack.open('Sharing updated', '', { duration: 3000 });
        this.closeShareDialog();
        this.cdr.detectChanges();
      },
      error: err => {
        this.sharing = false;
        this.snack.open(err?.error?.detail ?? 'Failed to update sharing', 'Dismiss', { duration: 6000 });
        this.cdr.detectChanges();
      },
    });
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
        this.cdr.detectChanges();
      },
      error: err => {
        this.provisioning     = false;
        this.provisionResults = err?.error?.detail ?? null;
        this.snack.open('Provisioning failed — check the result details', 'Dismiss', { duration: 6000 });
        this.cdr.detectChanges();
      },
    });
  }

  // ── Create dashboard ──────────────────────────────────────────────────────

  toggleCreate(): void {
    this.showCreate = !this.showCreate;
    if (this.showCreate) {
      this.newTitle     = '';
      this.newFolderUid = '';
      this.createError  = '';
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
        this.router.navigate(['/my-dashboards', result.uid], { queryParams: { edit: '1' } });
        this.cdr.detectChanges();
      },
      error: err => {
        this.creating    = false;
        this.createError = err?.error?.detail ?? 'Failed to create dashboard. Check API Gateway logs.';
        this.cdr.detectChanges();
      },
    });
  }
}
