import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { GrafanaService, GrafanaConfig } from '../../../core/services/grafana.service';
import { ApiService } from '../../../core/services/api.service';

@Component({
  selector: 'app-dashboard-view',
  standalone: true,
  imports: [
    CommonModule, MatIconModule, MatButtonModule,
    MatTooltipModule, MatProgressSpinnerModule, MatSnackBarModule,
  ],
  templateUrl: './dashboard-view.component.html',
  styleUrl: './dashboard-view.component.scss',
})
export class DashboardViewComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  config:      GrafanaConfig | null = null;
  meta:        any = null;
  iframeSrc:   SafeResourceUrl | null = null;
  loading      = true;
  deleting     = false;
  editMode     = false;
  accessDenied = false;
  isOwner      = false;
  currentUser  = '';

  uid = '';

  timeRanges = [
    { label: '1h',  from: 'now-1h'  },
    { label: '6h',  from: 'now-6h'  },
    { label: '24h', from: 'now-24h' },
    { label: '7d',  from: 'now-7d'  },
    { label: '30d', from: 'now-30d' },
  ];
  selectedFrom = 'now-24h';

  constructor(
    private route:     ActivatedRoute,
    private router:    Router,
    private grafana:   GrafanaService,
    private api:       ApiService,
    private sanitizer: DomSanitizer,
    private snack:     MatSnackBar,
    private cdr:       ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.uid      = this.route.snapshot.paramMap.get('id') ?? '';
    this.editMode = this.route.snapshot.queryParamMap.get('edit') === '1';
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
          this.config = cfg;
          if (!cfg.configured) { this.loading = false; this.cdr.detectChanges(); return; }
          this.loadMeta();
        },
        error: () => { this.loading = false; this.cdr.detectChanges(); },
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  // Called by ShellComponent when this component is re-activated via KEEP_ALIVE.
  onReuse(): void {
    if (this.config?.configured && (!this.iframeSrc || this.loading)) {
      this.loading = true;
      this.iframeSrc = null;
      this.loadMeta();
    }
  }

  loadMeta(): void {
    this.grafana.getDashboard(this.uid).pipe(takeUntil(this.destroy$)).subscribe({
      next: d => {
        this.meta    = d;
        this.loading = false;
        const owner  = d.siem_owner ?? null;
        this.isOwner = !!owner && !!this.currentUser && owner === this.currentUser;
        this.buildIframe();
        this.cdr.detectChanges();
      },
      error: err => {
        this.loading = false;
        if (err?.status === 403) {
          this.accessDenied = true;
        } else {
          this.buildIframe();
        }
        this.cdr.detectChanges();
      },
    });
  }

  buildIframe(): void {
    if (!this.config?.public_url) return;
    const slug = this.meta?.meta?.slug ?? this.uid;
    const base = `${this.config.public_url}/d/${this.uid}/${slug}?orgId=1`;
    const url  = this.editMode
      ? `${base}&from=${this.selectedFrom}&to=now`           // full toolbar — Grafana edit mode
      : `${base}&kiosk=1&theme=dark&from=${this.selectedFrom}&to=now&refresh=1m`;
    this.iframeSrc = this.sanitizer.bypassSecurityTrustResourceUrl(url);
  }

  toggleEditMode(): void {
    this.editMode = !this.editMode;
    this.buildIframe();
  }

  changeTime(from: string): void {
    this.selectedFrom = from;
    this.buildIframe();
  }

  delete(): void {
    if (!confirm(`Delete dashboard "${this.dashTitle}"? This cannot be undone.`)) return;
    this.deleting = true;
    this.grafana.deleteDashboard(this.uid).subscribe({
      next: () => {
        this.snack.open('Dashboard deleted', '', { duration: 3000 });
        this.router.navigate(['/my-dashboards']);
      },
      error: err => {
        this.deleting = false;
        this.snack.open(err?.error?.detail ?? 'Delete failed', 'Dismiss', { duration: 6000 });
        this.cdr.detectChanges();
      },
    });
  }

  get dashTitle(): string {
    return this.meta?.dashboard?.title ?? this.uid;
  }

  openInGrafana(): void {
    if (!this.config?.public_url || !this.meta) return;
    const slug = this.meta?.meta?.slug ?? this.uid;
    window.open(`${this.config.public_url}/d/${this.uid}/${slug}`, '_blank');
  }

  goBack(): void { this.router.navigate(['/my-dashboards']); }
}
