import { Component, NgZone, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { DragDropModule, CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';

import {
  GatewayService, CustomDashboard, DashboardWidget,
  WidgetType, WidgetSize, WIDGET_CATALOG,
} from '../../../core/services/gateway.service';
import { WidgetComponent } from '../widget/widget.component';

@Component({
  selector: 'app-dashboard-view',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatIconModule, MatTooltipModule, MatSnackBarModule, MatProgressBarModule,
    DragDropModule,
    WidgetComponent,
  ],
  templateUrl: './dashboard-view.component.html',
  styleUrl: './dashboard-view.component.scss',
})
export class DashboardViewComponent implements OnInit {
  dashboard: CustomDashboard | null = null;
  loading  = true;
  saving   = false;
  editMode = false;
  showCatalog  = false;
  renamingName = '';
  globalHours  = 24;

  readonly catalog = WIDGET_CATALOG;
  readonly sizeOptions: { value: WidgetSize; label: string }[] = [
    { value: 'quarter',       label: '¼ width'    },
    { value: 'half',          label: '½ width'    },
    { value: 'three-quarter', label: '¾ width'    },
    { value: 'full',          label: 'Full width' },
  ];

  constructor(
    private route:   ActivatedRoute,
    private router:  Router,
    private gateway: GatewayService,
    private snack:   MatSnackBar,
    private ngZone:  NgZone,
  ) {}

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id')!;
    this.gateway.getDashboard(id).subscribe({
      next:  d  => { this.dashboard = d; this.loading = false; },
      error: err => {
        this.loading = false;
        this.snack.open(err?.error?.detail ?? 'Failed to load dashboard', 'Dismiss', { duration: 6000 });
        this.router.navigate(['/my-dashboards']);
      },
    });
  }

  get isOwner(): boolean {
    return !!this.dashboard; // simplified — backend enforces real ownership
  }

  // ── Edit mode ──────────────────────────────────────────────────────────────
  toggleEdit(): void {
    if (this.editMode) {
      this.save();
    } else {
      this.renamingName = this.dashboard?.name ?? '';
      this.editMode = true;
    }
  }

  cancelEdit(): void {
    this.editMode    = false;
    this.showCatalog = false;
  }

  save(): void {
    if (!this.dashboard) return;
    this.saving = true;
    const updates: any = {
      widgets: this.dashboard.widgets,
    };
    if (this.renamingName.trim() && this.renamingName !== this.dashboard.name) {
      updates.name = this.renamingName.trim();
    }
    this.gateway.saveDashboard(this.dashboard.id, updates).subscribe({
      next: d => {
        this.dashboard   = d;
        this.editMode    = false;
        this.showCatalog = false;
        this.saving      = false;
        this.snack.open('Dashboard saved', '', { duration: 2500 });
      },
      error: err => {
        this.saving = false;
        this.snack.open(err?.error?.detail ?? 'Save failed', 'Dismiss', { duration: 6000 });
      },
    });
  }

  // ── Sharing ────────────────────────────────────────────────────────────────
  toggleShare(): void {
    if (!this.dashboard) return;
    const newState = !this.dashboard.shared;
    this.gateway.shareDashboard(this.dashboard.id, newState).subscribe({
      next: d => {
        this.dashboard = d;
        this.snack.open(newState ? 'Dashboard is now shared with everyone' : 'Dashboard is now private', '', { duration: 3000 });
      },
      error: err => this.snack.open(err?.error?.detail ?? 'Share failed', 'Dismiss', { duration: 6000 }),
    });
  }

  // ── Drag & drop ────────────────────────────────────────────────────────────
  onDrop(event: CdkDragDrop<DashboardWidget[]>): void {
    if (!this.dashboard || !this.editMode) return;
    moveItemInArray(this.dashboard.widgets, event.previousIndex, event.currentIndex);
  }

  // ── Widget management ──────────────────────────────────────────────────────
  addWidget(type: WidgetType): void {
    if (!this.dashboard) return;
    const meta = this.catalog.find(c => c.type === type)!;
    const widget: DashboardWidget = {
      id:     crypto.randomUUID(),
      type,
      title:  meta.label,
      size:   meta.defaultSize,
      config: { hours: this.globalHours, limit: 20 },
    };
    this.dashboard.widgets = [...this.dashboard.widgets, widget];
  }

  removeWidget(id: string): void {
    if (!this.dashboard) return;
    this.dashboard.widgets = this.dashboard.widgets.filter(w => w.id !== id);
  }

  setWidgetSize(widget: DashboardWidget, size: WidgetSize): void {
    widget.size = size;
  }

  widgetSizeClass(widget: DashboardWidget): string {
    if (widget.type === 'divider') return 'w-full w-auto';
    const sizeMap: Record<string, string> = {
      quarter: 'w-quarter', half: 'w-half', 'three-quarter': 'w-three-quarter', full: 'w-full',
    };
    const base = sizeMap[widget.size] ?? 'w-half';
    return widget.type === 'text' ? base + ' w-auto' : base;
  }

  widgetHeight(widget: DashboardWidget): string {
    if (widget.type === 'divider' || widget.type === 'text') return 'auto';
    if (widget.config?.height) return `${widget.config.height}px`;
    const defaults: Partial<Record<WidgetType, string>> = {
      'severity-tiles': '160px',
      'stat-card':      '160px',
      'severity-bars':  '230px',
      'source-bars':    '230px',
      'top-hosts':      '230px',
      'top-users':      '230px',
      'source-pie':     '280px',
      'category-pie':   '280px',
      'recent-alerts':  '380px',
      'ioc-summary':    '300px',
    };
    return defaults[widget.type] ?? '300px';
  }

  // ── Resize by drag ──────────────────────────────────────────────────────────
  startResize(event: MouseEvent, widget: DashboardWidget, wrapEl: HTMLElement): void {
    event.preventDefault();
    event.stopPropagation();

    const startY = event.clientY;
    const startH = wrapEl.offsetHeight;
    let currentH = startH;

    const onMove = (e: MouseEvent) => {
      currentH = Math.max(100, startH + (e.clientY - startY));
      wrapEl.style.height = `${currentH}px`;
    };

    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      // Sync final height back into Angular's zone so it's included on next Save
      this.ngZone.run(() => {
        widget.config = { ...widget.config, height: currentH };
      });
    };

    // Run listeners outside Angular's zone for smooth drag performance
    this.ngZone.runOutsideAngular(() => {
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  }

  exportPdf(): void {
    const cleanup = () => {
      document.body.classList.remove('siem-print-dashboard');
      window.removeEventListener('afterprint', cleanup);
    };
    window.addEventListener('afterprint', cleanup);
    document.body.classList.add('siem-print-dashboard');
    window.print();
  }
}
