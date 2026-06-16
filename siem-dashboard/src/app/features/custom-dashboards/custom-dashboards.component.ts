import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { GatewayService, CustomDashboard } from '../../core/services/gateway.service';

@Component({
  selector: 'app-custom-dashboards',
  standalone: true,
  imports: [
    CommonModule, FormsModule, RouterLink,
    MatIconModule, MatTooltipModule, MatProgressBarModule, MatSnackBarModule,
  ],
  templateUrl: './custom-dashboards.component.html',
  styleUrl: './custom-dashboards.component.scss',
})
export class CustomDashboardsComponent implements OnInit {
  dashboards: CustomDashboard[] = [];
  loading      = true;
  creating     = false;
  newName      = '';
  newDesc      = '';
  showCreateForm = false;

  constructor(
    private gateway: GatewayService,
    private router:  Router,
    private snack:   MatSnackBar,
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.gateway.listDashboards().subscribe({
      next:  ({ dashboards }) => { this.dashboards = dashboards; this.loading = false; },
      error: () => { this.loading = false; },
    });
  }

  create(): void {
    if (!this.newName.trim()) return;
    this.creating = true;
    this.gateway.createDashboard(this.newName.trim(), this.newDesc.trim()).subscribe({
      next: d => {
        this.creating      = false;
        this.showCreateForm = false;
        this.newName       = '';
        this.newDesc       = '';
        this.router.navigate(['/my-dashboards', d.id]);
      },
      error: err => {
        this.creating = false;
        this.snack.open(err?.error?.detail ?? 'Create failed', 'Dismiss', { duration: 6000 });
      },
    });
  }

  delete(d: CustomDashboard, e: Event): void {
    e.stopPropagation();
    if (!confirm(`Delete "${d.name}"? This cannot be undone.`)) return;
    this.gateway.deleteDashboard(d.id).subscribe({
      next:  () => this.dashboards = this.dashboards.filter(x => x.id !== d.id),
      error: err => this.snack.open(err?.error?.detail ?? 'Delete failed', 'Dismiss', { duration: 6000 }),
    });
  }

  myDashboards(): CustomDashboard[] { return this.dashboards.filter(d => !d.shared || this.isOwner(d)); }
  sharedByOthers(): CustomDashboard[] { return this.dashboards.filter(d => d.shared && !this.isOwner(d)); }

  isOwner(d: CustomDashboard): boolean {
    // We don't expose the current user's ID from the JWT on the frontend,
    // so we rely on the back end to return only this user's owned + shared ones.
    // We tag owner by showing an edit button only if the dashboard appears in "mine".
    return true; // simplified — ownership enforced by backend on save/delete
  }

  widgetSummary(d: CustomDashboard): string {
    const c = d.widgets?.length ?? 0;
    return c === 0 ? 'Empty' : `${c} widget${c === 1 ? '' : 's'}`;
  }

  timeAgo(ts: string): string {
    const m = Math.floor((Date.now() - new Date(ts).getTime()) / 60000);
    if (m < 1)  return 'just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }
}
