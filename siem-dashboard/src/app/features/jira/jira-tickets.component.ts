import { Component, OnInit, OnDestroy, HostListener, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { GatewayService, JiraTicket, JiraAssignee } from '../../core/services/gateway.service';

@Component({
  selector: 'app-jira-tickets',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    MatIconModule, MatButtonModule, MatProgressBarModule,
    MatTooltipModule, MatButtonToggleModule, MatSnackBarModule,
  ],
  templateUrl: './jira-tickets.component.html',
  styleUrl:    './jira-tickets.component.scss',
})
export class JiraTicketsComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();

  tickets:   JiraTicket[]   = [];
  assignees: JiraAssignee[] = [];
  total   = 0;
  loading = false;
  error   = '';

  statusFilter   = 'open';
  severityFilter = '';
  assignedFilter = '';           // '' | 'assigned' | 'unassigned'

  assigningKey:     string | null = null;   // ticket key whose dropdown is open
  assigningLoading  = false;

  constructor(private gateway: GatewayService, private snackBar: MatSnackBar, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.load();
    this.gateway.getJiraAssignees()
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: ({ assignees }) => { this.assignees = assignees; this.cdr.detectChanges(); },
        error: () => {},
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  load(): void {
    this.loading = true;
    this.error   = '';
    this.gateway.getJiraTickets({
      status:      this.statusFilter,
      severity:    this.severityFilter || undefined,
      max_results: 200,
    }).pipe(takeUntil(this.destroy$)).subscribe({
      next: ({ total, tickets }) => {
        this.total   = total;
        this.tickets = tickets ?? [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.error   = err?.error?.detail ?? err?.message ?? 'Failed to load JIRA tickets.';
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  onFilterChange(): void { this.load(); }

  // Called by ShellComponent when this component is re-activated via KEEP_ALIVE.
  onReuse(): void {
    if (this.error || !this.tickets.length || this.loading) {
      this.load();
    }
  }

  // ── Overview stats (computed from loaded tickets) ─────────────────────────
  get overview() {
    const t          = this.tickets;
    const assigned   = t.filter(x => x.assignee !== 'Unassigned').length;
    const unassigned = t.filter(x => x.assignee === 'Unassigned').length;
    const critical   = t.filter(x => x.severity === 'critical').length;
    const high       = t.filter(x => x.severity === 'high').length;
    return { total: t.length, assigned, unassigned, critical, high };
  }

  // ── Client-side assigned/unassigned filter ────────────────────────────────
  get filteredTickets(): JiraTicket[] {
    if (this.assignedFilter === 'assigned')   return this.tickets.filter(t => t.assignee !== 'Unassigned');
    if (this.assignedFilter === 'unassigned') return this.tickets.filter(t => t.assignee === 'Unassigned');
    return this.tickets;
  }

  // ── Assign panel ──────────────────────────────────────────────────────────
  toggleAssignPanel(key: string, event: Event): void {
    event.stopPropagation();
    this.assigningKey = this.assigningKey === key ? null : key;
  }

  assign(ticket: JiraTicket, assignee: JiraAssignee, event: Event): void {
    event.stopPropagation();
    this.assigningLoading = true;
    this.assigningKey     = null;
    this.gateway.assignJiraTicket(ticket.key, assignee.account_id).subscribe({
      next: () => {
        ticket.assignee       = assignee.display_name;
        this.assigningLoading = false;
        this.snackBar.open(`${ticket.key} assigned to ${assignee.display_name}`, 'OK', { duration: 4000 });
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.assigningLoading = false;
        this.snackBar.open(err?.error?.detail ?? 'Failed to assign ticket', 'Dismiss', { duration: 6000 });
        this.cdr.detectChanges();
      },
    });
  }

  @HostListener('document:click')
  closeAssignPanel(): void { this.assigningKey = null; }

  // ── Helpers ───────────────────────────────────────────────────────────────
  severityClass(sev: string): string {
    return ({ critical: 'critical', high: 'high', medium: 'medium', low: 'low' } as Record<string, string>)[sev?.toLowerCase()] ?? '';
  }

  statusClass(category: string): string {
    return ({ done: 'done', indeterminate: 'inprogress', 'new': 'open' } as Record<string, string>)[category?.toLowerCase()] ?? 'open';
  }

  open(url: string): void { window.open(url, '_blank', 'noopener'); }
}
