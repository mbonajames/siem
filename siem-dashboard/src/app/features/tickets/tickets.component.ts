import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { of, interval, Subscription } from 'rxjs';
import { catchError, startWith } from 'rxjs/operators';
import { JiraService } from '../../core/services/jira.service';

interface Toast { msg: string; type: 'ok' | 'err'; }

@Component({
  selector: 'app-tickets',
  standalone: true,
  imports: [CommonModule, FormsModule, MatIconModule],
  templateUrl: './tickets.component.html',
  styleUrl: './tickets.component.scss',
})
export class TicketsComponent implements OnInit, OnDestroy {
  // Ticket list
  issues: any[] = [];
  loading = false;
  total = 0;
  pageSize = 25;
  pageIndex = 0;

  // Filters
  selectedStatus   = '';
  selectedPriority = '';
  statuses   = ['', 'Open', 'In Progress', 'In Review', 'Done', 'Closed'];
  priorities = ['', 'Critical', 'High', 'Medium', 'Low'];

  // Stats
  stats = { open: 0, inProgress: 0, done: 0, critical: 0 };

  // Create form
  showForm = false;
  creating = false;
  form = { summary: '', description: '', priority: 'Medium' };

  // Auto-ticket status
  autoStatus: any = null;

  // Selected issue detail / comments
  selectedIssue: any = null;
  comments: any[] = [];
  commentsLoading = false;
  newComment = '';
  addingComment = false;

  toast: Toast | null = null;
  private toastTimer: any;
  private pollSub: Subscription | null = null;

  constructor(private jira: JiraService) {}

  ngOnInit(): void {
    this.load();
    this.loadAutoStatus();
    this.pollSub = interval(60_000).pipe(startWith(0)).subscribe(() => this.loadAutoStatus());
  }

  ngOnDestroy(): void {
    this.pollSub?.unsubscribe();
    clearTimeout(this.toastTimer);
  }

  // ── Ticket list ─────────────────────────────────────────────────────────────

  load(): void {
    this.loading = true;
    const params: any = { maxResults: this.pageSize, startAt: this.pageIndex * this.pageSize };
    if (this.selectedStatus)   params.status   = this.selectedStatus;
    if (this.selectedPriority) params.priority = this.selectedPriority;
    this.jira.getIssues(params).pipe(catchError(() => of(null))).subscribe(r => {
      this.issues = r?.issues ?? [];
      this.total  = r?.total  ?? 0;
      this.calcStats();
      this.loading = false;
    });
  }

  private calcStats(): void {
    this.stats = {
      open:       this.issues.filter(i => ['open','to do'].includes((i.fields?.status?.name ?? '').toLowerCase())).length,
      inProgress: this.issues.filter(i => (i.fields?.status?.name ?? '').toLowerCase().includes('progress')).length,
      done:       this.issues.filter(i => ['done','closed','resolved'].includes((i.fields?.status?.name ?? '').toLowerCase())).length,
      critical:   this.issues.filter(i => (i.fields?.priority?.name ?? '').toLowerCase() === 'critical').length,
    };
  }

  onFilter(): void { this.pageIndex = 0; this.load(); }

  onPage(dir: 1 | -1): void {
    const next = this.pageIndex + dir;
    if (next < 0 || next * this.pageSize >= this.total) return;
    this.pageIndex = next;
    this.load();
  }

  // ── Create ticket ───────────────────────────────────────────────────────────

  createTicket(): void {
    if (!this.form.summary.trim()) return;
    this.creating = true;
    this.jira.createIssue({
      summary:     this.form.summary,
      description: this.form.description,
      priority:    this.form.priority,
      labels:      ['siem'],
    }).subscribe({
      next: (res) => {
        this.creating = false;
        this.showForm = false;
        this.form = { summary: '', description: '', priority: 'Medium' };
        this.showToast(`Ticket ${res?.key ?? ''} created`, 'ok');
        this.load();
      },
      error: (e) => {
        this.creating = false;
        this.showToast(e?.error?.error ?? 'Create failed', 'err');
      },
    });
  }

  // ── Auto-ticket ─────────────────────────────────────────────────────────────

  loadAutoStatus(): void {
    this.jira.getAutoTicketStatus().pipe(catchError(() => of(null))).subscribe(s => {
      this.autoStatus = s;
    });
  }

  triggerAutoTicket(): void {
    this.jira.triggerAutoTicket().subscribe({
      next: () => {
        this.showToast('Auto-ticket scan triggered — check back in a few seconds', 'ok');
        setTimeout(() => { this.loadAutoStatus(); this.load(); }, 4000);
      },
      error: () => this.showToast('Trigger failed', 'err'),
    });
  }

  // ── Issue detail + comments ─────────────────────────────────────────────────

  selectIssue(issue: any): void {
    if (this.selectedIssue?.key === issue.key) { this.selectedIssue = null; return; }
    this.selectedIssue = issue;
    this.comments = [];
    this.newComment = '';
    this.commentsLoading = true;
    this.jira.getComments(issue.key).pipe(catchError(() => of(null))).subscribe(r => {
      this.comments = r?.comments ?? [];
      this.commentsLoading = false;
    });
  }

  submitComment(): void {
    if (!this.newComment.trim() || !this.selectedIssue) return;
    this.addingComment = true;
    this.jira.addComment(this.selectedIssue.key, this.newComment).subscribe({
      next: () => {
        const saved = this.newComment;
        this.newComment = '';
        this.addingComment = false;
        this.showToast('Comment added', 'ok');
        // re-fetch comments
        this.jira.getComments(this.selectedIssue.key).pipe(catchError(() => of(null))).subscribe(r => {
          this.comments = r?.comments ?? [];
        });
      },
      error: () => { this.addingComment = false; this.showToast('Comment failed', 'err'); },
    });
  }

  openInJira(issue: any): void {
    const self: string = issue?.self ?? '';
    const key: string  = issue?.key  ?? '';
    if (!self || !key) return;
    const base = self.replace(/\/rest\/api\/.*/, '');
    window.open(`${base}/browse/${key}`, '_blank');
  }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  getPriorityClass(p: string): string {
    const m: Record<string, string> = {
      critical: 'pri-critical', high: 'pri-high', medium: 'pri-medium', low: 'pri-low'
    };
    return m[(p ?? '').toLowerCase()] ?? 'pri-low';
  }

  getStatusClass(s: string): string {
    const l = (s ?? '').toLowerCase();
    if (l === 'done' || l === 'closed' || l === 'resolved') return 'st-done';
    if (l.includes('progress')) return 'st-progress';
    if (l.includes('review'))   return 'st-review';
    return 'st-open';
  }

  isAutoTicket(issue: any): boolean {
    return (issue?.fields?.labels ?? []).includes('auto-generated');
  }

  commentText(comment: any): string {
    try {
      const content = comment?.body?.content ?? [];
      return content.flatMap((b: any) => b.content ?? []).map((t: any) => t.text ?? '').join('');
    } catch { return ''; }
  }

  formatDate(ts: string | null): string {
    if (!ts) return '—';
    return new Date(ts).toLocaleString();
  }

  get pages(): number { return Math.ceil(this.total / this.pageSize) || 1; }

  showToast(msg: string, type: 'ok' | 'err'): void {
    clearTimeout(this.toastTimer);
    this.toast = { msg, type };
    this.toastTimer = setTimeout(() => (this.toast = null), 3500);
  }
}
