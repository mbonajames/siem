import { Component, OnInit, inject, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ActivatedRoute } from '@angular/router';
import { SettingsService, AuditLog } from '../../core/services/settings.service';
import { AuthService } from '../../core/services/auth.service';
import { NotificationsService, NotificationConfig } from '../../core/services/notifications.service';
import { ConnectorsComponent } from '../connectors/connectors.component';

const ACTION_ICONS: Record<string, string> = {
  login:                       'login',
  create_dashboard:            'dashboard_customize',
  delete_dashboard:            'delete',
  share_dashboard:             'public',
  create_jira_ticket:          'confirmation_number',
  save_integration_settings:   'settings',
  upload_vulnerability_scan:   'upload_file',
  delete_vulnerability_scan:   'delete_sweep',
  endpoint_action:             'device_hub',
  defender_ingest:             'security_update',
};

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [
    CommonModule, FormsModule, MatIconModule, MatButtonModule,
    MatProgressSpinnerModule, MatTooltipModule, MatSnackBarModule,
    ConnectorsComponent,
  ],
  templateUrl: './settings.component.html',
  styleUrl: './settings.component.scss',
})
export class SettingsComponent implements OnInit {
  readonly auth = inject(AuthService);

  // ── Notifications ──────────────────────────────────────────────────────────
  notifConfig: NotificationConfig = { enabled: false, min_severity: 'High', poll_interval_secs: 120 };
  notifLoading    = false;
  notifSaving     = false;
  notifTesting    = false;
  notifTestResult = '';
  showWebhook     = false;

  auditLogs:   AuditLog[] = [];
  auditTotal   = 0;
  auditLoading = true;
  auditError   = '';
  auditHours   = 24;
  auditOutcome = '';
  auditSearch  = '';

  /** true → /settings view; false → /activity-log view — set by the matched route's data, not guessed from the URL */
  readonly isSettingsView: boolean;

  constructor(
    private settingsService:   SettingsService,
    private notifSvc:          NotificationsService,
    private snackBar:          MatSnackBar,
    route:                     ActivatedRoute,
    private cdr:               ChangeDetectorRef,
  ) {
    this.isSettingsView = route.snapshot.data['isSettingsView'] === true;
  }

  ngOnInit(): void {
    this.loadAuditLogs();
    this.loadNotifConfig();
  }

  loadNotifConfig(): void {
    this.notifLoading = true;
    this.notifSvc.getConfig().pipe(catchError(() => of(null))).subscribe(cfg => {
      if (cfg) this.notifConfig = cfg;
      this.notifLoading = false;
      this.cdr.detectChanges();
    });
  }

  saveNotifConfig(): void {
    this.notifSaving = true;
    const payload = { ...this.notifConfig };
    if (!payload.teams_webhook_url) delete payload.teams_webhook_url;
    this.notifSvc.saveConfig(payload).pipe(catchError(() => of(null))).subscribe(res => {
      this.notifSaving = false;
      this.snackBar.open(res ? 'Notification settings saved' : 'Save failed', '', { duration: 3000 });
      this.cdr.detectChanges();
    });
  }

  testNotification(): void {
    this.notifTesting    = true;
    this.notifTestResult = '';
    this.notifSvc.sendTest().pipe(catchError(() => of(null))).subscribe(res => {
      this.notifTesting    = false;
      this.notifTestResult = res ? 'Test message sent to Teams!' : 'Test failed — check webhook URL.';
      this.cdr.detectChanges();
    });
  }

  deletingId  = '';
  clearing    = false;

  resolveUser(log: AuditLog): string {
    if (log.user && log.user !== 'anonymous') return log.user;
    return this.auth.user?.email ?? this.auth.user?.name ?? 'anonymous';
  }

  deleteLog(log: AuditLog): void {
    if (this.deletingId) return;
    this.deletingId = log.id;
    this.settingsService.deleteAuditLog(log.id).pipe(
      catchError(() => of(null))
    ).subscribe(res => {
      this.deletingId = '';
      if (res !== null) {
        this.auditLogs  = this.auditLogs.filter(l => l.id !== log.id);
        this.auditTotal = Math.max(0, this.auditTotal - 1);
      }
      this.cdr.detectChanges();
    });
  }

  clearAll(): void {
    if (!confirm('Delete all audit log entries? This cannot be undone.')) return;
    this.clearing = true;
    this.settingsService.clearAuditLogs().pipe(
      catchError(() => of(null))
    ).subscribe(() => {
      this.clearing   = false;
      this.auditLogs  = [];
      this.auditTotal = 0;
      this.cdr.detectChanges();
    });
  }

  loadAuditLogs(): void {
    this.auditLoading = true;
    this.auditError   = '';
    this.settingsService.getAuditLogs({
      limit:   200,
      hours:   this.auditHours,
      outcome: this.auditOutcome || undefined,
    }).pipe(catchError(() => of(null))).subscribe(res => {
      if (res) {
        this.auditLogs  = res.logs;
        this.auditTotal = res.total;
      } else {
        this.auditError = 'Failed to load audit logs';
      }
      this.auditLoading = false;
      this.cdr.detectChanges();
    });
  }

  onFilterChange(): void { this.loadAuditLogs(); }

  get filteredLogs(): AuditLog[] {
    const q = this.auditSearch.toLowerCase().trim();
    if (!q) return this.auditLogs;
    return this.auditLogs.filter(l =>
      this.resolveUser(l).toLowerCase().includes(q) ||
      l.action.toLowerCase().includes(q) ||
      l.resource.toLowerCase().includes(q) ||
      (l.details ?? '').toLowerCase().includes(q)
    );
  }

  actionIcon(action: string): string { return ACTION_ICONS[action] ?? 'history'; }

  actionLabel(action: string): string {
    return action.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }

  formatTime(ts: string): string {
    return new Date(ts).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    });
  }

  relativeTime(ts: string): string {
    const m = Math.floor((Date.now() - new Date(ts).getTime()) / 60000);
    if (m < 1)  return 'just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }

  outcomeClass(outcome: string): string {
    return { success: 'badge low', failure: 'badge critical', warning: 'badge medium' }[outcome] ?? 'badge';
  }
}
