import { Component, EventEmitter, OnDestroy, OnInit, Output, inject } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatMenuModule } from '@angular/material/menu';
import { MatBadgeModule } from '@angular/material/badge';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDividerModule } from '@angular/material/divider';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { GatewayService } from '../../core/services/gateway.service';

const POLL_INTERVAL_MS = 5 * 60 * 1000;

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [MatIconModule, MatButtonModule, MatMenuModule, MatBadgeModule, MatTooltipModule, MatDividerModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.scss',
})
export class HeaderComponent implements OnInit, OnDestroy {
  @Output() menuToggle = new EventEmitter<void>();

  readonly auth    = inject(AuthService);
  readonly gateway = inject(GatewayService);
  readonly router  = inject(Router);

  notificationCount = 0;
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  ngOnInit(): void {
    this.fetchNotificationCount();
    this.pollTimer = setInterval(() => this.fetchNotificationCount(), POLL_INTERVAL_MS);
  }

  ngOnDestroy(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }

  private fetchNotificationCount(): void {
    this.gateway.getStats(24).subscribe({
      next: stats => {
        const sev = stats.by_severity ?? {};
        this.notificationCount = (sev['Critical'] ?? 0) + (sev['High'] ?? 0);
      },
      error: () => { /* keep existing count on failure */ },
    });
  }

  get displayName(): string { return this.auth.user?.name ?? 'User'; }
  get initials(): string { return this.auth.user?.initials ?? '?'; }
  get email(): string { return this.auth.user?.email ?? ''; }
  get roleBadge(): string {
    if (this.auth.hasRole('socadmin'))   return 'Admin';
    if (this.auth.hasRole('socanalyst')) return 'Analyst';
    return '';
  }
  get isAdmin(): boolean { return this.auth.isAdmin(); }

  goToNotifications(): void {
    this.router.navigate(['/alerts'], {
      queryParams: { severity: 'Critical,High', hours: 24 },
    });
  }

  logout(): void { this.auth.logout(); }
}
