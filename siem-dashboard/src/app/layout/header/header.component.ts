import { Component, EventEmitter, OnDestroy, OnInit, Output, inject } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatMenuModule } from '@angular/material/menu';
import { MatBadgeModule } from '@angular/material/badge';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDividerModule } from '@angular/material/divider';
import { Router, NavigationEnd } from '@angular/router';
import { filter } from 'rxjs/operators';
import { AuthService } from '../../core/services/auth.service';
import { GatewayService } from '../../core/services/gateway.service';
import { OrgService } from '../../core/services/org.service';

const POLL_INTERVAL_MS = 5 * 60 * 1000;

const PAGE_TITLES: Record<string, { title: string; icon: string }> = {
  '/dashboard':        { title: 'Security Overview',       icon: 'shield'                   },
  '/alerts':           { title: 'Alerts & Investigation',  icon: 'warning_amber'             },
  '/correlation':      { title: 'Correlation',             icon: 'hub'                      },
  '/identity':         { title: 'Identity & Risk',         icon: 'manage_accounts'           },
  '/devices':          { title: 'Endpoint Security',       icon: 'devices'                  },
  '/network-security': { title: 'Network Security',        icon: 'wifi_tethering_error'     },
  '/email-security':   { title: 'Email Security',          icon: 'mark_email_unread'        },
  '/nessus':           { title: 'Vulnerability Scan',      icon: 'radar'                    },
  '/vulnerabilities':  { title: 'Threat Coverage',         icon: 'security_update_warning'  },
  '/rules':            { title: 'Detection Rules',         icon: 'policy'                   },
  '/my-dashboards':    { title: 'Dashboard Builder',       icon: 'dashboard_customize'      },
  '/jira':             { title: 'JIRA Tickets',            icon: 'confirmation_number'      },
  '/connectors':       { title: 'Connectors',              icon: 'cable'                    },
  '/mitre':            { title: 'MITRE ATT&CK Coverage',   icon: 'grid_view'                },
  '/threat-hunting':   { title: 'Threat Hunting',          icon: 'manage_search'            },
  '/settings':         { title: 'Recent Activity',         icon: 'history'                  },
};

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [MatIconModule, MatButtonModule, MatMenuModule, MatBadgeModule, MatTooltipModule, MatDividerModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.scss',
})
export class HeaderComponent implements OnInit, OnDestroy {
  @Output() menuToggle = new EventEmitter<void>();

  readonly auth       = inject(AuthService);
  readonly gateway    = inject(GatewayService);
  readonly router     = inject(Router);
  readonly orgService = inject(OrgService);

  notificationCount = 0;
  currentPageTitle  = 'Security Overview';
  currentPageIcon   = 'shield';

  private pollTimer: ReturnType<typeof setInterval> | null = null;

  ngOnInit(): void {
    this.updatePageMeta(this.router.url);

    this.router.events.pipe(
      filter(e => e instanceof NavigationEnd)
    ).subscribe((e: any) => this.updatePageMeta(e.urlAfterRedirects ?? e.url));

    this.fetchNotificationCount();
    this.pollTimer = setInterval(() => this.fetchNotificationCount(), POLL_INTERVAL_MS);
  }

  ngOnDestroy(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }

  private updatePageMeta(url: string): void {
    const key = Object.keys(PAGE_TITLES).find(k => url.startsWith(k));
    const meta = key ? PAGE_TITLES[key] : { title: 'Hope-Armor SIEM', icon: 'security' };
    this.currentPageTitle = meta.title;
    this.currentPageIcon  = meta.icon;
  }

  private fetchNotificationCount(): void {
    this.gateway.getStats(24).subscribe({
      next: stats => {
        const sev = stats.by_severity ?? {};
        this.notificationCount = (sev['Critical'] ?? 0) + (sev['High'] ?? 0);
      },
      error: () => {},
    });
  }

  get displayName(): string { return this.auth.user?.name ?? 'User'; }
  get initials():    string { return this.auth.user?.initials ?? '?'; }
  get email():       string { return this.auth.user?.email ?? ''; }

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
