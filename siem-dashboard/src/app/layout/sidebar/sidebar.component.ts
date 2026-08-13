import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { CommonModule } from '@angular/common';

interface NavItem {
  path:   string;
  icon:   string;
  label:  string;
  badge?: number;
}

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, MatIconModule, MatTooltipModule, CommonModule],
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss',
})
export class SidebarComponent {
  navItems: NavItem[] = [
    { path: '/dashboard',        icon: 'shield',               label: 'Security Overview'       },
    { path: '/discover',         icon: 'travel_explore',       label: 'Explore'                 },
    { path: '/my-dashboards',    icon: 'dashboard_customize',  label: 'Visualizations'          },
    { path: '/alerts',           icon: 'warning_amber',        label: 'Alerts Investigation'    },
    { path: '/devices',          icon: 'devices',              label: 'Endpoint Security'       },
    { path: '/network-security', icon: 'wifi_tethering_error', label: 'Network Security'        },
    { path: '/email-security',   icon: 'mark_email_unread',    label: 'Email Security'          },
    { path: '/identity',         icon: 'manage_accounts',      label: 'Identity Management'     },
    { path: '/nessus',           icon: 'radar',                label: 'Vulnerability Detection' },
    { path: '/jira',             icon: 'confirmation_number',  label: 'Cases'                   },
    { path: '/activity-log',      icon: 'history',              label: 'Recent Activities'       },
    { path: '/settings',         icon: 'settings',             label: 'Settings'                },
  ];
}
