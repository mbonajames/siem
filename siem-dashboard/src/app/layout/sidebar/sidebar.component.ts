import { Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatTooltipModule } from '@angular/material/tooltip';
import { CommonModule } from '@angular/common';

interface NavItem {
  path: string;
  icon: string;
  label: string;
  badge?: number;
}

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, MatIconModule, MatListModule, MatTooltipModule, CommonModule],
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss'
})
export class SidebarComponent {
  navItems: NavItem[] = [
    { path: '/dashboard',      icon: 'dashboard',          label: 'Security Overview'       },
    { path: '/alerts',         icon: 'warning_amber',       label: 'Alerts & Investigate'    },
    { path: '/devices',        icon: 'devices',             label: 'Endpoint Security'        },
    { path: '/nessus',         icon: 'radar',               label: 'Vulnerability Management' },
    { path: '/my-dashboards',  icon: 'dashboard_customize', label: 'Dashboard Management'            },
    { path: '/jira',           icon: 'confirmation_number', label: 'JIRA Tickets'             },
    
  ];
}
