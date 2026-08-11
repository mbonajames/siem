import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { CommonModule } from '@angular/common';
import { OrgService } from '../../core/services/org.service';

interface NavItem {
  path:   string;
  icon:   string;
  label:  string;
  badge?: number;
}

interface NavSection {
  label: string;
  items: NavItem[];
}

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive, MatIconModule, MatTooltipModule, CommonModule],
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss',
})
export class SidebarComponent {
  readonly orgService = inject(OrgService);

  navSections: NavSection[] = [
    {
      label: 'Detection',
      items: [
        { path: '/dashboard',   icon: 'shield',           label: 'Security Overview'    },
        { path: '/alerts',      icon: 'warning_amber',    label: 'Alerts & Investigate' },
        { path: '/correlation', icon: 'hub',              label: 'Correlation'          },
      ],
    },
    {
      label: 'Identity',
      items: [
        { path: '/identity', icon: 'manage_accounts', label: 'Identity & Risk' },
      ],
    },
    {
      label: 'Assets',
      items: [
        { path: '/devices',          icon: 'devices',              label: 'Endpoint Security'  },
        { path: '/network-security', icon: 'wifi_tethering_error', label: 'Network Security'   },
        { path: '/email-security',   icon: 'mark_email_unread',    label: 'Email Security'     },
      ],
    },
    {
      label: 'Compliance',
      items: [
        { path: '/nessus',           icon: 'radar',              label: 'Vulnerability Scan' },
        { path: '/vulnerabilities',  icon: 'security_update_warning', label: 'Threat Coverage' },
      ],
    },
    {
      label: 'Intelligence',
      items: [
        { path: '/mitre',          icon: 'grid_view',   label: 'MITRE ATT&CK'   },
        { path: '/threat-hunting', icon: 'manage_search', label: 'Threat Hunting' },
        { path: '/rules',          icon: 'policy',      label: 'Detection Rules' },
      ],
    },
    {
      label: 'Operations',
      items: [
        { path: '/my-dashboards', icon: 'dashboard_customize', label: 'Dashboards'    },
        { path: '/jira',          icon: 'confirmation_number', label: 'JIRA Tickets'  },
        { path: '/connectors',    icon: 'cable',               label: 'Connectors'    },
        { path: '/settings',      icon: 'settings',            label: 'Settings'      },
      ],
    },
  ];
}
