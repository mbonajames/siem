import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./features/login/login.component').then(m => m.LoginComponent),
  },
  {
    path: '',
    loadComponent: () => import('./layout/shell/shell.component').then(m => m.ShellComponent),
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      { path: 'dashboard', loadComponent: () => import('./features/dashboard/dashboard.component').then(m => m.DashboardComponent) },
      { path: 'alerts',    loadComponent: () => import('./features/alerts/alerts.component').then(m => m.AlertsComponent) },
      { path: 'devices',   loadComponent: () => import('./features/devices/devices.component').then(m => m.DevicesComponent) },
      { path: 'nessus',   loadComponent: () => import('./features/nessus/nessus.component').then(m => m.NessusComponent) },
      { path: 'jira',    loadComponent: () => import('./features/jira/jira-tickets.component').then(m => m.JiraTicketsComponent) },
      { path: 'network-security', loadComponent: () => import('./features/network-security/network-security.component').then(m => m.NetworkSecurityComponent) },
      { path: 'email-security',  loadComponent: () => import('./features/email-security/email-security.component').then(m => m.EmailSecurityComponent) },
      { path: 'my-dashboards',     loadComponent: () => import('./features/custom-dashboards/custom-dashboards.component').then(m => m.CustomDashboardsComponent) },
      { path: 'my-dashboards/:id', loadComponent: () => import('./features/custom-dashboards/dashboard-view/dashboard-view.component').then(m => m.DashboardViewComponent) },
      { path: 'identity',          loadComponent: () => import('./features/identity/identity.component').then(m => m.IdentityComponent) },
      { path: 'vulnerabilities',   loadComponent: () => import('./features/vulnerabilities/vulnerabilities.component').then(m => m.VulnerabilitiesComponent) },
      { path: 'correlation',       loadComponent: () => import('./features/correlation/correlation.component').then(m => m.CorrelationComponent) },
      { path: 'rules',             loadComponent: () => import('./features/rules/rules.component').then(m => m.RulesComponent) },
      { path: 'connectors',         loadComponent: () => import('./features/connectors/connectors.component').then(m => m.ConnectorsComponent) },
      { path: 'mitre',             loadComponent: () => import('./features/mitre/mitre.component').then(m => m.MitreComponent) },
      { path: 'threat-hunting',    loadComponent: () => import('./features/threat-hunting/threat-hunting.component').then(m => m.ThreatHuntingComponent) },
      { path: 'settings',          loadComponent: () => import('./features/settings/settings.component').then(m => m.SettingsComponent) },
      { path: '**', redirectTo: 'dashboard' },
    ],
  },
  { path: '**', redirectTo: 'login' },
];
