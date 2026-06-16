import { Component, OnInit, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';
import { MatPaginatorModule, MatPaginator } from '@angular/material/paginator';
import { MatSortModule, MatSort } from '@angular/material/sort';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatMenuModule } from '@angular/material/menu';
import { MatTabsModule } from '@angular/material/tabs';
import { MatChipsModule } from '@angular/material/chips';
import { DefenderService } from '../../core/services/defender.service';
import { SophosService } from '../../core/services/sophos.service';
import { DarktraceService } from '../../core/services/darktrace.service';
import { JiraService } from '../../core/services/jira.service';
import { forkJoin } from 'rxjs';
import { StatCardComponent } from '../../shared/components/stat-card/stat-card.component';

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [
    CommonModule, FormsModule, MatTableModule, MatPaginatorModule, MatSortModule,
    MatFormFieldModule, MatInputModule, MatSelectModule, MatButtonModule, MatIconModule,
    MatCardModule, MatProgressBarModule, MatMenuModule, MatTabsModule, MatChipsModule,
    StatCardComponent
  ],
  templateUrl: './vulnerabilities.component.html',
  styleUrl: './vulnerabilities.component.scss'
})
export class VulnerabilitiesComponent implements OnInit {
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;

  loading = false;
  defenderAlerts: any[] = [];
  sophosAlerts: any[] = [];
  darktraceAlerts: any[] = [];
  incidents: any[] = [];
  secureScore = 0;

  displayedColumnsDefender = ['title', 'severity', 'status', 'category', 'created', 'actions'];
  defenderDataSource = new MatTableDataSource<any>([]);
  sophosDataSource = new MatTableDataSource<any>([]);
  darktraceDataSource = new MatTableDataSource<any>([]);

  stats = { critical: 0, high: 0, medium: 0, low: 0 };

  constructor(
    private defender: DefenderService,
    private sophos: SophosService,
    private darktrace: DarktraceService,
    private jira: JiraService
  ) {}

  ngOnInit(): void {
    this.loadVulnerabilities();
  }

  ngAfterViewInit(): void {
    this.defenderDataSource.paginator = this.paginator;
    this.defenderDataSource.sort = this.sort;
  }

  loadVulnerabilities(): void {
    this.loading = true;
    forkJoin({
      defenderAlerts: this.defender.getAlerts({ top: 100 }),
      sophosAlerts: this.sophos.getAlerts({ pageSize: 100 }),
      darktraceAlerts: this.darktrace.getAlerts(50),
      defenderScore: this.defender.getSecureScore()
    }).subscribe({
      next: (data) => {
        this.defenderAlerts = data.defenderAlerts?.value ?? [];
        this.defenderDataSource.data = this.defenderAlerts;
        this.sophosAlerts = data.sophosAlerts?.items ?? [];
        this.sophosDataSource.data = this.sophosAlerts;
        this.darktraceAlerts = Array.isArray(data.darktraceAlerts) ? data.darktraceAlerts : [];
        this.darktraceDataSource.data = this.darktraceAlerts;
        this.secureScore = Math.round(data.defenderScore?.value?.[0]?.currentScore ?? 0);
        this.computeStats();
        this.loading = false;
      },
      error: () => { this.loading = false; }
    });
  }

  private computeStats(): void {
    const all = [...this.defenderAlerts, ...this.sophosAlerts];
    this.stats = {
      critical: all.filter(a => a.severity?.toLowerCase() === 'critical' || a.severity?.toLowerCase() === 'high').length,
      high: all.filter(a => a.severity?.toLowerCase() === 'high').length,
      medium: all.filter(a => a.severity?.toLowerCase() === 'medium').length,
      low: all.filter(a => a.severity?.toLowerCase() === 'low').length
    };
  }

  createTicket(alert: any): void {
    this.jira.createIssue({
      summary: `[Vulnerability] ${alert.title || alert.name}`,
      description: `Source: ${alert.providerName || 'Defender'}\nSeverity: ${alert.severity}\nCategory: ${alert.category}\nStatus: ${alert.status?.toLowerCase()}\nCreated: ${alert.createdDateTime}\n\n${alert.description ?? ''}`,
      priority: alert.severity === 'critical' ? 'Critical' : alert.severity === 'high' ? 'High' : 'Medium',
      labels: ['siem', 'vulnerability', alert.category?.toLowerCase() ?? 'security']
    }).subscribe({
      next: (issue) => alert('Ticket created: ' + issue.key),
      error: err => console.error(err)
    });
  }

  getSeverityClass(sev: string): string {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return 'info';
    }
  }
}
