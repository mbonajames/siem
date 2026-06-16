import { Component, OnInit, ViewChild, AfterViewInit } from '@angular/core';
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
import { MatTabsModule } from '@angular/material/tabs';
import { MatMenuModule } from '@angular/material/menu';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatChipsModule } from '@angular/material/chips';
import { forkJoin } from 'rxjs';
import { IdentityService } from '../../core/services/identity.service';
import { StatCardComponent } from '../../shared/components/stat-card/stat-card.component';
import { ResetPasswordDialogComponent } from './reset-password-dialog.component';

@Component({
  selector: 'app-identity',
  standalone: true,
  imports: [
    CommonModule, FormsModule, MatTableModule, MatPaginatorModule, MatSortModule,
    MatFormFieldModule, MatInputModule, MatSelectModule, MatButtonModule, MatIconModule,
    MatCardModule, MatProgressBarModule, MatTabsModule, MatMenuModule, MatTooltipModule,
    MatSnackBarModule, MatDialogModule, MatChipsModule, StatCardComponent,
    ResetPasswordDialogComponent,
  ],
  templateUrl: './identity.component.html',
  styleUrl: './identity.component.scss'
})
export class IdentityComponent implements OnInit, AfterViewInit {
  @ViewChild('userPaginator') userPaginator!: MatPaginator;
  @ViewChild('userSort') userSort!: MatSort;
  @ViewChild('signInPaginator') signInPaginator!: MatPaginator;

  userColumns = ['displayName', 'upn', 'riskLevel', 'riskState', 'riskDetail', 'updatedAt', 'actions'];
  signInColumns = ['user', 'upn', 'riskLevel', 'riskState', 'ipAddress', 'location', 'createdAt'];

  usersDataSource = new MatTableDataSource<any>([]);
  signInsDataSource = new MatTableDataSource<any>([]);

  loading = false;
  searchQuery = '';
  selectedRiskLevel = '';
  activeTab = 0;

  stats = { high: 0, medium: 0, low: 0, atRiskSignIns: 0 };

  riskLevelFilters = [
    { value: '', label: 'All Levels' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
  ];

  constructor(
    private identity: IdentityService,
    private snackBar: MatSnackBar,
    private dialog: MatDialog,
  ) {}

  ngOnInit(): void {
    this.loadData();
  }

  ngAfterViewInit(): void {
    this.usersDataSource.paginator = this.userPaginator;
    this.usersDataSource.sort = this.userSort;
    this.signInsDataSource.paginator = this.signInPaginator;
  }

  loadData(): void {
    this.loading = true;
    forkJoin({
      users: this.identity.getRiskyUsers({ top: 200 }),
      signIns: this.identity.getRiskySignIns({ top: 200 }),
    }).subscribe({
      next: ({ users, signIns }) => {
        const userList: any[] = (users as any)?.value ?? [];
        const signInList: any[] = (signIns as any)?.value ?? [];
        this.usersDataSource.data = userList;
        this.signInsDataSource.data = signInList;
        this.stats = {
          high: userList.filter(u => u.riskLevel === 'high').length,
          medium: userList.filter(u => u.riskLevel === 'medium').length,
          low: userList.filter(u => u.riskLevel === 'low').length,
          atRiskSignIns: signInList.filter(s => s.riskLevelDuringSignIn !== 'none' && s.riskLevelDuringSignIn !== 'hidden').length,
        };
        this.applyUserFilter();
        this.loading = false;
      },
      error: () => { this.loading = false; }
    });
  }

  applyUserFilter(): void {
    this.usersDataSource.filterPredicate = (data: any, filter: string) => {
      const f = JSON.parse(filter);
      const matchSearch = !f.search ||
        data.userDisplayName?.toLowerCase().includes(f.search.toLowerCase()) ||
        data.userPrincipalName?.toLowerCase().includes(f.search.toLowerCase());
      const matchLevel = !f.riskLevel || data.riskLevel === f.riskLevel;
      return matchSearch && matchLevel;
    };
    this.usersDataSource.filter = JSON.stringify({ search: this.searchQuery, riskLevel: this.selectedRiskLevel });
  }

  revokeSessions(user: any): void {
    if (!confirm(`Revoke all sessions for ${user.userDisplayName}? They will be signed out immediately.`)) return;
    this.identity.revokeSessions(user.id).subscribe({
      next: () => this.snackBar.open(`Sessions revoked for ${user.userDisplayName}`, 'OK', { duration: 4000 }),
      error: (err) => this.snackBar.open(`Failed: ${err.error?.error ?? err.message}`, 'Close', { duration: 5000 }),
    });
  }

  resetPassword(user: any): void {
    if (!confirm(`Force password reset for ${user.userDisplayName}? A temporary password will be generated.`)) return;
    this.identity.resetPassword(user.id).subscribe({
      next: (res: any) => {
        this.dialog.open(ResetPasswordDialogComponent, {
          data: { user: user.userDisplayName, password: res.temporaryPassword },
          width: '420px',
        });
      },
      error: (err) => this.snackBar.open(`Failed: ${err.error?.error ?? err.message}`, 'Close', { duration: 5000 }),
    });
  }

  dismissRisk(user: any): void {
    if (!confirm(`Dismiss risk for ${user.userDisplayName}? This marks them as safe after investigation.`)) return;
    this.identity.dismissRisk(user.id).subscribe({
      next: () => {
        this.snackBar.open(`Risk dismissed for ${user.userDisplayName}`, 'OK', { duration: 4000 });
        this.loadData();
      },
      error: (err) => this.snackBar.open(`Failed: ${err.error?.error ?? err.message}`, 'Close', { duration: 5000 }),
    });
  }

  getRiskClass(level: string): string {
    switch (level) {
      case 'high': return 'critical';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return 'info';
    }
  }
}
