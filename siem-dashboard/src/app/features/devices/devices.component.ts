import { Component, OnInit, OnDestroy, ViewChild } from '@angular/core';
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
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatMenuModule } from '@angular/material/menu';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTabsModule } from '@angular/material/tabs';
import { MatDividerModule } from '@angular/material/divider';
import { SophosService } from '../../core/services/sophos.service';
import { WazuhService } from '../../core/services/wazuh.service';
import { forkJoin, of, interval, Subscription } from 'rxjs';
import { catchError, switchMap, takeWhile } from 'rxjs/operators';
import { StatCardComponent } from '../../shared/components/stat-card/stat-card.component';
import { HealthDialogComponent } from './health-dialog.component';

@Component({
  selector: 'app-devices',
  standalone: true,
  imports: [
    CommonModule, FormsModule, MatTableModule, MatPaginatorModule, MatSortModule,
    MatFormFieldModule, MatInputModule, MatSelectModule, MatButtonModule, MatIconModule,
    MatCardModule, MatProgressBarModule, MatDialogModule, MatMenuModule, MatTooltipModule,
    MatSnackBarModule, MatTabsModule, MatDividerModule, StatCardComponent
  ],
  templateUrl: './devices.component.html',
  styleUrl: './devices.component.scss'
})
export class DevicesComponent implements OnInit, OnDestroy {
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;

  displayedColumns = ['hostname', 'type', 'os', 'assignedUser', 'health', 'isolation', 'lastSeen', 'actions'];
  dataSource = new MatTableDataSource<any>([]);
  loading = false;
  searchQuery = '';
  selectedHealth = '';
  selectedType = '';
  activeTab = 0;

  /** endpointId → 'isolating' | 'removing' */
  isolationPending = new Map<string, 'isolating' | 'removing'>();
  private pollSubs = new Map<string, Subscription>();

  stats = { total: 0, good: 0, suspicious: 0, bad: 0, isolated: 0 };

  healthFilters = [
    { value: '', label: 'All Health' },
    { value: 'good', label: 'Good' },
    { value: 'suspicious', label: 'Suspicious' },
    { value: 'bad', label: 'Bad' }
  ];

  typeFilters = [
    { value: '', label: 'All Types' },
    { value: 'computer', label: 'Computer' },
    { value: 'server', label: 'Server' },
    { value: 'securityVm', label: 'Security VM' },
  ];

  isolatedDevices: any[] = [];
  wazuhAgents: any[] = [];

  constructor(
    private sophos: SophosService,
    private wazuh: WazuhService,
    private snackBar: MatSnackBar,
    private dialog: MatDialog,
  ) {}

  ngOnInit(): void {
    this.loadDevices();
  }

  ngOnDestroy(): void {
    this.pollSubs.forEach(s => s.unsubscribe());
  }

  ngAfterViewInit(): void {
    this.dataSource.paginator = this.paginator;
    this.dataSource.sort = this.sort;
  }

  loadDevices(): void {
    this.loading = true;
    forkJoin({
      sophosEndpoints: this.sophos.getEndpoints().pipe(catchError(() => of(null))),
      wazuhAgents: this.wazuh.getAgents({ limit: 200 }).pipe(catchError(() => of(null)))
    }).subscribe({
      next: (data) => {
        const endpoints = data.sophosEndpoints?.items ?? [];
        this.dataSource.data = endpoints;
        this.isolatedDevices = endpoints.filter((e: any) => e.isolation?.status === 'isolated');
        this.stats = {
          total: endpoints.length,
          good: endpoints.filter((e: any) => e.health?.overall === 'good').length,
          suspicious: endpoints.filter((e: any) => e.health?.overall === 'suspicious').length,
          bad: endpoints.filter((e: any) => e.health?.overall === 'bad').length,
          isolated: this.isolatedDevices.length
        };
        this.wazuhAgents = data.wazuhAgents?.data?.affected_items ?? [];
        this.applyFilters();
        this.loading = false;
      },
      error: () => { this.loading = false; }
    });
  }

  applyFilters(): void {
    this.dataSource.filterPredicate = (data: any, filter: string) => {
      const parsed = JSON.parse(filter);
      const matchSearch = !parsed.search ||
        data.hostname?.toLowerCase().includes(parsed.search.toLowerCase()) ||
        data.associatedPerson?.name?.toLowerCase().includes(parsed.search.toLowerCase());
      const matchHealth = !parsed.health || data.health?.overall === parsed.health;
      const matchType  = !parsed.type  || data.type === parsed.type;
      return matchSearch && matchHealth && matchType;
    };
    this.dataSource.filter = JSON.stringify({ search: this.searchQuery, health: this.selectedHealth, type: this.selectedType });
  }

  onSearch(): void {
    this.applyFilters();
  }

  private sophosErrMsg(err: any): string {
    const d = err?.error?.detail;
    if (d) return typeof d === 'string' ? d : d?.message || JSON.stringify(d);
    return err?.error?.error || err?.error?.message || err?.message || 'Unknown error';
  }

  private pollIsolationStatus(deviceId: string, expectedStatus: 'isolated' | 'notIsolated'): void {
    this.pollSubs.get(deviceId)?.unsubscribe();
    const sub = interval(4000).pipe(
      switchMap(() => this.sophos.getEndpoint(deviceId).pipe(catchError(() => of(null)))),
      takeWhile((d, idx) => {
        if (!d) return idx < 10;
        const current = d.isolation?.status ?? 'notIsolated';
        if (current === expectedStatus) {
          this.updateDeviceRow(d);
          this.isolationPending.delete(deviceId);
          this.pollSubs.delete(deviceId);
          this.rebuildStats();
          const msg = expectedStatus === 'isolated'
            ? `${d.hostname} is now isolated`
            : `${d.hostname} isolation removed`;
          this.snackBar.open(msg, 'OK', { duration: 4000 });
          return false;
        }
        return idx < 30;
      })
    ).subscribe();
    this.pollSubs.set(deviceId, sub);
  }

  private updateDeviceRow(updated: any): void {
    const data = this.dataSource.data;
    const idx = data.findIndex(d => d.id === updated.id);
    if (idx !== -1) {
      data[idx] = { ...data[idx], ...updated };
      this.dataSource.data = [...data];
    }
  }

  private rebuildStats(): void {
    const items = this.dataSource.data;
    this.isolatedDevices = items.filter((e: any) => e.isolation?.status === 'isolated');
    this.stats = {
      total: items.length,
      good: items.filter((e: any) => e.health?.overall === 'good').length,
      suspicious: items.filter((e: any) => e.health?.overall === 'suspicious').length,
      bad: items.filter((e: any) => e.health?.overall === 'bad').length,
      isolated: this.isolatedDevices.length,
    };
  }

  isolateDevice(device: any): void {
    if (!confirm(`Isolate ${device.hostname}? It will lose network access.`)) return;
    this.sophos.isolateEndpoint(device.id, 'Isolated via SIEM dashboard').subscribe({
      next: () => {
        this.isolationPending.set(device.id, 'isolating');
        this.snackBar.open(`Isolating ${device.hostname}…`, undefined, { duration: 3000 });
        this.pollIsolationStatus(device.id, 'isolated');
      },
      error: (err) => this.snackBar.open(`Failed to isolate: ${this.sophosErrMsg(err)}`, 'Close', { duration: 6000 })
    });
  }

  removeIsolation(device: any): void {
    if (!confirm(`Remove isolation from ${device.hostname}?`)) return;
    this.sophos.removeIsolation(device.id).subscribe({
      next: () => {
        this.isolationPending.set(device.id, 'removing');
        this.snackBar.open(`Removing isolation from ${device.hostname}…`, undefined, { duration: 3000 });
        this.pollIsolationStatus(device.id, 'notIsolated');
      },
      error: (err) => this.snackBar.open(`Failed to remove isolation: ${this.sophosErrMsg(err)}`, 'Close', { duration: 6000 })
    });
  }

  scanDevice(device: any): void {
    this.sophos.scanEndpoint(device.id).subscribe({
      next: () => this.snackBar.open(`Scan triggered on ${device.hostname}`, 'OK', { duration: 3000 }),
      error: (err) => this.snackBar.open(`Scan failed: ${this.sophosErrMsg(err)}`, 'Close', { duration: 6000 })
    });
  }

  checkUpdates(device: any): void {
    this.sophos.triggerUpdateCheck(device.id).subscribe({
      next: () => this.snackBar.open(`Update check triggered on ${device.hostname}`, 'OK', { duration: 3000 }),
      error: (err) => this.snackBar.open(`Update check failed: ${this.sophosErrMsg(err)}`, 'Close', { duration: 6000 })
    });
  }

  openInSophosCentral(device: any): void {
    window.open(`https://cloud.sophos.com/manage/endpoint-protection/computers`, '_blank');
  }

  viewHealth(device: any): void {
    this.dialog.open(HealthDialogComponent, {
      data: { endpointId: device.id, hostname: device.hostname },
      width: '520px',
      panelClass: 'siem-dialog',
    });
  }

  toggleTamperProtection(device: any): void {
    this.sophos.getTamperProtection(device.id).subscribe({
      next: (tp) => {
        const currentlyEnabled = tp?.enabled ?? true;
        const action = currentlyEnabled ? 'disable' : 'enable';
        if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} tamper protection on ${device.hostname}?`)) return;
        this.sophos.setTamperProtection(device.id, !currentlyEnabled).subscribe({
          next: () => this.snackBar.open(`Tamper protection ${action}d on ${device.hostname}`, 'OK', { duration: 3000 }),
          error: (err) => this.snackBar.open(`Failed: ${this.sophosErrMsg(err)}`, 'Close', { duration: 6000 })
        });
      },
      error: (err) => this.snackBar.open(`Could not fetch tamper status: ${err.message}`, 'Close', { duration: 5000 })
    });
  }

  getHealthClass(health: string): string {
    switch (health) {
      case 'good': return 'low';
      case 'suspicious': return 'medium';
      case 'bad': return 'critical';
      default: return 'info';
    }
  }

  getHealthIcon(health: string): string {
    switch (health) {
      case 'good': return 'check_circle';
      case 'suspicious': return 'warning';
      case 'bad': return 'cancel';
      default: return 'help';
    }
  }
}
