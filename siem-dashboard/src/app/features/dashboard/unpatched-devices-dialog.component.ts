import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-unpatched-devices-dialog',
  standalone: true,
  imports: [CommonModule, MatDialogModule, MatButtonModule, MatIconModule],
  template: `
    <h2 mat-dialog-title>
      <mat-icon style="color:#F46A1F">warning</mat-icon>
      Unhealthy Devices ({{ data.devices.length }})
    </h2>

    <mat-dialog-content>
      <div class="device-list">
        @for (d of data.devices; track d.id) {
          <div class="device-row">
            <div class="device-info">
              <div class="device-hostname">
                <mat-icon class="type-icon">{{ d.type === 'server' ? 'dns' : 'computer' }}</mat-icon>
                {{ d.hostname }}
              </div>
              <div class="device-meta">
                {{ d.type | titlecase }} &middot; {{ d.os?.name ?? '—' }} &middot;
                Last seen {{ d.lastSeenAt | date:'MM/dd HH:mm' }}
              </div>
              @if (d.associatedPerson?.name) {
                <div class="device-user">
                  <mat-icon>person</mat-icon> {{ d.associatedPerson.name }}
                </div>
              }
            </div>
            <div class="device-badges">
              <span [class]="'badge badge-' + d.health?.overall">
                {{ d.health?.overall | titlecase }}
              </span>
              @if (d.health?.threats?.status === 'bad') {
                <span class="badge badge-threat">
                  <mat-icon>bug_report</mat-icon> Threat
                </span>
              }
              @if (d.isolation?.status === 'isolated') {
                <span class="badge badge-isolated">
                  <mat-icon>lock</mat-icon> Isolated
                </span>
              }
            </div>
          </div>
        }
        @if (data.devices.length === 0) {
          <div class="empty">
            <mat-icon>check_circle</mat-icon>
            <p>All devices are healthy</p>
          </div>
        }
      </div>
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="ref.close()">Close</button>
      <button mat-flat-button color="primary" (click)="goToDevices()">
        <mat-icon>open_in_new</mat-icon> View in Devices
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] { display: flex; align-items: center; gap: 10px; }
    mat-dialog-content { min-width: 480px; max-height: 60vh; padding-top: 4px !important; }
    .device-list { display: flex; flex-direction: column; gap: 2px; }
    .device-row {
      display: flex; align-items: center; justify-content: space-between;
      padding: 10px 12px; border-radius: 6px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      &:hover { background: rgba(255,255,255,.04); }
    }
    .device-hostname {
      display: flex; align-items: center; gap: 6px;
      font-weight: 500; font-size: 14px;
    }
    .type-icon { font-size: 16px; width: 16px; height: 16px; color: #8b949e; }
    .device-meta { font-size: 12px; color: #8b949e; margin-top: 2px; padding-left: 22px; }
    .device-user { font-size: 12px; color: #8b949e; padding-left: 22px; margin-top: 2px;
      display: flex; align-items: center; gap: 4px;
      mat-icon { font-size: 13px; width: 13px; height: 13px; } }
    .device-badges { display: flex; flex-direction: column; align-items: flex-end; gap: 4px; flex-shrink: 0; }
    .badge {
      padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 500;
      display: flex; align-items: center; gap: 3px;
      mat-icon { font-size: 12px; width: 12px; height: 12px; }
    }
    .badge-bad        { background: rgba(218,54,51,.15);  color: #da3633; }
    .badge-suspicious { background: rgba(210,153,34,.15); color: #d29922; }
    .badge-threat     { background: rgba(218,54,51,.1);   color: #f85149; }
    .badge-isolated   { background: rgba(210,153,34,.1);  color: #d29922; }
    .empty { text-align: center; padding: 40px; color: #8b949e;
      mat-icon { font-size: 40px; width: 40px; height: 40px; color: #3fb950; display: block; margin: 0 auto 8px; } }
  `]
})
export class UnpatchedDevicesDialogComponent {
  constructor(
    public ref: MatDialogRef<UnpatchedDevicesDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { devices: any[] },
    private router: Router,
  ) {}

  goToDevices(): void {
    this.ref.close();
    this.router.navigate(['/devices']);
  }
}
