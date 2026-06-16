import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatExpansionModule } from '@angular/material/expansion';
import { SophosService } from '../../core/services/sophos.service';

@Component({
  selector: 'app-health-dialog',
  standalone: true,
  imports: [CommonModule, MatDialogModule, MatButtonModule, MatIconModule,
            MatProgressSpinnerModule, MatExpansionModule],
  template: `
    <h2 mat-dialog-title>
      <mat-icon [class]="'health-title-icon ' + overallClass(health?.overall)">
        {{ overallIcon(health?.overall) }}
      </mat-icon>
      Health — {{ data.hostname }}
    </h2>

    <mat-dialog-content>
      @if (loading) {
        <div class="spinner-wrap"><mat-spinner diameter="40"></mat-spinner></div>
      } @else if (error) {
        <p class="error-msg">{{ error }}</p>
      } @else if (health) {
        <div class="section">
          <div class="row">
            <span class="label">Overall</span>
            <span [class]="'chip ' + overallClass(health.overall)">{{ health.overall | titlecase }}</span>
          </div>
          <div class="row">
            <span class="label">Threats</span>
            <span [class]="'chip ' + overallClass(health.threats?.status)">
              {{ health.threats?.status | titlecase }}
            </span>
          </div>
          <div class="row">
            <span class="label">Services</span>
            <span [class]="'chip ' + overallClass(health.services?.status)">
              {{ health.services?.status | titlecase }}
            </span>
          </div>
        </div>

        @if (health.services?.serviceDetails?.length) {
          <mat-expansion-panel>
            <mat-expansion-panel-header>
              <mat-panel-title>Services ({{ health.services.serviceDetails.length }})</mat-panel-title>
            </mat-expansion-panel-header>
            <div class="service-list">
              @for (svc of health.services.serviceDetails; track svc.name) {
                <div class="service-row">
                  <mat-icon [class]="svc.status === 'running' ? 'svc-ok' : 'svc-bad'">
                    {{ svc.status === 'running' ? 'check_circle' : 'cancel' }}
                  </mat-icon>
                  <span>{{ svc.name }}</span>
                  <span class="svc-status">{{ svc.status }}</span>
                </div>
              }
            </div>
          </mat-expansion-panel>
        }

        @if (health.endpoint_assessments?.system_assessment?.details?.length) {
          <mat-expansion-panel>
            <mat-expansion-panel-header>
              <mat-panel-title>System Assessment</mat-panel-title>
            </mat-expansion-panel-header>
            <div class="service-list">
              @for (item of health.endpoint_assessments.system_assessment.details; track item.name) {
                <div class="service-row">
                  <mat-icon [class]="item.status === 'good' ? 'svc-ok' : 'svc-bad'">
                    {{ item.status === 'good' ? 'check_circle' : 'warning' }}
                  </mat-icon>
                  <span>{{ item.name }}</span>
                  <span [class]="'chip chip-sm ' + overallClass(item.status)">{{ item.status }}</span>
                </div>
              }
            </div>
          </mat-expansion-panel>
        }
      }
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="ref.close()">Close</button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] { display: flex; align-items: center; gap: 10px; }
    .health-title-icon { font-size: 22px; width: 22px; height: 22px; }
    mat-dialog-content { min-width: 400px; padding-top: 8px !important; }
    .spinner-wrap { display: flex; justify-content: center; padding: 32px; }
    .error-msg { color: #da3633; }
    .section { margin-bottom: 16px; }
    .row { display: flex; align-items: center; gap: 12px; padding: 6px 0;
           border-bottom: 1px solid rgba(255,255,255,.07); }
    .label { min-width: 80px; color: var(--siem-text-secondary, #8b949e); font-size: 13px; }
    .chip { padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 500; }
    .chip-sm { padding: 1px 8px; font-size: 11px; }
    .good  { color: #3fb950; background: rgba(63,185,80,.15); }
    .bad   { color: #da3633; background: rgba(218,54,51,.15); }
    .suspicious { color: #d29922; background: rgba(210,153,34,.15); }
    .service-list { display: flex; flex-direction: column; gap: 4px; padding: 8px 0; }
    .service-row { display: flex; align-items: center; gap: 8px; font-size: 13px; }
    .service-row span:nth-child(2) { flex: 1; }
    .svc-ok { color: #3fb950; font-size: 16px; width: 16px; height: 16px; }
    .svc-bad { color: #da3633; font-size: 16px; width: 16px; height: 16px; }
    .svc-status { font-size: 11px; color: var(--siem-text-secondary, #8b949e); }
  `]
})
export class HealthDialogComponent {
  health: any = null;
  loading = true;
  error = '';

  constructor(
    public ref: MatDialogRef<HealthDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { endpointId: string; hostname: string },
    private sophos: SophosService,
  ) {
    this.sophos.getEndpointHealth(data.endpointId).subscribe({
      next: (h) => { this.health = h; this.loading = false; },
      error: (e) => { this.error = e?.error?.error || e?.message || 'Failed to load health'; this.loading = false; }
    });
  }

  overallClass(status: string): string {
    if (status === 'good') return 'good';
    if (status === 'bad') return 'bad';
    return 'suspicious';
  }

  overallIcon(status: string): string {
    if (status === 'good') return 'check_circle';
    if (status === 'bad') return 'cancel';
    return 'warning';
  }
}
