import { Component, Input } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-stat-card',
  standalone: true,
  imports: [MatCardModule, MatIconModule, CommonModule],
  template: `
    <mat-card class="stat-card" [class]="'severity-' + severity">
      <mat-card-content>
        <div class="stat-header">
          <mat-icon [class]="'severity-' + severity">{{ icon }}</mat-icon>
          <span class="stat-label">{{ label }}</span>
        </div>
        <div class="stat-value">{{ value | number }}</div>
        <div class="stat-sub" *ngIf="subtitle">{{ subtitle }}</div>
      </mat-card-content>
    </mat-card>
  `,
  styles: [`
    .stat-card {
      background: var(--siem-surface) !important;
      border: 1px solid var(--siem-border) !important;
      border-radius: 8px !important;
      transition: border-color 0.2s;
      &:hover { border-color: var(--siem-info) !important; }
      mat-card-content { padding: 16px !important; }
    }
    .stat-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
      mat-icon { font-size: 18px; width: 18px; height: 18px; }
    }
    .stat-label { font-size: 12px; color: var(--siem-text-secondary); font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-value { font-size: 32px; font-weight: 700; color: var(--siem-text-primary); line-height: 1; margin-bottom: 4px; }
    .stat-sub { font-size: 12px; color: var(--siem-text-secondary); }
  `]
})
export class StatCardComponent {
  @Input() label = '';
  @Input() value: number = 0;
  @Input() icon = 'info';
  @Input() severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'info';
  @Input() subtitle = '';
}
