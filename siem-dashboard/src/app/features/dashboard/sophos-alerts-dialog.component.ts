import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';

@Component({
  selector: 'app-sophos-alerts-dialog',
  standalone: true,
  imports: [CommonModule, MatDialogModule, MatButtonModule, MatIconModule, MatTooltipModule],
  template: `
    <h2 mat-dialog-title>
      <mat-icon style="color:#da3633">notifications_active</mat-icon>
      Sophos Alerts — {{ data.total }} total
    </h2>

    <mat-dialog-content>
      @if (!data.items.length) {
        <div class="no-item">No alert items available.</div>
      } @else {
        <div class="list">
          @for (a of data.items; track a.id ?? $index) {
            <div class="row">
              <span [class]="'sev-dot sev-' + sevClass(a.severity)"></span>

              <div class="main">
                <div class="desc">{{ a.description ?? a.type ?? '—' }}</div>
                <div class="meta">
                  @if (a.product) { <span class="chip">{{ a.product }}</span> }
                  @if (a.category) { <span class="chip">{{ a.category }}</span> }
                  @if (a.location) { <span class="loc">{{ a.location }}</span> }
                </div>
              </div>

              <div class="right">
                <span [class]="'sev-label sev-' + sevClass(a.severity)">
                  {{ sevLabel(a.severity) }}
                </span>
                <span class="ts">{{ (a.raisedAt ?? a.when) | date:'MM/dd HH:mm' }}</span>
              </div>
            </div>
          }
        </div>

        @if (data.total > data.items.length) {
          <div class="more-hint">Showing {{ data.items.length }} of {{ data.total }} alerts</div>
        }
      }
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="ref.close()">Close</button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] { display: flex; align-items: center; gap: 10px; }
    mat-dialog-content { padding-top: 4px !important; }

    .list { display: flex; flex-direction: column; gap: 1px; }

    .row {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 4px;
      border-bottom: 1px solid rgba(255,255,255,.05);
      font-size: 13px;
    }
    .row:last-child { border-bottom: none; }

    .sev-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .sev-critical { background: #da3633; }
    .sev-high     { background: #f85149; }
    .sev-medium   { background: #d29922; }
    .sev-low      { background: #3fb950; }

    .main { flex: 1; min-width: 0; }
    .desc {
      font-weight: 500; white-space: nowrap;
      overflow: hidden; text-overflow: ellipsis;
    }
    .meta {
      display: flex; align-items: center; gap: 6px;
      margin-top: 2px; font-size: 11px; color: #8b949e;
    }
    .chip {
      padding: 0 6px; border-radius: 3px; font-size: 10px;
      background: rgba(255,255,255,.06);
    }
    .loc { font-size: 11px; }

    .right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
    .sev-label { font-size: 11px; font-weight: 500; }
    .sev-label.sev-critical { color: #da3633; }
    .sev-label.sev-high     { color: #f85149; }
    .sev-label.sev-medium   { color: #d29922; }
    .sev-label.sev-low      { color: #3fb950; }
    .ts { font-size: 11px; color: #8b949e; font-family: monospace; white-space: nowrap; }

    .no-item { color: #8b949e; text-align: center; padding: 24px 0; }
    .more-hint { text-align: center; font-size: 12px; color: #8b949e; padding: 12px 0 4px; }
  `]
})
export class SophosAlertsDialogComponent {
  constructor(
    public ref: MatDialogRef<SophosAlertsDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { items: any[]; total: number },
  ) {}

  sevClass(sev: string): string {
    const s = (sev ?? '').toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high')     return 'high';
    if (s === 'medium')   return 'medium';
    return 'low';
  }

  sevLabel(sev: string): string {
    const s = (sev ?? '').toLowerCase();
    if (s === 'critical') return 'Critical';
    if (s === 'high')     return 'High';
    if (s === 'medium')   return 'Medium';
    return 'Low';
  }
}
