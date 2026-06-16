import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';

@Component({
  selector: 'app-detections-dialog',
  standalone: true,
  imports: [CommonModule, MatDialogModule, MatButtonModule, MatIconModule, MatTooltipModule],
  template: `
    <h2 mat-dialog-title>
      <mat-icon style="color:#7F77DD">manage_search</mat-icon>
      XDR Detections — {{ data.total }} total
    </h2>

    <mat-dialog-content>
      @if (!data.items.length) {
        <div class="no-det">No detection items available.</div>
      } @else {
        <div class="det-list">
          @for (d of data.items; track d.id ?? $index) {
            <div class="det-row">
              <span [class]="'sev-dot sev-' + sevClass(d.severity)"></span>

              <div class="det-main">
                <div class="det-rule">{{ d.detectionRule ?? d.name ?? '—' }}</div>
                <div class="det-meta">
                  <span class="det-case" [matTooltip]="d._caseId">{{ d._caseName }}</span>
                  @if (d.type) { <span class="det-type">{{ d.type }}</span> }
                  @if (d.sensor?.source) { <span class="det-src">{{ d.sensor.source }}</span> }
                </div>
              </div>

              <div class="det-right">
                @if (d.mitreAttacks?.[0]?.tactic?.id) {
                  <span class="mitre-chip" [matTooltip]="d.mitreAttacks[0].tactic.techniques?.[0]?.name ?? ''">
                    {{ d.mitreAttacks[0].tactic.id }}
                  </span>
                }
                <span [class]="'sev-label sev-' + sevClass(d.severity)">
                  {{ sevLabel(d.severity) }}
                </span>
                <span class="det-time">{{ d.time | date:'MM/dd HH:mm' }}</span>
              </div>
            </div>
          }
        </div>

        @if (data.total > data.items.length) {
          <div class="more-hint">
            Showing {{ data.items.length }} of {{ data.total }} detections
          </div>
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

    .det-list { display: flex; flex-direction: column; gap: 1px; }

    .det-row {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 4px;
      border-bottom: 1px solid rgba(255,255,255,.05);
      font-size: 13px;
    }
    .det-row:last-child { border-bottom: none; }

    .sev-dot {
      width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
    }
    .sev-critical { background: #da3633; }
    .sev-high     { background: #f85149; }
    .sev-medium   { background: #d29922; }
    .sev-low      { background: #3fb950; }

    .det-main { flex: 1; min-width: 0; }
    .det-rule {
      font-weight: 500; white-space: nowrap;
      overflow: hidden; text-overflow: ellipsis;
    }
    .det-meta {
      display: flex; align-items: center; gap: 8px;
      margin-top: 2px; font-size: 11px; color: #8b949e;
    }
    .det-case { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .det-type, .det-src {
      padding: 0 6px; border-radius: 3px; font-size: 10px;
      background: rgba(255,255,255,.06);
    }

    .det-right {
      display: flex; align-items: center; gap: 8px;
      flex-shrink: 0;
    }
    .mitre-chip {
      padding: 1px 6px; border-radius: 4px; font-size: 11px; font-family: monospace;
      background: rgba(127,119,221,.12); color: #7F77DD;
      border: 1px solid rgba(127,119,221,.25);
    }
    .sev-label { font-size: 11px; font-weight: 500; }
    .sev-label.sev-critical { color: #da3633; }
    .sev-label.sev-high     { color: #f85149; }
    .sev-label.sev-medium   { color: #d29922; }
    .sev-label.sev-low      { color: #3fb950; }

    .det-time { font-size: 11px; color: #8b949e; font-family: monospace; white-space: nowrap; }

    .no-det { color: #8b949e; text-align: center; padding: 24px 0; }

    .more-hint {
      text-align: center; font-size: 12px; color: #8b949e;
      padding: 12px 0 4px;
    }
  `]
})
export class DetectionsDialogComponent {
  constructor(
    public ref: MatDialogRef<DetectionsDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { items: any[]; total: number },
  ) {}

  sevClass(sev: number): string {
    if (sev >= 9) return 'critical';
    if (sev >= 7) return 'high';
    if (sev >= 4) return 'medium';
    return 'low';
  }

  sevLabel(sev: number): string {
    if (sev >= 9) return 'Critical';
    if (sev >= 7) return 'High';
    if (sev >= 4) return 'Medium';
    return 'Low';
  }
}
