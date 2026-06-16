import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatChipsModule } from '@angular/material/chips';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { SophosService } from '../../core/services/sophos.service';

@Component({
  selector: 'app-cases-dialog',
  standalone: true,
  imports: [CommonModule, MatDialogModule, MatButtonModule, MatIconModule, MatChipsModule, MatExpansionModule, MatProgressSpinnerModule],
  template: `
    <h2 mat-dialog-title>
      <mat-icon style="color:#7F77DD">folder_special</mat-icon>
      Cases — {{ data.total }} total
    </h2>

    <mat-dialog-content>
      <div class="cases-list">
        @for (c of data.cases; track c.id) {
          <mat-expansion-panel class="case-panel" (opened)="loadDetections(c.id)">
            <mat-expansion-panel-header>
              <mat-panel-title class="case-title">
                <span [class]="'sev-dot sev-' + severityClass(c.initialDetection?.severity)"></span>
                <span class="case-name">{{ c.name }}</span>
              </mat-panel-title>
              <mat-panel-description class="case-meta">
                <span [class]="'status-chip status-' + c.status">{{ c.status }}</span>
                <span class="case-date">{{ c.createdAt | date:'MM/dd/yy HH:mm' }}</span>
              </mat-panel-description>
            </mat-expansion-panel-header>

            <div class="case-body">
              <div class="case-row">
                <span class="lbl">Case ID</span>
                <span class="val mono">{{ c.id }}</span>
              </div>
              <div class="case-row">
                <span class="lbl">Type</span>
                <span class="val">{{ c.type | titlecase }}</span>
              </div>
              <div class="case-row">
                <span class="lbl">Assignee</span>
                <span class="val">{{ c.assignee?.name ?? '—' }}</span>
              </div>
              <div class="case-row">
                <span class="lbl">Updated</span>
                <span class="val">{{ c.updatedAt | date:'MM/dd/yy HH:mm' }}</span>
              </div>

              @if (c.initialDetection) {
                <div class="detection-block">
                  <div class="detection-header">Initial Detection</div>
                  <div class="case-row">
                    <span class="lbl">Rule</span>
                    <span class="val mono">{{ c.initialDetection.detectionRule }}</span>
                  </div>
                  <div class="case-row">
                    <span class="lbl">Severity</span>
                    <span [class]="'val sev-label sev-' + severityClass(c.initialDetection.severity)">
                      {{ c.initialDetection.severity }} — {{ severityLabel(c.initialDetection.severity) }}
                    </span>
                  </div>
                  <div class="case-row">
                    <span class="lbl">Type</span>
                    <span class="val">{{ c.initialDetection.type }}</span>
                  </div>
                  <div class="case-row">
                    <span class="lbl">Source</span>
                    <span class="val">{{ c.initialDetection.sensor?.source ?? '—' }}</span>
                  </div>
                  <div class="case-row">
                    <span class="lbl">Time</span>
                    <span class="val">{{ c.initialDetection.time | date:'MM/dd/yy HH:mm' }}</span>
                  </div>

                  @if (c.initialDetection.mitreAttacks?.length) {
                    <div class="case-row mitre-row">
                      <span class="lbl">MITRE</span>
                      <div class="mitre-chips">
                        @for (att of c.initialDetection.mitreAttacks; track att.tactic?.id) {
                          <span class="mitre-chip" [title]="att.tactic?.name">
                            {{ att.tactic?.id }}
                            @if (att.tactic?.techniques?.[0]) {
                              · {{ att.tactic.techniques[0].id }}
                            }
                          </span>
                        }
                      </div>
                    </div>
                  }
                </div>
              }

              <!-- All detections for this case -->
              <div class="detections-section">
                <div class="detections-header">
                  All Detections
                  @if (detectionsLoading.has(c.id)) {
                    <mat-spinner diameter="14" class="det-spinner"></mat-spinner>
                  } @else if (detectionsMap.get(c.id)?.length) {
                    <span class="det-count">{{ detectionsMap.get(c.id)!.length }}</span>
                  }
                </div>

                @if (!detectionsLoading.has(c.id) && detectionsMap.get(c.id)?.length) {
                  @for (det of detectionsMap.get(c.id)!; track det.id ?? $index) {
                    <div class="det-row">
                      <span [class]="'sev-dot sev-' + severityClass(det.severity)"></span>
                      <span class="det-rule mono">{{ det.detectionRule ?? det.name ?? '—' }}</span>
                      <span class="det-type">{{ det.type ?? '—' }}</span>
                      <span class="det-time">{{ det.time | date:'MM/dd HH:mm' }}</span>
                    </div>
                  }
                } @else if (!detectionsLoading.has(c.id) && detectionsMap.has(c.id)) {
                  <div class="no-det">No detections found</div>
                }
              </div>
            </div>
          </mat-expansion-panel>
        }
      </div>

      @if (data.total > data.cases.length) {
        <div class="more-hint">
          Showing {{ data.cases.length }} of {{ data.total }} cases
        </div>
      }
    </mat-dialog-content>

    <mat-dialog-actions align="end">
      <button mat-button (click)="ref.close()">Close</button>
    </mat-dialog-actions>
  `,
  styles: [`
    h2[mat-dialog-title] { display: flex; align-items: center; gap: 10px; }
    mat-dialog-content { padding-top: 4px !important; }

    .cases-list { display: flex; flex-direction: column; gap: 6px; }

    .case-panel {
      background: var(--siem-surface-elevated, #1c2128) !important;
      border: 1px solid rgba(255,255,255,.07) !important;
      border-radius: 6px !important;
    }

    .case-title {
      display: flex; align-items: center; gap: 8px;
      overflow: hidden;
    }
    .case-name {
      font-size: 13px; font-weight: 500;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      max-width: 360px;
    }
    .case-meta {
      display: flex; align-items: center; gap: 8px; flex-shrink: 0;
    }
    .case-date { font-size: 11px; color: #8b949e; }

    .sev-dot {
      width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
    }
    .sev-critical { background: #da3633; }
    .sev-high     { background: #f85149; }
    .sev-medium   { background: #d29922; }
    .sev-low      { background: #3fb950; }

    .status-chip {
      padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 500;
    }
    .status-new        { background: rgba(88,166,255,.15); color: #58a6ff; }
    .status-open       { background: rgba(210,153,34,.15); color: #d29922; }
    .status-closed     { background: rgba(139,148,158,.15); color: #8b949e; }
    .status-inProgress { background: rgba(127,119,221,.15); color: #7F77DD; }

    .case-body { padding: 4px 0 8px; }
    .case-row {
      display: flex; align-items: flex-start; gap: 12px;
      padding: 4px 0; font-size: 13px;
      border-bottom: 1px solid rgba(255,255,255,.04);
    }
    .lbl { min-width: 70px; color: #8b949e; flex-shrink: 0; }
    .val { flex: 1; word-break: break-word; }
    .mono { font-family: monospace; font-size: 12px; }

    .detection-block {
      margin-top: 10px; padding: 10px 12px;
      background: rgba(127,119,221,.07);
      border: 1px solid rgba(127,119,221,.2);
      border-radius: 6px;
    }
    .detection-header {
      font-size: 11px; font-weight: 600; color: #7F77DD;
      text-transform: uppercase; letter-spacing: .06em;
      margin-bottom: 6px;
    }

    .sev-label { font-weight: 500; }
    .sev-label.sev-critical { color: #da3633; }
    .sev-label.sev-high     { color: #f85149; }
    .sev-label.sev-medium   { color: #d29922; }
    .sev-label.sev-low      { color: #3fb950; }

    .mitre-row { align-items: flex-start; }
    .mitre-chips { display: flex; flex-wrap: wrap; gap: 4px; }
    .mitre-chip {
      padding: 1px 7px; border-radius: 4px; font-size: 11px; font-family: monospace;
      background: rgba(218,54,51,.12); color: #f85149;
      border: 1px solid rgba(218,54,51,.2);
    }

    .more-hint {
      text-align: center; font-size: 12px; color: #8b949e;
      padding: 12px 0 4px;
    }

    .detections-section { margin-top: 12px; }
    .detections-header {
      display: flex; align-items: center; gap: 8px;
      font-size: 11px; font-weight: 600; color: #da3633;
      text-transform: uppercase; letter-spacing: .06em;
      margin-bottom: 6px;
    }
    .det-count {
      background: rgba(218,54,51,.15); color: #f85149;
      padding: 1px 7px; border-radius: 10px; font-size: 11px;
    }
    .det-spinner { display: inline-block; }
    .det-row {
      display: flex; align-items: center; gap: 8px;
      padding: 3px 0; font-size: 12px;
      border-bottom: 1px solid rgba(255,255,255,.04);
    }
    .det-rule { flex: 1; font-size: 11px; }
    .det-type { color: #8b949e; font-size: 11px; flex-shrink: 0; }
    .det-time { color: #8b949e; font-size: 11px; flex-shrink: 0; }
    .no-det { font-size: 12px; color: #8b949e; padding: 4px 0; }
  `]
})
export class CasesDialogComponent {
  detectionsMap = new Map<string, any[]>();
  detectionsLoading = new Set<string>();

  constructor(
    public ref: MatDialogRef<CasesDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { cases: any[]; total: number },
    private sophos: SophosService,
  ) {}

  loadDetections(caseId: string): void {
    if (this.detectionsMap.has(caseId) || this.detectionsLoading.has(caseId)) return;
    this.detectionsLoading.add(caseId);
    this.sophos.getCaseDetections(caseId, { pageSize: 25 }).subscribe({
      next: (res) => {
        this.detectionsMap.set(caseId, res?.items ?? []);
        this.detectionsLoading.delete(caseId);
      },
      error: () => {
        this.detectionsMap.set(caseId, []);
        this.detectionsLoading.delete(caseId);
      }
    });
  }

  severityClass(sev: number): string {
    if (sev >= 9) return 'critical';
    if (sev >= 7) return 'high';
    if (sev >= 4) return 'medium';
    return 'low';
  }

  severityLabel(sev: number): string {
    if (sev >= 9) return 'Critical';
    if (sev >= 7) return 'High';
    if (sev >= 4) return 'Medium';
    return 'Low';
  }
}
