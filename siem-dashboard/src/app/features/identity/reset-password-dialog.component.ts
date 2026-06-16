import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';

@Component({
  selector: 'app-reset-password-dialog',
  standalone: true,
  imports: [CommonModule, MatDialogModule, MatButtonModule, MatIconModule, MatSnackBarModule],
  template: `
    <h2 mat-dialog-title>
      <mat-icon style="vertical-align:middle;margin-right:8px;color:var(--siem-medium)">key</mat-icon>
      Password Reset
    </h2>
    <mat-dialog-content>
      <p>Password reset for <strong>{{ data.user }}</strong>.</p>
      <p style="font-size:13px;color:var(--siem-text-secondary)">
        Share this temporary password securely. The user must change it on next sign-in.
      </p>
      <div class="temp-password-box">
        <code>{{ data.password }}</code>
        <button mat-icon-button (click)="copy()" matTooltip="Copy to clipboard">
          <mat-icon>content_copy</mat-icon>
        </button>
      </div>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-flat-button color="primary" (click)="ref.close()">Done</button>
    </mat-dialog-actions>
  `,
  styles: [`
    .temp-password-box {
      display: flex;
      align-items: center;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: 6px;
      padding: 10px 14px;
      margin-top: 12px;
      gap: 8px;
      code {
        flex: 1;
        font-size: 16px;
        letter-spacing: 2px;
        font-family: monospace;
        color: var(--siem-low);
      }
    }
  `]
})
export class ResetPasswordDialogComponent {
  constructor(
    public ref: MatDialogRef<ResetPasswordDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { user: string; password: string },
    private snackBar: MatSnackBar,
  ) {}

  copy(): void {
    navigator.clipboard.writeText(this.data.password).then(() => {
      this.snackBar.open('Copied to clipboard', '', { duration: 2000 });
    });
  }
}
