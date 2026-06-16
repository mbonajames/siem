import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatDividerModule } from '@angular/material/divider';
import { SettingsService, IntegrationConfig } from '../../core/services/settings.service';

interface IntegrationState {
  key: string;
  config: IntegrationConfig;
  formData: Record<string, string>;
  showSecrets: Record<string, boolean>;
  testStatus: 'idle' | 'testing' | 'connected' | 'error';
  testMessage: string;
  saving: boolean;
  expanded: boolean;
}

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [
    CommonModule, FormsModule, MatCardModule, MatButtonModule, MatIconModule,
    MatFormFieldModule, MatInputModule, MatProgressSpinnerModule, MatSnackBarModule,
    MatTooltipModule, MatExpansionModule, MatDividerModule,
  ],
  templateUrl: './settings.component.html',
  styleUrl: './settings.component.scss',
})
export class SettingsComponent implements OnInit {
  integrations: IntegrationState[] = [];
  loading = true;

  constructor(
    private settingsService: SettingsService,
    private snackBar: MatSnackBar,
  ) {}

  ngOnInit(): void {
    this.settingsService.getSettings().subscribe({
      next: (data) => {
        this.integrations = Object.entries(data).map(([key, config]) => ({
          key,
          config,
          formData: Object.fromEntries(
            Object.entries(config.fields).map(([k, f]) => [k, f.type === 'password' ? '' : f.value])
          ),
          showSecrets: {},
          testStatus: 'idle' as const,
          testMessage: '',
          saving: false,
          expanded: false,
        }));
        this.loading = false;
      },
      error: () => { this.loading = false; },
    });
  }

  fieldKeys(state: IntegrationState): string[] {
    return Object.keys(state.config.fields);
  }

  getInputType(state: IntegrationState, key: string): string {
    const field = state.config.fields[key];
    if (field.type === 'password') {
      return state.showSecrets[key] ? 'text' : 'password';
    }
    return 'text';
  }

  toggleSecret(state: IntegrationState, key: string): void {
    state.showSecrets[key] = !state.showSecrets[key];
  }

  save(state: IntegrationState): void {
    state.saving = true;
    this.settingsService.saveIntegration(state.key, state.formData).subscribe({
      next: () => {
        state.saving = false;
        // Refresh the configured status from backend
        this.settingsService.getSettings().subscribe(data => {
          const updated = data[state.key];
          if (updated) {
            state.config = updated;
            // Reset password fields after save
            Object.entries(updated.fields).forEach(([k, f]) => {
              if (f.type === 'password') state.formData[k] = '';
            });
          }
        });
        this.snackBar.open(`${state.config.label} credentials saved`, 'OK', { duration: 3000 });
        state.testStatus = 'idle';
      },
      error: (err) => {
        state.saving = false;
        this.snackBar.open(`Save failed: ${err.error?.error ?? err.message}`, 'Close', { duration: 5000 });
      },
    });
  }

  testConnection(state: IntegrationState): void {
    state.testStatus = 'testing';
    state.testMessage = '';
    this.settingsService.testConnection(state.key).subscribe({
      next: (res) => {
        state.testStatus = res.status;
        state.testMessage = res.message;
      },
      error: () => {
        state.testStatus = 'error';
        state.testMessage = 'Request failed';
      },
    });
  }

  configuredCount(): number {
    return this.integrations.filter(i => i.config.configured).length;
  }
}
