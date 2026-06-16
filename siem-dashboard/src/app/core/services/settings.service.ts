import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface IntegrationField {
  label: string;
  type: 'text' | 'password' | 'url';
  value: string;
  configured: boolean;
}

export interface IntegrationConfig {
  label: string;
  description: string;
  icon: string;
  configured: boolean;
  fields: Record<string, IntegrationField>;
}

export type SettingsResponse = Record<string, IntegrationConfig>;

@Injectable({ providedIn: 'root' })
export class SettingsService {
  constructor(private api: ApiService) {}

  getSettings(): Observable<SettingsResponse> {
    return this.api.get<SettingsResponse>('/settings/');
  }

  saveIntegration(integration: string, fields: Record<string, string>): Observable<any> {
    return this.api.patch('/settings/', { integration, fields });
  }

  testConnection(integration: string): Observable<{ status: 'connected' | 'error'; message: string }> {
    return this.api.post(`/settings/${integration}/test/`, {});
  }
}
