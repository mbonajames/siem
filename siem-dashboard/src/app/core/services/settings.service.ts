import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface AuditLog {
  id:          string;
  timestamp:   string;
  user:        string;
  action:      string;
  resource:    string;
  outcome:     'success' | 'failure' | 'warning';
  ip_address?: string;
  details?:    string;
}

export interface AuditLogsPage {
  total: number;
  logs:  AuditLog[];
}

@Injectable({ providedIn: 'root' })
export class SettingsService {
  constructor(private api: ApiService) {}

  getAuditLogs(params: {
    limit?:   number;
    hours?:   number;
    outcome?: string;
  } = {}): Observable<AuditLogsPage> {
    const p: Record<string, any> = {};
    if (params.limit   != null) p['limit']   = params.limit;
    if (params.hours   != null) p['hours']   = params.hours;
    if (params.outcome)         p['outcome'] = params.outcome;
    return this.api.get<AuditLogsPage>('/audit-logs', p);
  }

  deleteAuditLog(id: string): Observable<void> {
    return this.api.delete<void>(`/audit-logs/${encodeURIComponent(id)}`);
  }

  clearAuditLogs(): Observable<{ deleted: number }> {
    return this.api.delete<{ deleted: number }>('/audit-logs');
  }
}
