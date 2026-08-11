import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface NotificationConfig {
  teams_webhook_url?:      string;
  teams_webhook_url_masked?: string;
  enabled:                 boolean;
  min_severity:            'Critical' | 'High';
  poll_interval_secs:      number;
}

export interface NotificationStatus {
  last_notified_at:   string;
  webhook_configured: boolean;
}

@Injectable({ providedIn: 'root' })
export class NotificationsService {
  constructor(private api: ApiService) {}

  getConfig(): Observable<NotificationConfig> {
    return this.api.get<NotificationConfig>('/notifications/config');
  }

  saveConfig(config: NotificationConfig): Observable<{ ok: boolean }> {
    return this.api.post<{ ok: boolean }>('/notifications/config', config);
  }

  sendTest(): Observable<{ ok: boolean }> {
    return this.api.post<{ ok: boolean }>('/notifications/test', {});
  }

  getStatus(): Observable<NotificationStatus> {
    return this.api.get<NotificationStatus>('/notifications/status');
  }
}
