import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface WazuhAlert {
  id: string;
  timestamp: string;
  rule: { id: string; level: number; description: string; groups: string[] };
  agent: { id: string; name: string; ip: string };
  data: Record<string, any>;
  full_log: string;
}

export interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: 'active' | 'disconnected' | 'pending' | 'never_connected';
  os: { platform: string; name: string; version: string };
  version: string;
  lastKeepAlive: string;
  dateAdd: string;
}

@Injectable({ providedIn: 'root' })
export class WazuhService {
  constructor(private api: ApiService) {}

  getAlerts(params?: { limit?: number; offset?: number; level?: number; hours?: number; agent_id?: string; search?: string }): Observable<any> {
    return this.api.get('/wazuh/alerts/', params);
  }

  getAlertStats(hours = 24): Observable<any> {
    return this.api.get('/wazuh/alerts/stats/', { hours });
  }

  getAgents(params?: { limit?: number; offset?: number; status?: string; search?: string }): Observable<any> {
    return this.api.get('/wazuh/agents/', params);
  }

  getRules(params?: { limit?: number; offset?: number; search?: string; level?: number }): Observable<any> {
    return this.api.get('/wazuh/rules/', params);
  }

  getDecoders(params?: { limit?: number; offset?: number; search?: string }): Observable<any> {
    return this.api.get('/wazuh/decoders/', params);
  }

  getSummary(): Observable<any> {
    return this.api.get('/wazuh/summary/');
  }
}
