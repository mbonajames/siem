import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ApiService } from './api.service';

@Injectable({ providedIn: 'root' })
export class SophosService {
  constructor(private api: ApiService) {}

  /** Convert our normalized device format to the shape devices.component.ts expects */
  private toEndpointFormat(d: any): any {
    return {
      id:               d.endpoint_id,
      hostname:         d.hostname,
      type:             d.type,
      os:               { name: d.os ?? '', platform: '', build: '' },
      health: {
        overall:  d.health_overall,
        threats:  { status: d.health_threats },
        services: { status: d.health_services },
      },
      isolation:        { status: d.isolated ? 'isolated' : 'notIsolated' },
      lastSeenAt:       d.last_seen,
      assignedProducts: (d.products ?? []).map((code: string) => ({ code, status: 'installed' })),
      tamperProtectionEnabled: d.tamper_protected,
      group:            d.group,
      ipv4Addresses:    d.ip_addresses ?? [],
      assignedUser:     d.assignedUser ?? null,
    };
  }

  getEndpoints(params?: { health?: string; type?: string; lockdown?: string }): Observable<any> {
    return this.api.get<any>('/endpoints', params).pipe(
      map((res: any) => ({ items: (res.devices ?? []).map((d: any) => this.toEndpointFormat(d)) }))
    );
  }

  getEndpoint(endpointId: string): Observable<any> {
    return this.api.get<any>(`/endpoints/${endpointId}`).pipe(
      map((d: any) => this.toEndpointFormat(d))
    );
  }

  getEndpointHealth(endpointId: string): Observable<any> {
    return this.api.get<any>(`/endpoints/${endpointId}/health`);
  }

  isolateEndpoint(endpointId: string, comment?: string): Observable<any> {
    const params = comment ? { comment } : {};
    return this.api.post(`/endpoints/${endpointId}/isolate`, {}, params);
  }

  removeIsolation(endpointId: string): Observable<any> {
    return this.api.post(`/endpoints/${endpointId}/unisolate`, {});
  }

  scanEndpoint(endpointId: string): Observable<any> {
    return this.api.post(`/endpoints/${endpointId}/scan`, {});
  }

  triggerUpdateCheck(endpointId: string): Observable<any> {
    return this.api.post(`/endpoints/${endpointId}/update-check`, {});
  }

  getTamperProtection(endpointId: string): Observable<any> {
    return this.api.get<any>(`/endpoints/${endpointId}/tamper-protection`);
  }

  setTamperProtection(endpointId: string, enabled: boolean): Observable<any> {
    return this.api.post(`/endpoints/${endpointId}/tamper-protection`, {}, { enabled: String(enabled) });
  }

  getHealthSummary(): Observable<any> {
    return this.api.get<any>('/endpoints/health/summary');
  }

  searchEndpoints(ip?: string, hostname?: string): Observable<any> {
    const params: Record<string, string> = {};
    if (ip) params['ip'] = ip;
    if (hostname) params['hostname'] = hostname;
    return this.api.get<any>('/endpoints/search', params);
  }

  // ── Stubs for components not yet migrated ─────────────────────────────────
  getAlerts(params?: { pageSize?: number; severity?: string }): Observable<any> {
    return this.api.get('/sophos/alerts/', params);
  }

  getCases(params?: { pageSize?: number }): Observable<any> {
    return this.api.get('/sophos/cases/', params);
  }

  getCaseDetections(caseId: string, params?: { pageSize?: number }): Observable<any> {
    return this.api.get(`/sophos/cases/${caseId}/detections/`, params);
  }

  getDetectionsSummary(): Observable<any> {
    return this.api.get('/sophos/detections-summary/');
  }

  getThreats(): Observable<any> {
    return this.api.get('/sophos/threats/');
  }
}
