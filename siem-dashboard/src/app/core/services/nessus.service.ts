import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import { environment } from '../../../environments/environment';

export interface NessusScan {
  id: number; uuid: string; name: string; status: string;
  folder_id: number | null;
  last_modification_date: number | null;
  creation_date: number | null;
  starttime: string; timezone: string;
}

export interface NessusFolder {
  id: number; name: string; type: string;
  scans: NessusScan[];
}

export interface NessusScanInfo {
  id: number; name: string; status: string;
  targets: string; scan_start: number | null; scan_end: number | null;
}

export interface NessusHost {
  host_id: number; hostname: string;
  critical: number; high: number; medium: number; low: number; info: number;
}

export interface NessusVuln {
  plugin_id: number; plugin_name: string;
  severity: number; severity_label: string; count: number; vuln_index: number;
}

export interface NessusHistoryEntry {
  history_id: number; uuid: string; status: string;
  creation_date: number | null; last_modification_date: number | null;
}

export interface NessusScanDetail {
  info: NessusScanInfo;
  hosts: NessusHost[];
  vulnerabilities: NessusVuln[];
  history: NessusHistoryEntry[];
}

@Injectable({ providedIn: 'root' })
export class NessusService {
  private base = environment.apiBaseUrl;

  constructor(private api: ApiService, private http: HttpClient) {}

  getFolders(): Observable<{ folders: NessusFolder[] }> {
    return this.api.get('/nessus/folders');
  }

  getScan(id: number, historyId?: number): Observable<NessusScanDetail> {
    const params: Record<string, any> = {};
    if (historyId != null) params['history_id'] = historyId;
    return this.api.get(`/nessus/scans/${id}`, params);
  }

  exportScan(id: number, format: string): Observable<Blob> {
    return this.http.post(
      `${this.base}/nessus/scans/${id}/export`,
      { format },
      { responseType: 'blob' },
    );
  }
}
