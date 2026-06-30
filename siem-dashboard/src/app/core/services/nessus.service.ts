import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, from, of } from 'rxjs';
import { concatMap, toArray, map, catchError } from 'rxjs/operators';
import { ApiService } from './api.service';
import { environment } from '../../../environments/environment';

// ── Data models ───────────────────────────────────────────────────────────────

export interface VulnSummary {
  critical: number; high: number; medium: number; low: number; info: number;
  total_hosts: number; total_findings: number;
}

export interface VulnScanSummary {
  id: string; scan_id: string; mfi: string; quarter: string; year: number;
  scan_type: 'internal' | 'external';
  branch?: string;
  storage_path?: string;
  uploaded_at: string; filename: string; summary: VulnSummary;
}

export interface VulnFindingWithContext extends VulnFinding {
  scan_id:   string;
  filename:  string;
  branch:    string;
  scan_type: 'internal' | 'external';
}

export interface VulnHost {
  name: string; ip: string; os: string; fqdn: string;
  critical: number; high: number; medium: number; low: number; info: number;
}

export interface VulnFinding {
  plugin_id: string; plugin_name: string;
  severity: string; severity_num: number;
  host: string; port: string; protocol: string; svc_name: string;
  description: string; solution: string; risk_factor: string;
  cvss_base: number | null; cvss3_base: number | null;
  cve: string[]; see_also: string; plugin_output: string;
}

export interface VulnScan extends VulnScanSummary {
  hosts: VulnHost[];
  findings: VulnFinding[];
}

export interface VulnTrendPoint {
  mfi: string; quarter: string; year: number;
  scan_type: 'internal' | 'external'; summary: VulnSummary;
}

export interface VulnUploadResult {
  uploaded: VulnScanSummary[];
  errors:   { filename: string; error: string }[];
}

export interface ScanGroup {
  mfi: string; year: number; quarter: string;
  internal: VulnScanSummary[];
  external: VulnScanSummary[];
}

// ── Service ───────────────────────────────────────────────────────────────────

@Injectable({ providedIn: 'root' })
export class NessusService {
  private base = environment.apiBaseUrl;

  constructor(private api: ApiService, private http: HttpClient) {}

  private _uploadOne(
    file: File, mfi: string, quarter: string,
    year: number, scanType: 'internal' | 'external', branch?: string,
  ): Observable<VulnScanSummary> {
    const form = new FormData();
    form.append('file', file);
    let params = new HttpParams()
      .set('mfi', mfi).set('quarter', quarter)
      .set('year', year.toString()).set('scan_type', scanType);
    if (branch) params = params.set('branch', branch);
    return this.http.post<VulnScanSummary>(`${this.base}/vuln/upload`, form, { params });
  }

  uploadScans(
    files: File[], mfi: string, quarter: string,
    year: number, scanType: 'internal' | 'external', branch?: string,
  ): Observable<VulnUploadResult> {
    return from(files).pipe(
      concatMap(file =>
        this._uploadOne(file, mfi, quarter, year, scanType, branch).pipe(
          map(scan  => ({ ok: scan,  filename: file.name, err: null  as string | null })),
          catchError(e => of({ ok: null as VulnScanSummary | null,
                               filename: file.name, err: this._errMsg(e) })),
        ),
      ),
      toArray(),
      map(results => ({
        uploaded: results.filter(r => r.ok).map(r => r.ok!),
        errors:   results.filter(r => r.err).map(r => ({ filename: r.filename, error: r.err! })),
      })),
    );
  }

  listScans(mfi?: string): Observable<{ scans: VulnScanSummary[] }> {
    const params: Record<string, string> = {};
    if (mfi) params['mfi'] = mfi;
    return this.api.get('/vuln/scans', params);
  }

  getScan(id: string): Observable<VulnScan> {
    return this.api.get(`/vuln/scans/${id}`);
  }

  deleteScan(id: string): Observable<void> {
    return this.api.delete(`/vuln/scans/${id}`);
  }

  updateScanMeta(
    id: string,
    meta: Partial<Pick<VulnScanSummary, 'mfi' | 'branch' | 'quarter' | 'year' | 'scan_type'>>,
  ): Observable<VulnScanSummary> {
    return this.api.patch(`/vuln/scans/${id}`, meta);
  }

  getTrends(): Observable<{ trends: VulnTrendPoint[] }> {
    return this.api.get('/vuln/trends');
  }

  reportUrl(mfi: string, year: number, quarter: string,
            type: 'technical' | 'executive'): string {
    const p = new HttpParams()
      .set('mfi', mfi).set('year', year.toString()).set('quarter', quarter);
    return `${this.base}/vuln/report/${type}?${p.toString()}`;
  }

  static groupScans(scans: VulnScanSummary[]): ScanGroup[] {
    const map = new Map<string, ScanGroup>();
    for (const s of scans) {
      const key = `${s.mfi}||${s.year}||${s.quarter}`;
      if (!map.has(key)) {
        map.set(key, { mfi: s.mfi, year: s.year, quarter: s.quarter,
                       internal: [], external: [] });
      }
      const grp = map.get(key)!;
      if (s.scan_type === 'external') grp.external.push(s);
      else grp.internal.push(s);
    }
    return [...map.values()].sort((a, b) =>
      b.year !== a.year ? b.year - a.year : b.quarter.localeCompare(a.quarter),
    );
  }

  private _errMsg(e: any): string {
    return e?.error?.detail ?? e?.error?.error ?? e?.message ?? 'Unknown error';
  }
}
