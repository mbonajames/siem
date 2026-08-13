import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface GrafanaDashboard {
  id:           number;
  uid:          string;
  title:        string;
  url:          string;
  tags:         string[];
  folderTitle?: string;
  folderUid?:   string;
  type:         string;
  isStarred?:   boolean;
  // access-control fields injected by the SIEM backend
  owner:        string | null;
  shared_with:  string[];
  accessible:   boolean;
}

export interface GrafanaFolder {
  id:    number;
  uid:   string;
  title: string;
}

export interface GrafanaDatasource {
  id:   number;
  uid:  string;
  name: string;
  type: string;
}

export interface GrafanaConfig {
  configured:  boolean;
  public_url:  string;
}

export interface GrafanaSaveResult {
  id:      number;
  uid:     string;
  url:     string;
  status:  string;
  version: number;
}

@Injectable({ providedIn: 'root' })
export class GrafanaService {
  constructor(private api: ApiService) {}

  getConfig(): Observable<GrafanaConfig> {
    return this.api.get<GrafanaConfig>('/grafana/config');
  }

  listDashboards(q?: string): Observable<GrafanaDashboard[]> {
    return this.api.get<GrafanaDashboard[]>('/grafana/dashboards', q ? { q } : undefined);
  }

  listFolders(): Observable<GrafanaFolder[]> {
    return this.api.get<GrafanaFolder[]>('/grafana/folders');
  }

  listDatasources(): Observable<GrafanaDatasource[]> {
    return this.api.get<GrafanaDatasource[]>('/grafana/datasources');
  }

  getDashboard(uid: string): Observable<any> {
    return this.api.get<any>(`/grafana/dashboards/${uid}`);
  }

  /** Create new or overwrite existing dashboard. Pass overwrite:true to update. */
  saveDashboard(payload: {
    dashboard: Record<string, any>;
    folderUid?: string;
    overwrite?: boolean;
    message?: string;
  }): Observable<GrafanaSaveResult> {
    return this.api.post<GrafanaSaveResult>('/grafana/dashboards', payload);
  }

  deleteDashboard(uid: string): Observable<any> {
    return this.api.delete<any>(`/grafana/dashboards/${uid}`);
  }

  shareDashboard(uid: string, sharedWith: string[]): Observable<{ uid: string; owner: string; shared_with: string[] }> {
    return this.api.patch<any>(`/grafana/dashboards/${uid}/share`, { shared_with: sharedWith });
  }

  listUsers(q: string): Observable<{ users: string[] }> {
    return this.api.get<{ users: string[] }>('/users', q ? { q } : undefined);
  }

  provisionDatasources(): Observable<{ results: any[] }> {
    return this.api.post<{ results: any[] }>('/grafana/datasources/provision', {});
  }

  createFolder(title: string, uid?: string): Observable<GrafanaFolder> {
    return this.api.post<GrafanaFolder>('/grafana/folders', { title, uid });
  }
}
