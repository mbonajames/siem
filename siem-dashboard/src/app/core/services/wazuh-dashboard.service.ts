import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface WazuhDashboardConfig {
  configured: boolean;
  url:        string;
}

export interface DiscoverSearchRequest {
  query?:     string;
  index?:     string;
  time_from?: string;
  size?:      number;
  offset?:    number;
}

export interface DiscoverHit {
  '@timestamp'?: string;
  agent?:  { name?: string; id?: string };
  rule?:   { description?: string; level?: number; groups?: string[]; id?: string };
  data?:   Record<string, any>;
  [key: string]: any;
}

export interface DiscoverResult {
  total: number;
  hits:  DiscoverHit[];
}

export interface DiscoverFieldsResult {
  fields: string[];
}

@Injectable({ providedIn: 'root' })
export class WazuhDashboardService {
  constructor(private api: ApiService) {}

  getConfig(): Observable<WazuhDashboardConfig> {
    return this.api.get<WazuhDashboardConfig>('/wazuh-dashboard/config');
  }

  search(req: DiscoverSearchRequest): Observable<DiscoverResult> {
    return this.api.post<DiscoverResult>('/discover/search', req);
  }

  getFields(index?: string): Observable<DiscoverFieldsResult> {
    const params = index ? { index } : undefined;
    return this.api.get<DiscoverFieldsResult>('/discover/fields', params);
  }
}
