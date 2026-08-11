import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface Connector {
  id:           string;
  name:         string;
  category:     string;
  description:  string;
  icon:         string;
  color:        string;
  configured:   boolean;
  status:       'connected' | 'disconnected' | 'not_configured' | 'unknown';
  last_checked: string | null;
}

export interface ConnectorTestResult {
  status:  string;
  detail:  string;
  checked: string;
}

@Injectable({ providedIn: 'root' })
export class ConnectorsService {
  constructor(private api: ApiService) {}

  list(): Observable<Connector[]> {
    return this.api.get<Connector[]>('/connectors');
  }

  test(id: string): Observable<ConnectorTestResult> {
    return this.api.get<ConnectorTestResult>(`/connectors/${id}/test`);
  }
}
