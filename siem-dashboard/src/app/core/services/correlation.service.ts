import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export type EntityType = 'user' | 'device' | 'ip' | 'hash';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Source = 'wazuh' | 'sophos' | 'darktrace' | 'email' | 'jira';

export interface CorrelatedEvent {
  id: string;
  timestamp: string;
  source: Source;
  severity: Severity;
  title: string;
  description: string;
  agent: string;
  tags: string[];
  rule_id?: string;
  rule_level?: number;
  sophos_id?: string;
  sophos_endpoint_id?: string;
  network_message_id?: string;
  delivery_action?: string;
  jira_key?: string;
  raw: any;
}

export interface Insight {
  type: string;
  severity: Severity;
  title: string;
  detail: string;
  related_ids: string[];
}

export interface SourceStat {
  count: number;
  critical: number;
  high: number;
}

export interface CorrelationResult {
  entity: { type: EntityType; value: string; days: number };
  total: number;
  events: CorrelatedEvent[];
  source_stats: Record<Source, SourceStat>;
  insights: Insight[];
  errors: Record<string, string>;
}

@Injectable({ providedIn: 'root' })
export class CorrelationService {
  constructor(private api: ApiService) {}

  investigate(payload: {
    entity_type: EntityType;
    entity_value: string;
    days?: number;
  }): Observable<CorrelationResult> {
    return this.api.post('/correlation/investigate/', payload);
  }

  createTicket(payload: {
    entity_type: string;
    entity_value: string;
    total: number;
    insights: Insight[];
    days: number;
    priority?: string;
    notes?: string;
  }): Observable<any> {
    return this.api.post('/correlation/ticket/', payload);
  }
}
