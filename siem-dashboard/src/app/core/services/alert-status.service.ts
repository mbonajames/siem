import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface AlertStatus {
  alert_id:   string;
  status:     'new' | 'acknowledged' | 'closed';
  assignee:   string | null;
  tags:       string[];
  updated_by: string;
  updated_at: string;
  comments:   AlertComment[];
}

export interface AlertComment {
  author: string;
  text:   string;
  ts:     string;
}

export interface StatusUpdate {
  alert_id:  string;
  status:    'new' | 'acknowledged' | 'closed';
  assignee?: string;
  comment?:  string;
  tags?:     string[];
}

@Injectable({ providedIn: 'root' })
export class AlertStatusService {
  constructor(private api: ApiService) {}

  batchGet(alertIds: string[]): Observable<AlertStatus[]> {
    return this.api.get<AlertStatus[]>('/alert-status', { ids: alertIds.join(',') });
  }

  getOne(alertId: string): Observable<AlertStatus> {
    return this.api.get<AlertStatus>(`/alert-status/${alertId}`);
  }

  upsert(update: StatusUpdate): Observable<AlertStatus> {
    return this.api.post<AlertStatus>('/alert-status', update);
  }

  addComment(alertId: string, comment: string): Observable<AlertStatus> {
    return this.api.post<AlertStatus>(`/alert-status/${alertId}/comment`, { comment });
  }
}
