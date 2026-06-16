import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface EmailRecord {
  Timestamp: string;
  NetworkMessageId: string;
  InternetMessageId: string;
  SenderFromAddress: string;
  SenderDisplayName: string;
  SenderIPv4: string;
  RecipientEmailAddress: string;
  Subject: string;
  DeliveryAction: string;
  DeliveryLocation: string;
  ThreatTypes: string;
  AuthenticationDetails: string;
  UrlCount: number;
  AttachmentCount: number;
  OrgLevelPolicy: string;
  OrgLevelAction: string;
}

export interface EmailUrl {
  Url: string;
  UrlDomain: string;
  UrlLocation: string;
  ThreatTypes: string;
}

export interface EmailAttachment {
  FileName: string;
  FileSize: number;
  FileType: string;
  SHA256: string;
  ThreatTypes: string;
  DetectionMethods: string;
}

export interface EmailPostDelivery {
  Timestamp: string;
  ActionType: string;
  ActionTrigger: string;
  ActionResult: string;
  DeliveryLocation: string;
}

export interface EmailDetail {
  urls: EmailUrl[];
  attachments: EmailAttachment[];
  post_delivery: EmailPostDelivery[];
}

export interface EmailStats {
  Total: number;
  Phishing: number;
  Malware: number;
  Spam: number;
  BEC: number;
  Blocked: number;
  Delivered: number;
  Quarantined: number;
}

export interface HuntingResult {
  results: any[];
  schema: any[];
}

export interface EmailSearchFilters {
  sender?: string;
  recipient?: string;
  subject?: string;
  threat_type?: string;
  delivery_action?: string;
  days?: number;
}

@Injectable({ providedIn: 'root' })
export class EmailSecurityService {
  constructor(private api: ApiService) {}

  searchEmails(filters: EmailSearchFilters): Observable<{ results: EmailRecord[] }> {
    const params: any = {};
    if (filters.sender)          params['sender']          = filters.sender;
    if (filters.recipient)       params['recipient']       = filters.recipient;
    if (filters.subject)         params['subject']         = filters.subject;
    if (filters.threat_type)     params['threat_type']     = filters.threat_type;
    if (filters.delivery_action) params['delivery_action'] = filters.delivery_action;
    if (filters.days)            params['days']            = filters.days;
    return this.api.get('/email/search/', params);
  }

  getStats(days = 7): Observable<EmailStats> {
    return this.api.get('/email/stats/', { days });
  }

  getDetail(networkMessageId: string): Observable<EmailDetail> {
    return this.api.get(`/email/${encodeURIComponent(networkMessageId)}/detail/`);
  }

  runHunt(query: string): Observable<HuntingResult> {
    return this.api.post('/email/hunt/', { query });
  }

  emailAction(payload: {
    user_id: string;
    internet_message_id: string;
    action: 'quarantine' | 'soft_delete' | 'hard_delete' | 'move_inbox' | 'move_junk';
  }): Observable<any> {
    return this.api.post('/email/action/', payload);
  }
}
