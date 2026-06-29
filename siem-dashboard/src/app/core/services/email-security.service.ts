import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface MitreTechnique {
  id: string;
  technique: string;
  tactics: string[];
}

export interface EmailRecord {
  // Identifiers
  Timestamp: string;
  NetworkMessageId: string;
  InternetMessageId: string;
  // Sender
  SenderFromAddress: string;
  SenderDisplayName: string;
  SenderDomain: string;
  SenderIPv4: string;
  SenderSHA256: string;
  // Recipient
  RecipientEmailAddress: string;
  AllRecipients: string[];
  // Content
  Subject: string;
  DeliveryAction: string;
  DeliveryLocation: string;
  // Threat
  ThreatTypes: string;
  Verdict: string;
  UrlCount: number;
  AttachmentCount: number;
  IpCount: number;
  // Alert metadata
  Severity: string;
  Status: string;
  AlertTitle: string;
  AlertDescription: string;
  Category: string;
  Classification: string;
  Determination: string;
  DetectionSource: string;
  ServiceSource: string;
  ThreatFamily: string;
  Actor: string;
  AlertUrl: string;
  // Incident linkage
  IncidentId: string;
  IncidentUrl: string;
  IncidentTitle: string;
  IncidentSeverity: string;
  IncidentStatus: string;
  IncidentClassification: string;
  IncidentDetermination: string;
  IncidentAssignedTo: string;
  IncidentTags: string[];
  // Timeline
  FirstActivity: string;
  LastActivity: string;
  ResolvedAt: string;
  MitreTechniques: MitreTechnique[];
  Domains: string[];
  FileHashes: string[];
  // Compat
  AuthenticationDetails: string;
  OrgLevelPolicy: string;
  OrgLevelAction: string;
}

export interface EmailUrl {
  Url: string;
  UrlDomain: string;
  UrlLocation: string;
  ThreatTypes: string;
  Verdict: string;
  Remediation: string;
}

export interface EmailAttachment {
  FileName: string;
  FilePath: string;
  FileSize: number;
  FileType: string;
  SHA256: string;
  SHA1: string;
  MD5: string;
  ThreatTypes: string;
  Verdict: string;
  Remediation: string;
}

export interface EmailIp {
  IP: string;
  Country: string;
  Verdict: string;
  Remediation: string;
}

export interface EmailUser {
  UPN: string;
  Account: string;
  Domain: string;
  DisplayName: string;
  AadId: string;
  Verdict: string;
  Type: string;
}

export interface EmailComment {
  Text: string;
  Author: string;
  Created: string;
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
  ips: EmailIp[];
  users: EmailUser[];
  comments: EmailComment[];
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

// Evidence item from a Defender incident alert (returned by _extract_evidence)
export interface IncidentEvidence {
  type: string;         // 'email' | 'ip' | 'url' | 'file' | 'user' | 'device' | 'mailbox' | 'network' | ...
  verdict?: string;
  remediation?: string;
  // email (mailMessageEvidence)
  subject?: string;
  sender?: string;
  sender_display?: string;
  sender_domain?: string;
  recipient?: string;
  delivery?: string;
  sender_ip?: string;
  message_id?: string;
  // ip
  ip?: string;
  country?: string;
  // url
  url?: string;
  // file
  name?: string;
  path?: string;
  sha256?: string;
  sha1?: string;
  md5?: string;
  size?: number;
  // user
  upn?: string;
  account?: string;
  domain?: string;
  display_name?: string;
  // device
  hostname?: string;
  os?: string;
  // network
  remote_ip?: string;
  remote_port?: string;
  protocol?: string;
  // cloud app
  app_name?: string;
  // fallback for any unrecognised type
  raw?: Record<string, any>;
}

export interface DefenderIncidentAlert {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  category: string;
  classification: string;
  determination: string;
  serviceSource: string;
  detectionSource: string;
  threatFamily: string;
  actor: string;
  assignedTo: string;
  alertUrl: string;
  createdAt: string;
  lastActivity: string;
  evidence: IncidentEvidence[];
  mitreTechniques: MitreTechnique[];
}

export interface DefenderIncident {
  id: string;
  title: string;
  severity: string;
  status: string;
  classification: string;
  determination: string;
  assignedTo: string;
  tags: string[];
  incidentUrl: string;
  createdAt: string;
  lastUpdated: string;
  alerts: DefenderIncidentAlert[];
}

export interface IncidentAlert {
  AlertId: string;
  AlertTitle: string;
  Description: string;
  Severity: string;
  Status: string;
  Category: string;
  Classification: string;
  Determination: string;
  ServiceSource: string;
  DetectionSource: string;
  ThreatFamily: string;
  Actor: string;
  AlertUrl: string;
  CreatedAt: string;
  LastActivity: string;
  AssignedTo: string;
  EvidenceCounts: Record<string, number>;
  MitreTechniques: MitreTechnique[];
}

export interface IncidentDetail {
  IncidentId: string;
  Title: string;
  Severity: string;
  Status: string;
  Classification: string;
  Determination: string;
  AssignedTo: string;
  Tags: string[];
  IncidentUrl: string;
  CreatedAt: string;
  LastUpdated: string;
  AlertCount: number;
  Alerts: IncidentAlert[];
}

export interface VtResult {
  ioc_type: string;
  ioc_value: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  stats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout?: number };
  reputation?: number;
  country?: string;
  as_owner?: string;
  asn?: number;
  categories?: string[];
  registrar?: string;
  tags?: string[];
  meaningful_name?: string;
  type_description?: string;
  last_analysis_date?: number;
  top_detections?: { engine: string; category: string; result: string }[];
  permalink: string;
  // error state (populated by frontend catchError)
  _vtError?: boolean;
  _notFound?: boolean;
  error?: string;
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

  getIncident(incidentId: string): Observable<IncidentDetail> {
    return this.api.get<IncidentDetail>(`/incident/${encodeURIComponent(incidentId)}/`);
  }

  getIncidents(days = 7): Observable<{ incidents: DefenderIncident[]; total: number }> {
    return this.api.get('/incidents/', { days });
  }

  vtLookup(type: 'ip' | 'domain' | 'hash' | 'url', value: string): Observable<VtResult> {
    switch (type) {
      case 'url':    return this.api.get<VtResult>('/vt/url/', { url: value });
      case 'ip':     return this.api.get<VtResult>(`/vt/ip/${encodeURIComponent(value)}`);
      case 'domain': return this.api.get<VtResult>(`/vt/domain/${encodeURIComponent(value)}`);
      case 'hash':   return this.api.get<VtResult>(`/vt/hash/${encodeURIComponent(value)}`);
    }
  }
}
