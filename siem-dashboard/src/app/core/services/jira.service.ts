import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface JiraIssue {
  id: string;
  key: string;
  fields: {
    summary: string;
    status: { name: string; statusCategory: { colorName: string } };
    priority: { name: string; iconUrl: string };
    assignee: { displayName: string; emailAddress: string; avatarUrls: Record<string, string> } | null;
    created: string;
    updated: string;
    description: any;
    labels: string[];
    issuetype: { name: string; iconUrl: string };
  };
}

@Injectable({ providedIn: 'root' })
export class JiraService {
  constructor(private api: ApiService) {}

  getIssues(params?: { maxResults?: number; startAt?: number; status?: string; priority?: string; assignee?: string }): Observable<any> {
    return this.api.get('/jira/issues/', params);
  }

  getIssue(issueKey: string): Observable<any> {
    return this.api.get(`/jira/issues/${issueKey}/`);
  }

  createIssue(data: { summary: string; description: string; priority?: string; labels?: string[] }): Observable<any> {
    return this.api.post('/jira/issues/', data);
  }

  transitionIssue(issueKey: string, transitionId: string): Observable<any> {
    return this.api.put(`/jira/issues/${issueKey}/transition/`, { transitionId });
  }

  getComments(issueKey: string): Observable<any> {
    return this.api.get(`/jira/issues/${issueKey}/comments/`);
  }

  addComment(issueKey: string, body: string): Observable<any> {
    return this.api.post(`/jira/issues/${issueKey}/comments/`, { body });
  }

  getAutoTicketStatus(): Observable<any> {
    return this.api.get('/jira/auto-ticket/');
  }

  triggerAutoTicket(): Observable<any> {
    return this.api.post('/jira/auto-ticket/', {});
  }
}
