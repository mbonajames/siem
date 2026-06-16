import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

@Injectable({ providedIn: 'root' })
export class DefenderService {
  constructor(private api: ApiService) {}

  getAlerts(params?: { top?: number; severity?: string }): Observable<any> {
    return this.api.get('/defender/alerts/', params);
  }

  getEmailThreats(top = 50): Observable<any> {
    return this.api.get('/defender/threats/email/', { top });
  }

  getSecureScore(): Observable<any> {
    return this.api.get('/defender/secure-score/');
  }

  getIncidents(): Observable<any> {
    return this.api.get('/defender/incidents/');
  }
}
