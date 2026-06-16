import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

@Injectable({ providedIn: 'root' })
export class IdentityService {
  constructor(private api: ApiService) {}

  getRiskyUsers(params?: { top?: number; riskLevel?: string }): Observable<any> {
    return this.api.get('/identity/risky-users/', params);
  }

  getRiskySignIns(params?: { top?: number }): Observable<any> {
    return this.api.get('/identity/risky-signins/', params);
  }

  revokeSessions(userId: string): Observable<any> {
    return this.api.post(`/identity/users/${userId}/revoke-sessions/`, {});
  }

  resetPassword(userId: string): Observable<any> {
    return this.api.post(`/identity/users/${userId}/reset-password/`, {});
  }

  dismissRisk(userId: string): Observable<any> {
    return this.api.post(`/identity/users/${userId}/dismiss-risk/`, {});
  }
}
