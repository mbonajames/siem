import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

@Injectable({ providedIn: 'root' })
export class DarktraceService {
  constructor(private api: ApiService) {}

  getAlerts(limit = 50): Observable<any> {
    return this.api.get('/darktrace/alerts/', { limit });
  }

  getDevices(count = 100): Observable<any> {
    return this.api.get('/darktrace/devices/', { count });
  }

  getSummaryStatistics(): Observable<any> {
    return this.api.get('/darktrace/summary-statistics/');
  }
}
