import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = environment.apiBaseUrl;

  constructor(private http: HttpClient) {}

  get<T>(path: string, params?: Record<string, any>, extraHeaders?: Record<string, string>): Observable<T> {
    let httpParams = new HttpParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v === undefined || v === null) return;
        if (Array.isArray(v)) {
          v.forEach(item => { httpParams = httpParams.append(k, String(item)); });
        } else {
          httpParams = httpParams.set(k, String(v));
        }
      });
    }
    const headers = extraHeaders ? new HttpHeaders(extraHeaders) : undefined;
    return this.http.get<T>(`${this.base}${path}`, { params: httpParams, headers });
  }

  post<T>(path: string, body: any, params?: Record<string, any>, extraHeaders?: Record<string, string>): Observable<T> {
    let httpParams = new HttpParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null) httpParams = httpParams.set(k, String(v));
      });
    }
    const headers = extraHeaders ? new HttpHeaders(extraHeaders) : undefined;
    return this.http.post<T>(`${this.base}${path}`, body, { params: httpParams, headers });
  }

  put<T>(path: string, body: any, extraHeaders?: Record<string, string>): Observable<T> {
    const headers = extraHeaders ? new HttpHeaders(extraHeaders) : undefined;
    return this.http.put<T>(`${this.base}${path}`, body, { headers });
  }

  patch<T>(path: string, body: any, extraHeaders?: Record<string, string>): Observable<T> {
    const headers = extraHeaders ? new HttpHeaders(extraHeaders) : undefined;
    return this.http.patch<T>(`${this.base}${path}`, body, { headers });
  }

  delete<T>(path: string, extraHeaders?: Record<string, string>): Observable<T> {
    const headers = extraHeaders ? new HttpHeaders(extraHeaders) : undefined;
    return this.http.delete<T>(`${this.base}${path}`, { headers });
  }
}
