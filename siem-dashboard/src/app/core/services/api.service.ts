import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = environment.apiBaseUrl;
  private auth = inject(AuthService);

  constructor(private http: HttpClient) {}

  private headers(extra?: Record<string, string>): HttpHeaders {
    let h = new HttpHeaders();
    const token = this.auth.getToken();
    if (token) h = h.set('Authorization', `Bearer ${token}`);
    const email = this.auth.user?.email;
    if (email) h = h.set('X-User-Email', email);
    if (extra) Object.entries(extra).forEach(([k, v]) => { h = h.set(k, v); });
    return h;
  }

  get<T>(path: string, params?: Record<string, any>, extraHeaders?: Record<string, string>): Observable<T> {
    let p = new HttpParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v == null) return;
        if (Array.isArray(v)) v.forEach(i => { p = p.append(k, String(i)); });
        else p = p.set(k, String(v));
      });
    }
    return this.http.get<T>(`${this.base}${path}`, { params: p, headers: this.headers(extraHeaders) });
  }

  post<T>(path: string, body: any, params?: Record<string, any>, extraHeaders?: Record<string, string>): Observable<T> {
    let p = new HttpParams();
    if (params) Object.entries(params).forEach(([k, v]) => { if (v != null) p = p.set(k, String(v)); });
    return this.http.post<T>(`${this.base}${path}`, body, { params: p, headers: this.headers(extraHeaders) });
  }

  put<T>(path: string, body: any, extraHeaders?: Record<string, string>): Observable<T> {
    return this.http.put<T>(`${this.base}${path}`, body, { headers: this.headers(extraHeaders) });
  }

  patch<T>(path: string, body: any, extraHeaders?: Record<string, string>): Observable<T> {
    return this.http.patch<T>(`${this.base}${path}`, body, { headers: this.headers(extraHeaders) });
  }

  delete<T>(path: string, extraHeaders?: Record<string, string>): Observable<T> {
    return this.http.delete<T>(`${this.base}${path}`, { headers: this.headers(extraHeaders) });
  }
}
