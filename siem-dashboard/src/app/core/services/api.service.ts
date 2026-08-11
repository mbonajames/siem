import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable, from, of } from 'rxjs';
import { switchMap, catchError, map } from 'rxjs/operators';
import { MsalService } from '@azure/msal-angular';
import { environment } from '../../../environments/environment';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base  = environment.apiBaseUrl;
  private scope = environment.msal.apiScope;
  private auth  = inject(AuthService);

  constructor(
    private http: HttpClient,
    private msal: MsalService,
  ) {}

  // Acquire a Bearer token silently from the MSAL cache.
  // If the account is unavailable or the silent call fails, resolves to null
  // (the request is sent without auth rather than redirecting the user).
  private token$(): Observable<string | null> {
    const account = this.msal.instance.getActiveAccount()
                  ?? this.msal.instance.getAllAccounts()[0]
                  ?? null;
    if (!account) return of(null);

    return from(
      this.msal.instance.acquireTokenSilent({ scopes: [this.scope], account })
    ).pipe(
      map(r => r.accessToken),
      catchError(() => of(null)),  // silent failure — never redirect
    );
  }

  private authHeaders(extra?: Record<string, string>): Observable<HttpHeaders> {
    return this.token$().pipe(
      map(token => {
        let h = new HttpHeaders(extra ?? {});
        if (token) h = h.set('Authorization', `Bearer ${token}`);
        // Always send the user email as a header so the backend can identify
        // the caller even when the custom-API access token lacks identity claims.
        const email = this.auth.user?.email;
        if (email) h = h.set('X-User-Email', email);
        return h;
      }),
    );
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
    return this.authHeaders(extraHeaders).pipe(
      switchMap(headers => this.http.get<T>(`${this.base}${path}`, { params: p, headers })),
    );
  }

  post<T>(path: string, body: any, params?: Record<string, any>, extraHeaders?: Record<string, string>): Observable<T> {
    let p = new HttpParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v != null) p = p.set(k, String(v));
      });
    }
    return this.authHeaders(extraHeaders).pipe(
      switchMap(headers => this.http.post<T>(`${this.base}${path}`, body, { params: p, headers })),
    );
  }

  put<T>(path: string, body: any, extraHeaders?: Record<string, string>): Observable<T> {
    return this.authHeaders(extraHeaders).pipe(
      switchMap(headers => this.http.put<T>(`${this.base}${path}`, body, { headers })),
    );
  }

  patch<T>(path: string, body: any, extraHeaders?: Record<string, string>): Observable<T> {
    return this.authHeaders(extraHeaders).pipe(
      switchMap(headers => this.http.patch<T>(`${this.base}${path}`, body, { headers })),
    );
  }

  delete<T>(path: string, extraHeaders?: Record<string, string>): Observable<T> {
    return this.authHeaders(extraHeaders).pipe(
      switchMap(headers => this.http.delete<T>(`${this.base}${path}`, { headers })),
    );
  }
}
