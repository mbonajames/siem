import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';

const { clientId, tenantId, redirectUri } = environment.msal;
const AUTHORITY  = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0`;
const TOKEN_KEY  = 'siem_id_token';
const NONCE_KEY  = 'siem_auth_nonce';
const LOGIN_RECORDED_KEY = 'siem_login_recorded';

export type AppRole = 'socadmin' | 'socanalyst';

export interface AuthUser {
  name:     string;
  email:    string;
  initials: string;
  roles:    AppRole[];
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private _claims: Record<string, any> | null = null;

  constructor() {
    this._loadFromStorage();
  }

  /** Called from APP_INITIALIZER — parses the Azure AD redirect fragment before routing starts. */
  processCallbackIfNeeded(): void {
    const hash = window.location.hash.substring(1);
    if (!hash.includes('id_token=')) return;

    const params  = new URLSearchParams(hash);
    const idToken = params.get('id_token');
    if (!idToken) return;

    try {
      const claims = this._decode(idToken);
      const nonce  = sessionStorage.getItem(NONCE_KEY);
      if (nonce && claims['nonce'] !== nonce) return;
      if ((claims['exp'] as number) * 1000 < Date.now()) return;

      sessionStorage.setItem(TOKEN_KEY, idToken);
      sessionStorage.removeItem(NONCE_KEY);
      this._claims = claims;
      history.replaceState({}, '', window.location.pathname);
    } catch { /* malformed token — ignore */ }
  }

  private _loadFromStorage(): void {
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) return;
    try {
      const claims = this._decode(token);
      if ((claims['exp'] as number) * 1000 > Date.now()) {
        this._claims = claims;
      } else {
        sessionStorage.removeItem(TOKEN_KEY);
      }
    } catch {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  }

  private _decode(token: string): Record<string, any> {
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - b64.length % 4) : '';
    return JSON.parse(atob(b64 + pad));
  }

  getToken(): string | null {
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) return null;
    try {
      const claims = this._decode(token);
      if ((claims['exp'] as number) * 1000 <= Date.now()) {
        sessionStorage.removeItem(TOKEN_KEY);
        this._claims = null;
        return null;
      }
    } catch { return null; }
    return token;
  }

  get account(): Record<string, any> | null {
    return this._claims;
  }

  get user(): AuthUser | null {
    if (!this._claims) return null;
    const name  = (this._claims['name'] as string) ?? (this._claims['preferred_username'] as string) ?? '';
    const email = (this._claims['preferred_username'] as string) ?? (this._claims['email'] as string) ?? '';
    const roles = ((this._claims['roles'] as string[]) ?? []) as AppRole[];
    const parts = name.trim().split(' ');
    const initials = parts.length >= 2
      ? (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
      : name.slice(0, 2).toUpperCase() || '??';
    return { name, email, initials, roles };
  }

  hasRole(role: AppRole): boolean {
    return this.user?.roles.includes(role) ?? false;
  }

  isAdmin(): boolean {
    return this.hasRole('socadmin');
  }

  markLoginRecorded(): void {
    sessionStorage.setItem(LOGIN_RECORDED_KEY, '1');
  }

  get loginAlreadyRecorded(): boolean {
    return !!sessionStorage.getItem(LOGIN_RECORDED_KEY);
  }

  login(): void {
    const nonce = crypto.randomUUID();
    const state = crypto.randomUUID();
    sessionStorage.setItem(NONCE_KEY, nonce);

    const params = new URLSearchParams({
      client_id:     clientId,
      response_type: 'id_token',
      redirect_uri:  redirectUri,
      scope:         'openid profile email',
      nonce,
      state,
      response_mode: 'fragment',
    });

    window.location.href = `${AUTHORITY}/authorize?${params}`;
  }

  logout(): void {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(NONCE_KEY);
    sessionStorage.removeItem(LOGIN_RECORDED_KEY);
    this._claims = null;
    window.location.href =
      `${AUTHORITY}/logout?post_logout_redirect_uri=${encodeURIComponent(redirectUri)}`;
  }
}
