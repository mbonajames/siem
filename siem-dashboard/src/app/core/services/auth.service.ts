import { Injectable, inject } from '@angular/core';
import { MsalService, MsalBroadcastService } from '@azure/msal-angular';
import { AccountInfo, InteractionStatus, RedirectRequest } from '@azure/msal-browser';
import { Observable, filter, map, shareReplay } from 'rxjs';
import { environment } from '../../../environments/environment';

const { apiScope, redirectUri: postLogoutUri } = environment.msal;

export type AppRole = 'socadmin' | 'socanalyst';

export interface AuthUser {
  name: string;
  email: string;
  initials: string;
  roles: AppRole[];
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly msal = inject(MsalService);
  private readonly broadcast = inject(MsalBroadcastService);

  readonly isAuthenticated$: Observable<boolean> = this.broadcast.inProgress$.pipe(
    filter(status => status === InteractionStatus.None),
    map(() => this.msal.instance.getAllAccounts().length > 0),
    shareReplay(1),
  );

  get account(): AccountInfo | null {
    return this.msal.instance.getAllAccounts()[0] ?? null;
  }

  get user(): AuthUser | null {
    const acct = this.account;
    if (!acct) return null;
    const name = acct.name ?? acct.username;
    const email = acct.username;
    const roles = ((acct.idTokenClaims?.['roles'] as string[]) ?? []) as AppRole[];
const parts = name.trim().split(' ');
    const initials =
      parts.length >= 2
        ? (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
        : name.slice(0, 2).toUpperCase();
    return { name, email, initials, roles };
  }

  hasRole(role: AppRole): boolean {
    return this.user?.roles.includes(role) ?? false;
  }

  isAdmin(): boolean {
    return this.hasRole('socadmin');
  }

  login(): void {
    this.msal.loginRedirect({ scopes: ['openid', 'profile', 'email'] } as RedirectRequest);
  }

  logout(): void {
    this.msal.logoutRedirect({ postLogoutRedirectUri: postLogoutUri });
  }
}
