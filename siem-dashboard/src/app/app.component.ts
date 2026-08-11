import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { MsalService, MsalBroadcastService } from '@azure/msal-angular';
import { EventType, InteractionStatus, AuthenticationResult } from '@azure/msal-browser';
import { Subject, filter, takeUntil } from 'rxjs';
import { GatewayService } from './core/services/gateway.service';
import { AuthService } from './core/services/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet],
  template: '<router-outlet />',
})
export class AppComponent implements OnInit, OnDestroy {
  private readonly destroying$ = new Subject<void>();

  private readonly auth = inject(AuthService);

  constructor(
    private readonly msal: MsalService,
    private readonly broadcast: MsalBroadcastService,
    private readonly gateway: GatewayService,
  ) {}

  ngOnInit(): void {
    // Keep the active account in sync as the auth state changes
    this.broadcast.inProgress$
      .pipe(
        filter(status => status === InteractionStatus.None),
        takeUntil(this.destroying$),
      )
      .subscribe(() => {
        const accounts = this.msal.instance.getAllAccounts();
        this.msal.instance.setActiveAccount(accounts[0] ?? null);
      });

    // Record a login audit event exactly once when MSAL completes a login flow.
    // Read email/name directly from the MSAL account in the event payload —
    // same source the HeaderComponent uses via AuthService — so the user is
    // always recorded without depending on token acquisition timing.
    this.msal.instance.addEventCallback(event => {
      if (event.eventType === EventType.LOGIN_SUCCESS) {
        const payload = event.payload as AuthenticationResult;
        if (payload?.account) {
          this.msal.instance.setActiveAccount(payload.account);
        }
        const acct = payload?.account;
        this.gateway.recordLogin(
          acct?.username ?? this.auth.user?.email,
          acct?.name    ?? this.auth.user?.name,
        ).subscribe();
      }
    });
  }

  ngOnDestroy(): void {
    this.destroying$.next();
    this.destroying$.complete();
  }
}
