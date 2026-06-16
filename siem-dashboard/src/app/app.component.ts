import { Component, OnDestroy, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { MsalService, MsalBroadcastService } from '@azure/msal-angular';
import { InteractionStatus } from '@azure/msal-browser';
import { Subject, filter, takeUntil } from 'rxjs';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet],
  template: '<router-outlet />',
})
export class AppComponent implements OnInit, OnDestroy {
  private readonly destroying$ = new Subject<void>();

  constructor(
    private readonly msal: MsalService,
    private readonly broadcast: MsalBroadcastService,
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
  }

  ngOnDestroy(): void {
    this.destroying$.next();
    this.destroying$.complete();
  }
}
