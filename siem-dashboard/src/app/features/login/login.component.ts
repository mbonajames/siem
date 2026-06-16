import { Component, OnInit, OnDestroy, inject } from '@angular/core';
import { Router } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MsalBroadcastService } from '@azure/msal-angular';
import { InteractionStatus } from '@azure/msal-browser';
import { Subject, filter, take, takeUntil } from 'rxjs';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [MatButtonModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss',
})
export class LoginComponent implements OnInit, OnDestroy {
  private readonly auth      = inject(AuthService);
  private readonly router    = inject(Router);
  private readonly broadcast = inject(MsalBroadcastService);
  private readonly destroy$  = new Subject<void>();

  ngOnInit(): void {
    // Wait for MSAL to finish processing any in-progress redirect before deciding
    // whether to show the login card or forward the user to the dashboard.
    this.broadcast.inProgress$.pipe(
      filter(status => status === InteractionStatus.None),
      take(1),
      takeUntil(this.destroy$),
    ).subscribe(() => {
      if (this.auth.account) {
        this.router.navigate(['/dashboard'], { replaceUrl: true });
      }
    });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  signIn(): void {
    this.auth.login();
  }
}
