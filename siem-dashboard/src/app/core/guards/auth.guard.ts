import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { InteractionStatus } from '@azure/msal-browser';
import { MsalBroadcastService } from '@azure/msal-angular';
import { filter, map, take } from 'rxjs';
import { AuthService } from '../services/auth.service';

// Wait for MSAL to finish any in-progress interaction (including redirect handling)
// before checking the account. This is reliable regardless of APP_INITIALIZER timing.
export const authGuard: CanActivateFn = () => {
  const auth      = inject(AuthService);
  const router    = inject(Router);
  const broadcast = inject(MsalBroadcastService);

  return broadcast.inProgress$.pipe(
    filter(status => status === InteractionStatus.None),
    take(1),
    map(() => auth.account ? true : router.createUrlTree(['/login'])),
  );
};
