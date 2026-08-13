import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

// Prevent multiple simultaneous redirects when several requests all return 401.
let redirecting = false;

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  return next(req).pipe(
    catchError(err => {
      if (err.status === 401 && !redirecting) {
        redirecting = true;
        auth.login();
      }
      return throwError(() => err);
    }),
  );
};
