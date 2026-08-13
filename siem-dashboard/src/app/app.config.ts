import { ApplicationConfig, provideZoneChangeDetection, APP_INITIALIZER } from '@angular/core';
import { provideRouter, RouteReuseStrategy, withEnabledBlockingInitialNavigation } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { authInterceptor } from './core/interceptors/auth.interceptor';
import { routes } from './app.routes';
import { SiemReuseStrategy } from './route-reuse-strategy';
import { AuthService } from './core/services/auth.service';

function initAuth(auth: AuthService) {
  return (): Promise<void> => {
    auth.processCallbackIfNeeded();
    return Promise.resolve();
  };
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection(),
    provideRouter(routes, withEnabledBlockingInitialNavigation()),
    provideAnimationsAsync(),
    provideHttpClient(withInterceptors([authInterceptor])),
    { provide: RouteReuseStrategy, useClass: SiemReuseStrategy },
    {
      provide:    APP_INITIALIZER,
      useFactory: initAuth,
      deps:       [AuthService],
      multi:      true,
    },
  ],
};
