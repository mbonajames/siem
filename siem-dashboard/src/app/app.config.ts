import { ApplicationConfig, provideZoneChangeDetection, APP_INITIALIZER } from '@angular/core';
import { provideRouter, RouteReuseStrategy, withEnabledBlockingInitialNavigation } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideHttpClient, withInterceptorsFromDi, HTTP_INTERCEPTORS } from '@angular/common/http';
import { routes } from './app.routes';
import { SiemReuseStrategy } from './route-reuse-strategy';
import { environment } from '../environments/environment';
import {
  IPublicClientApplication,
  PublicClientApplication,
  BrowserCacheLocation,
  LogLevel,
  InteractionType,
} from '@azure/msal-browser';
import {
  MsalService,
  MsalBroadcastService,
  MsalInterceptor,
  MSAL_INSTANCE,
  MSAL_INTERCEPTOR_CONFIG,
  MSAL_BROADCAST_CONFIG,
} from '@azure/msal-angular';
import { firstValueFrom } from 'rxjs';

function initMsal(msal: MsalService) {
  // navigateToLoginRequestUrl:false stops MSAL from calling router.navigateByUrl()
  // during APP_INITIALIZER (when the router isn't ready). MSAL cleans the URL via
  // history.replaceState(); Angular's router takes over after APP_INITIALIZER.
  // .catch() prevents auth errors (e.g. state mismatch) from crashing bootstrap.
  return () => firstValueFrom(
    msal.handleRedirectObservable({ navigateToLoginRequestUrl: false }),
    { defaultValue: null }
  ).catch(() => null);
}

const { clientId, tenantId, redirectUri, apiScope } = environment.msal;
const authority = `https://login.microsoftonline.com/${tenantId}`;

function msalInstanceFactory(): IPublicClientApplication {
  return new PublicClientApplication({
    auth: {
      clientId,
      authority,
      redirectUri,
      postLogoutRedirectUri: redirectUri,
    },
    cache: {
      cacheLocation: BrowserCacheLocation.SessionStorage,
    },
    system: {
      loggerOptions: {
        logLevel: LogLevel.Warning,
        piiLoggingEnabled: false,
      },
    },
  });
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes, withEnabledBlockingInitialNavigation()),
    provideAnimationsAsync(),
    provideHttpClient(withInterceptorsFromDi()),
    { provide: RouteReuseStrategy, useClass: SiemReuseStrategy },
    {
      provide: MSAL_INSTANCE,
      useFactory: msalInstanceFactory,
    },
    {
      provide: MSAL_INTERCEPTOR_CONFIG,
      useValue: {
        interactionType: InteractionType.Redirect,
        protectedResourceMap: new Map(),
        strictMatching: false,
      },
    },
    {
      provide: MSAL_BROADCAST_CONFIG,
      useValue: { eventsToReplay: 1 },
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: MsalInterceptor,
      multi: true,
    },
    MsalService,
    MsalBroadcastService,
    {
      provide: APP_INITIALIZER,
      useFactory: initMsal,
      deps: [MsalService],
      multi: true,
    },
  ],
};
