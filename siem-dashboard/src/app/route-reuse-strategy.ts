import { RouteReuseStrategy, DetachedRouteHandle, ActivatedRouteSnapshot } from '@angular/router';

/**
 * Keep heavy pages alive when navigating away so state (data, scroll, filters)
 * is preserved on return — no more values resetting to zero.
 */
export class SiemReuseStrategy implements RouteReuseStrategy {
  private handles = new Map<string, DetachedRouteHandle>();

  private readonly KEEP_ALIVE = new Set([
    'dashboard', 'devices', 'nessus',
    'alerts', 'network-security', 'email-security',
    'identity', 'jira', 'my-dashboards', 'my-dashboards/:id',
    'connectors', 'discover',
  ]);

  private key(r: ActivatedRouteSnapshot): string {
    const path = r.routeConfig?.path ?? '';
    // For parameterised routes, include param values so each unique URL gets
    // its own cached instance (e.g. /my-dashboards/uid1 ≠ /my-dashboards/uid2).
    const params = Object.values(r.params).join('/');
    return params ? `${path}::${params}` : path;
  }

  shouldDetach(route: ActivatedRouteSnapshot): boolean {
    return this.KEEP_ALIVE.has(route.routeConfig?.path ?? '');
  }

  store(route: ActivatedRouteSnapshot, handle: DetachedRouteHandle | null): void {
    if (handle) this.handles.set(this.key(route), handle);
  }

  shouldAttach(route: ActivatedRouteSnapshot): boolean {
    return this.handles.has(this.key(route));
  }

  retrieve(route: ActivatedRouteSnapshot): DetachedRouteHandle | null {
    return this.handles.get(this.key(route)) ?? null;
  }

  shouldReuseRoute(future: ActivatedRouteSnapshot, curr: ActivatedRouteSnapshot): boolean {
    if (future.routeConfig !== curr.routeConfig) return false;
    // Same route config but different params (e.g. navigating between dashboard UIDs)
    // must NOT reuse, otherwise ngOnInit never fires for the new params.
    return this.key(future) === this.key(curr);
  }
}
