import { RouteReuseStrategy, DetachedRouteHandle, ActivatedRouteSnapshot } from '@angular/router';

/**
 * Keep heavy pages alive when navigating away so state (data, scroll, filters)
 * is preserved on return — no more values resetting to zero.
 */
export class SiemReuseStrategy implements RouteReuseStrategy {
  private handles = new Map<string, DetachedRouteHandle>();

  private readonly KEEP_ALIVE = new Set([
    'dashboard', 'devices', 'rules', 'tickets', 'nessus', 'correlation'
  ]);

  private key(r: ActivatedRouteSnapshot): string {
    return r.routeConfig?.path ?? '';
  }

  shouldDetach(route: ActivatedRouteSnapshot): boolean {
    return this.KEEP_ALIVE.has(this.key(route));
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
    return future.routeConfig === curr.routeConfig;
  }
}
