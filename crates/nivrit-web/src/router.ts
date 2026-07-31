/**
 * Minimal routing over the History API.
 *
 * Nivrit had no router: the view was React state, and the OAuth and
 * password-reset entry points were detected by sniffing query parameters and
 * then erasing them with `replaceState`. That meant no view was linkable, the
 * back button did nothing, and a refresh always landed on sign-in.
 *
 * A router library would be perhaps 20 KB for six views with no nesting, no
 * loaders, and no code splitting — and every runtime dependency in this app runs
 * in the page that holds the user's private key (see docs/adr/0003). This is the
 * whole feature in a few dozen lines.
 *
 * Routes are paths so links work and the browser treats them as real
 * navigations. The nginx config already rewrites unknown paths to `index.html`,
 * so deep links resolve.
 */

export type Route =
  | { name: 'auth' }
  | { name: 'forgot' }
  | { name: 'reset'; token: string }
  | { name: 'oauth'; provider: string; code: string; state: string }
  | { name: 'dashboard'; tab: DashboardTab };

export type DashboardTab = 'secrets' | 'members' | 'audit' | 'tokens' | 'settings';

const TABS: DashboardTab[] = ['secrets', 'members', 'audit', 'tokens', 'settings'];

function isTab(value: string): value is DashboardTab {
  return (TABS as string[]).includes(value);
}

/**
 * Derive the current route from a URL.
 *
 * Exported and pure so it can be tested without a browser, which is most of the
 * value of having a router at all.
 */
export function parseRoute(url: URL): Route {
  const params = url.searchParams;

  // OAuth providers redirect back with these, and the reset email links with a
  // token. Both are query parameters rather than paths because the redirect
  // target is configured outside this app.
  const code = params.get('code');
  const provider = params.get('provider');
  const state = params.get('state');
  if (code && provider && state) {
    return { name: 'oauth', provider, code, state };
  }

  const token = params.get('token');
  if (token) return { name: 'reset', token };

  const segments = url.pathname.split('/').filter(Boolean);

  if (segments[0] === 'forgot-password') return { name: 'forgot' };
  if (segments[0] === 'reset-password') return { name: 'auth' };

  if (segments[0] === 'app') {
    const tab = segments[1] ?? 'secrets';
    return { name: 'dashboard', tab: isTab(tab) ? tab : 'secrets' };
  }

  return { name: 'auth' };
}

/** The canonical path for a route, used when navigating. */
export function routeToPath(route: Route): string {
  switch (route.name) {
    case 'auth':
      return '/';
    case 'forgot':
      return '/forgot-password';
    case 'reset':
      return '/reset-password';
    case 'oauth':
      return '/';
    case 'dashboard':
      return `/app/${route.tab}`;
  }
}

/** Push a route onto the history stack. */
export function navigate(route: Route): void {
  window.history.pushState({}, '', routeToPath(route));
  window.dispatchEvent(new PopStateEvent('popstate'));
}

/**
 * Replace the current entry.
 *
 * Used after consuming a one-time query parameter — an OAuth code or a reset
 * token should not stay in the address bar, in history, or in a `Referer`
 * header, and the user must not be able to navigate back onto a spent one.
 */
export function replaceRoute(route: Route): void {
  window.history.replaceState({}, '', routeToPath(route));
  window.dispatchEvent(new PopStateEvent('popstate'));
}
