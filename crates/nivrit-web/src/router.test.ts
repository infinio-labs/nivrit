import { describe, expect, test } from 'vitest';
import { parseRoute, routeToPath, type Route } from './router';

const at = (href: string) => parseRoute(new URL(href, 'http://localhost'));

describe('parseRoute', () => {
  test('the root is the auth screen', () => {
    expect(at('/')).toEqual({ name: 'auth' });
  });

  test('an unknown path falls back to auth rather than a blank page', () => {
    expect(at('/nonsense/deep/path')).toEqual({ name: 'auth' });
  });

  test('dashboard tabs are addressable', () => {
    expect(at('/app/secrets')).toEqual({ name: 'dashboard', tab: 'secrets' });
    expect(at('/app/audit')).toEqual({ name: 'dashboard', tab: 'audit' });
    expect(at('/app/tokens')).toEqual({ name: 'dashboard', tab: 'tokens' });
  });

  test('/app with no tab defaults to secrets', () => {
    expect(at('/app')).toEqual({ name: 'dashboard', tab: 'secrets' });
  });

  test('an unrecognised tab falls back to secrets', () => {
    // Someone editing the URL by hand should not reach a dead view.
    expect(at('/app/not-a-tab')).toEqual({ name: 'dashboard', tab: 'secrets' });
  });

  test('a reset link is recognised by its token', () => {
    expect(at('/reset-password?token=abc123')).toEqual({ name: 'reset', token: 'abc123' });
  });

  test('an OAuth callback needs all three parameters', () => {
    expect(at('/?provider=github&code=xyz&state=st')).toEqual({
      name: 'oauth',
      provider: 'github',
      code: 'xyz',
      state: 'st',
    });
    // A partial callback is not a callback; treat it as an ordinary visit
    // rather than entering a flow that cannot complete.
    expect(at('/?provider=github&code=xyz')).toEqual({ name: 'auth' });
  });

  test('an OAuth callback takes precedence over a token parameter', () => {
    expect(at('/?provider=github&code=xyz&state=st&token=t')).toMatchObject({ name: 'oauth' });
  });

  test('the forgot-password screen has its own path', () => {
    expect(at('/forgot-password')).toEqual({ name: 'forgot' });
  });

  test('a spent reset path without a token returns to auth', () => {
    expect(at('/reset-password')).toEqual({ name: 'auth' });
  });
});

describe('routeToPath', () => {
  test('round-trips every dashboard tab', () => {
    for (const tab of ['secrets', 'members', 'audit', 'tokens', 'settings'] as const) {
      const route: Route = { name: 'dashboard', tab };
      expect(at(routeToPath(route))).toEqual(route);
    }
  });

  test('drops one-time parameters, so a token cannot be reached by going back', () => {
    expect(routeToPath({ name: 'reset', token: 'secret-token' })).toBe('/reset-password');
    expect(routeToPath({ name: 'oauth', provider: 'github', code: 'c', state: 's' })).toBe('/');
  });
});
