import { test, expect } from '@playwright/test';

/**
 * Browser smoke test that needs only a running API, not the Docker stack.
 *
 * `smoke.spec.ts` covers the full multi-user lifecycle but requires Docker
 * Compose via its global setup, so it tends not to get run. This one registers
 * a fresh account through the UI and exercises the paths that carry the most
 * risk of silent breakage: the WASM key derivation on register, the recovery
 * code dialog, secret round-tripping through client-side encryption, and the
 * tabs added since.
 *
 * Run with:
 *   NIVRIT_API=http://127.0.0.1:4000 bun run dev --port 5199   # in one shell
 *   bunx playwright test e2e/ui-smoke.spec.ts \
 *     --config playwright-standalone.config.ts
 */

const UNIQUE = Date.now();
const EMAIL = `ui-smoke-${UNIQUE}@example.com`;
// Must satisfy the shared policy: 12+ characters, and unrelated to the email.
const PASSWORD = 'harbour lantern glacier tuesday';

test('register, store a secret, and read it back through the UI', async ({ page }) => {
  const failures: string[] = [];
  page.on('pageerror', (e) => failures.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') failures.push(`console: ${m.text()}`);
  });

  await page.goto('/');

  // --- register -----------------------------------------------------------
  await page.getByRole('button', { name: 'Create account' }).first().click();
  await page.getByTestId('email-input').fill(EMAIL);
  await page.getByTestId('password-input').fill(PASSWORD);
  await page.getByTestId('auth-submit').click();

  // Registration runs several Argon2id derivations in WASM, so allow real time.
  const recoveryCode = page.getByTestId('recovery-code');
  await expect(recoveryCode).toBeVisible({ timeout: 60_000 });
  const code = (await recoveryCode.textContent())?.trim() ?? '';
  expect(code).toMatch(/^[A-Z0-9]{4}(-[A-Z0-9]{4}){5}$/);

  // The dialog must not be dismissable until the user acknowledges it.
  const continueButton = page.getByRole('button', { name: /continue to my vault/i });
  await expect(continueButton).toBeDisabled();
  await page.getByRole('checkbox').check();
  await expect(continueButton).toBeEnabled();
  await continueButton.click();

  // --- create org, project, environment -----------------------------------
  await page.getByTestId('org-name-input').fill('SmokeOrg');
  await page.getByTestId('org-slug-input').fill(`smoke-org-${UNIQUE}`);
  await page.getByTestId('create-org-btn').click();

  await page.getByTestId('org-select').selectOption({ label: 'SmokeOrg' });
  await page.getByTestId('project-name-input').fill('SmokeProject');
  await page.getByTestId('project-slug-input').fill(`smoke-proj-${UNIQUE}`);
  await page.getByTestId('create-project-btn').click();

  await page.getByTestId('project-select').selectOption({ label: 'SmokeProject' });
  await page.getByTestId('env-name-input').fill('Prod');
  await page.getByTestId('env-slug-input').fill(`prod-${UNIQUE}`);
  await page.getByTestId('create-env-btn').click();

  // --- a secret must survive the encrypt/decrypt round trip ---------------
  await page.getByTestId('secret-key-input').fill('API_KEY');
  await page.getByTestId('secret-value-input').fill('sk-live-ui-smoke');
  await page.getByTestId('set-secret-btn').click();

  await expect(page.getByText('API_KEY')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Show' }).first().click();
  await expect(page.getByText('sk-live-ui-smoke')).toBeVisible();

  // --- folders --------------------------------------------------------------
  // A secret filed into a folder used to be invisible here: the UI never sent
  // folder_id, and the server matches it exactly, so only root secrets came back.
  await page.getByTestId('folder-name-input').fill('database');
  await page.getByTestId('create-folder-btn').click();
  await page.getByTestId('folder-select').selectOption({ label: 'database' });

  // The root secret must not leak into the folder view.
  await expect(page.getByText('API_KEY')).toHaveCount(0);

  await page.getByTestId('secret-key-input').fill('DB_PASSWORD');
  await page.getByTestId('secret-value-input').fill('pg-in-folder');
  await page.getByTestId('set-secret-btn').click();
  await expect(page.getByText('DB_PASSWORD')).toBeVisible({ timeout: 15_000 });

  // Back to the root: the folder's secret must not appear there either.
  await page.getByTestId('folder-select').selectOption({ value: '' });
  await expect(page.getByText('API_KEY')).toBeVisible();
  await expect(page.getByText('DB_PASSWORD')).toHaveCount(0);

  // --- inheritance ----------------------------------------------------------
  // A second environment that imports the first should show the first's
  // secrets, marked as inherited, without duplicating them.
  await page.getByTestId('env-name-input').fill('Staging');
  await page.getByTestId('env-slug-input').fill(`staging-${UNIQUE}`);
  await page.getByTestId('create-env-btn').click();
  await page.getByTestId('env-select').selectOption({ label: 'Staging' });

  await expect(page.getByText('API_KEY')).toHaveCount(0);

  await page.getByTestId('import-source-select').selectOption({ label: 'Prod' });
  await page.getByTestId('create-import-btn').click();

  await expect(page.getByText('API_KEY')).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText('from Prod').first()).toBeVisible();

  // A local value of the same name must win over the inherited one.
  await page.getByTestId('secret-key-input').fill('API_KEY');
  await page.getByTestId('secret-value-input').fill('sk-staging-override');
  await page.getByTestId('set-secret-btn').click();
  await expect(page.getByText('from Prod')).toHaveCount(0, { timeout: 15_000 });
  await page.getByRole('button', { name: 'Show' }).first().click();
  await expect(page.getByText('sk-staging-override')).toBeVisible();

  await page.getByTestId('env-select').selectOption({ label: 'Prod' });

  // --- the tabs added alongside this work must at least render ------------
  await page.getByRole('button', { name: 'Access tokens' }).click();
  await expect(
    page.getByRole('heading', { name: 'Access tokens', exact: true })
  ).toBeVisible();

  await page.getByRole('button', { name: 'Audit log' }).click();
  await expect(page.getByRole('heading', { name: 'Audit log', exact: true })).toBeVisible();
  // This account is the project admin, so entries are visible rather than 403.
  await expect(page.getByText('write').first()).toBeVisible({ timeout: 15_000 });

  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

  // --- routing --------------------------------------------------------------
  // Views used to be React state only: nothing was linkable and back did
  // nothing. Each tab should now have its own URL and sit in history.
  await expect(page).toHaveURL(/\/app\/settings$/);

  await page.goBack();
  await expect(page).toHaveURL(/\/app\/audit$/);
  await expect(page.getByRole('heading', { name: 'Audit log', exact: true })).toBeVisible();

  await page.goForward();
  await expect(page).toHaveURL(/\/app\/settings$/);
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

  // --- project-key rotation (ADR 0008) ---------------------------------------
  // Mint a new key version, then confirm secrets from *before* the rotation
  // still decrypt -- proving the browser correctly picked up the version the
  // server tagged each ciphertext with, not just the one it just minted.
  await page.getByRole('button', { name: 'Members' }).click();
  await expect(page.getByRole('heading', { name: 'Members', exact: true })).toBeVisible();
  await page.getByTestId('rotate-key-btn').click();
  await expect(page.getByText(/rotated project key to version 2/i)).toBeVisible({
    timeout: 15_000,
  });

  await page.getByRole('button', { name: 'Secrets' }).click();
  await page.getByTestId('env-select').selectOption({ label: 'Prod' });
  await expect(page.getByText('API_KEY')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Show' }).first().click();
  await expect(page.getByText('sk-live-ui-smoke')).toBeVisible();

  // A secret written *after* rotation must also round-trip, under the new version.
  await page.getByTestId('secret-key-input').fill('POST_ROTATION_KEY');
  await page.getByTestId('secret-value-input').fill('sk-after-rotation');
  await page.getByTestId('set-secret-btn').click();
  await expect(page.getByText('POST_ROTATION_KEY')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Show' }).nth(1).click();
  await expect(page.getByText('sk-after-rotation')).toBeVisible();

  // --- environment RBAC overrides (ADR 0009/0010) ---------------------------
  // Set an override on the currently-selected environment (Prod), confirm it
  // shows up in the list with the right role badge, then remove it and
  // confirm the list goes back to empty. Targets this account itself (the
  // only project member available in a single-session smoke test) -- the
  // authz enforcement itself is covered by the Rust integration tests and a
  // live two-user script, not re-proven here; this only proves the UI calls
  // the right endpoints and renders what comes back.
  await page.getByRole('button', { name: 'Members' }).click();
  await expect(page.getByRole('heading', { name: 'Members', exact: true })).toBeVisible();

  await page.getByTestId('env-role-email-input').fill(EMAIL);
  await page.getByTestId('env-role-select').selectOption({ label: 'Viewer' });
  await page.getByTestId('env-role-set-btn').click();

  const overrideBadge = page.getByText('viewer', { exact: true });
  await expect(overrideBadge).toBeVisible({ timeout: 15_000 });

  await page.getByTestId(/env-role-remove-/).click();
  await expect(
    page.getByText('No overrides on this environment -- every member uses their project-level role.')
  ).toBeVisible({ timeout: 15_000 });

  // A 'none' override must be settable too -- it's the tier below Viewer that
  // gives an override the ability to deny, not just grant.
  await page.getByTestId('env-role-email-input').fill(EMAIL);
  await page.getByTestId('env-role-select').selectOption({ label: 'None' });
  await page.getByTestId('env-role-set-btn').click();
  await expect(page.getByText('none', { exact: true })).toBeVisible({ timeout: 15_000 });
  await page.getByTestId(/env-role-remove-/).click();

  // A React error would otherwise be invisible: the boundary renders a fallback
  // and the test would carry on past a broken page.
  expect(failures, `browser reported errors:\n${failures.join('\n')}`).toEqual([]);
});
