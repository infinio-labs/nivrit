import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const state = JSON.parse(
  readFileSync(join(import.meta.dirname, '.state', 'test-state.json'), 'utf-8')
);

test('web E2EE full lifecycle', async ({ page }) => {
  const orgSlug = `org-${Date.now()}`;
  const projectSlug = `proj-${Date.now()}`;
  const envSlug = `env-${Date.now()}`;

  await page.goto('/');

  // Log in as Alice.
  await page.getByTestId('email-input').fill(state.aliceEmail);
  await page.getByTestId('password-input').fill(state.password);
  await page.getByTestId('auth-submit').click();

  // Create organization.
  await page.getByTestId('org-name-input').fill('WebOrg');
  await page.getByTestId('org-slug-input').fill(orgSlug);
  await page.getByTestId('create-org-btn').click();

  // Select the new org and create a project.
  await page.getByTestId('org-select').selectOption({ label: 'WebOrg' });
  await page.getByTestId('project-name-input').fill('WebProject');
  await page.getByTestId('project-slug-input').fill(projectSlug);
  await page.getByTestId('create-project-btn').click();

  // Select the new project and create an environment.
  await page.getByTestId('project-select').selectOption({ label: 'WebProject' });
  await page.getByTestId('env-name-input').fill('Prod');
  await page.getByTestId('env-slug-input').fill(envSlug);
  await page.getByTestId('create-env-btn').click();

  // Select the new environment and set a secret.
  await page.getByTestId('env-select').selectOption({ label: 'Prod' });
  await page.getByTestId('secret-key-input').fill('WEB_KEY');
  await page.getByTestId('secret-value-input').fill('webvalue');
  await page.getByTestId('set-secret-btn').click();

  // Reveal the secret and verify its value.
  const aliceRow = page.locator('tr', { hasText: 'WEB_KEY' });
  await aliceRow.getByRole('button', { name: 'Show' }).click();
  await expect(aliceRow.getByText('webvalue')).toBeVisible();

  // Invite Bob to the project.
  await page.getByRole('button', { name: 'Members' }).click();
  await page.getByTestId('invite-email-input').fill(state.bobEmail);
  await page.getByTestId('invite-btn').click();

  // Log out and log in as Bob.
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await page.getByTestId('email-input').fill(state.bobEmail);
  await page.getByTestId('password-input').fill(state.password);
  await page.getByTestId('auth-submit').click();

  // Bob selects the shared org/project/env and sees the secret.
  await page.getByTestId('org-select').selectOption({ label: 'WebOrg' });
  await page.getByTestId('project-select').selectOption({ label: 'WebProject' });
  await page.getByTestId('env-select').selectOption({ label: 'Prod' });

  const bobRow = page.locator('tr', { hasText: 'WEB_KEY' });
  await bobRow.getByRole('button', { name: 'Show' }).click();
  await expect(bobRow.getByText('webvalue')).toBeVisible();

  // Bob deletes the secret.
  page.on('dialog', (dialog) => dialog.accept());
  await bobRow.getByRole('button', { name: 'Delete' }).click();

  // Verify the secret is gone.
  await expect(page.locator('tr', { hasText: 'WEB_KEY' })).not.toBeVisible();
});
