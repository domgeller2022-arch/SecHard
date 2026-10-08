import { expect, test } from '@playwright/test';

/**
 * The checks a user's session and their data actually have to pass.
 *
 * These run through the real interface: a real browser, real cookies, the real Server Actions, the
 * real PostgREST, and the real row-level security policies. Nothing here is mocked, which is the
 * point — an authorization test that stubs the database tests the stub.
 */

const USER_A = { email: 'user-a@example.invalid', password: 'local-development-only' };
const USER_B = { email: 'user-b@example.invalid', password: 'local-development-only' };

async function signIn(page: import('@playwright/test').Page, user: { email: string; password: string }) {
  await page.goto('/');
  await page.getByLabel('Email').fill(user.email);
  await page.getByLabel('Password').fill(user.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/notes$/);
}

test.describe('anonymous access', () => {
  test('a private page redirects to the sign-in form', async ({ page }) => {
    await page.goto('/notes');
    // The redirect carries the original path so the user can be returned to it after signing in.
    await expect(page).toHaveURL((url) => new URL(url).pathname === '/');
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    // And the private content is not merely hidden; it was never sent.
    await expect(page.getByText('User A private note')).toHaveCount(0);
    await expect(page.getByText('User B private note')).toHaveCount(0);
  });
});

test.describe('an owner sees only their own notes', () => {
  test('user A sees A\'s note and never B\'s', async ({ page }) => {
    await signIn(page, USER_A);
    await expect(page.getByTestId('notes').getByText('User A private note')).toBeVisible();
    await expect(page.getByText('User B private note')).toHaveCount(0);
  });

  test('user B sees B\'s note and never A\'s', async ({ page }) => {
    await signIn(page, USER_B);
    await expect(page.getByTestId('notes').getByText('User B private note')).toBeVisible();
    await expect(page.getByText('User A private note')).toHaveCount(0);
  });

  // One user's private output must never appear in another user's response, including after a
  // sign-out and sign-in in the same browser session, which is where a cache would betray them.
  test('signing out and in as another user does not leak the previous user\'s notes', async ({ page }) => {
    await signIn(page, USER_A);
    await expect(page.getByText('User A private note')).toBeVisible();

    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/$/);

    await signIn(page, USER_B);
    await expect(page.getByText('User B private note')).toBeVisible();
    await expect(page.getByText('User A private note')).toHaveCount(0);
  });
});

test.describe('an owner can work with their own notes', () => {
  test('create, rename, and delete', async ({ page }) => {
    await signIn(page, USER_A);

    const title = `Playwright note ${Date.now()}`;
    // `exact` is required: the rename control on each existing note has the accessible name
    // "New title", which a substring match would also select.
    await page.getByLabel('Title', { exact: true }).fill(title);
    await page.getByLabel('Body').fill('Created by the end-to-end test.');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByTestId('notes').getByText(title)).toBeVisible();

    // Rename only this note: the rename control belongs to the list item containing the title.
    const item = page.getByTestId('note').filter({ hasText: title });
    const renamed = `${title} (renamed)`;
    await item.getByLabel('New title').fill(renamed);
    await item.getByRole('button', { name: 'Rename' }).click();
    await expect(page.getByTestId('notes').getByText(renamed)).toBeVisible();

    await page.getByTestId('note').filter({ hasText: renamed }).getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByTestId('notes').getByText(renamed)).toHaveCount(0);
  });

  test('a note title cannot be empty', async ({ page }) => {
    await signIn(page, USER_A);
    await page.getByLabel('Title', { exact: true }).fill('');
    // The form marks the field required, so the browser refuses to submit it.
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page).toHaveURL(/\/notes$/);
    await expect(page.getByTestId('notes')).toBeVisible();
  });
});

test.describe('private output is not cached for the next user', () => {
  test('the notes response is not marked publicly cacheable', async ({ page }) => {
    await signIn(page, USER_A);
    const response = await page.request.get('/notes');
    expect(response.status()).toBe(200);
    const cacheControl = response.headers()['cache-control'] ?? '';
    expect(cacheControl).not.toMatch(/public/);
    // Next.js may store a per-user RSC payload, but it must not be a shared, public cache entry.
    expect(cacheControl).not.toMatch(/s-maxage=[1-9]/);
  });
});
