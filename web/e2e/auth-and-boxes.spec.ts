import { expect, test } from '@playwright/test'

const seedEmail = process.env.SEED_ADMIN_EMAIL ?? 'admin@example.local'
const seedPassword = process.env.SEED_ADMIN_PASSWORD ?? 'admin-dev-password-change-me'

// Names are generated per-run so the test is safe to re-run against a
// persistent db.
const stamp = () => new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)

test.describe('Storage Boxes UI', () => {
  test('sign in shows dashboard with live box count', async ({ page }) => {
    await page.goto('/')
    // Protected route redirects to /login.
    await expect(page).toHaveURL(/\/login/)
    await page.getByLabel('Email').fill(seedEmail)
    await page.getByLabel('Password').fill(seedPassword)
    await page.getByRole('button', { name: 'Sign in' }).click()

    // Landed on the dashboard.
    await expect(page).toHaveURL(/\/dashboard/)
    await expect(page.getByTestId('stat-box-count')).toBeVisible()
    await expect(page.locator('.user-chip')).toContainText(seedEmail)
  })

  test('create → unlock → upload → download → delete a box via the UI', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill(seedEmail)
    await page.getByLabel('Password').fill(seedPassword)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/dashboard/)

    await page.getByRole('link', { name: /All boxes/ }).click()
    await expect(page).toHaveURL(/\/boxes/)

    const boxName = `e2e-${stamp()}`
    const boxPassword = 'boxpass-ui-1'

    // Create a box.
    await page.getByLabel('Name').fill(boxName)
    await page.getByLabel(/Box password/).fill(boxPassword)
    await page.getByRole('button', { name: 'Create box' }).click()
    const row = page.getByTestId(`box-row-${boxName}`)
    await expect(row).toBeVisible()

    // Unlock.
    await row.click()
    const unlockPanel = page.getByRole('heading', { name: /Unlock “/ })
    await expect(unlockPanel).toBeVisible()
    await page.locator('section.card', { has: unlockPanel }).getByLabel('Password').fill(boxPassword)
    await page.locator('section.card', { has: unlockPanel }).getByRole('button', { name: 'Unlock' }).click()

    // Explorer visible.
    const explorerHeader = page.getByRole('heading', { name: boxName, exact: true })
    await expect(explorerHeader).toBeVisible()
    await expect(page.getByText('Empty folder')).toBeVisible()

    // Upload a file by setting an in-memory File on the hidden input.
    const filename = 'playwright.txt'
    const payload = Buffer.from(`hello from playwright at ${new Date().toISOString()}`)
    await page.locator('[data-testid="file-input"]').setInputFiles({
      name: filename,
      mimeType: 'text/plain',
      buffer: payload,
    })

    // The file appears in the table.
    const table = page.locator('table.file-table')
    await expect(table).toBeVisible()
    await expect(table.getByRole('row', { name: new RegExp(filename) })).toBeVisible()

    // Download and compare bytes.
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      table.getByRole('button', { name: 'Download' }).click(),
    ])
    const downloadPath = await download.path()
    const fs = await import('node:fs/promises')
    const got = await fs.readFile(downloadPath)
    expect(got.equals(payload)).toBe(true)

    // Delete the uploaded file via the row's Delete button, auto-confirming
    // the browser's window.confirm.
    page.once('dialog', (d) => d.accept())
    await table.getByRole('button', { name: `Delete /${filename}` }).click()
    await expect(table.getByRole('row', { name: new RegExp(filename) })).toHaveCount(0)

    // Lock, then delete the box from the sidebar list.
    await page.getByRole('button', { name: 'Lock' }).click()
    page.once('dialog', (d) => d.accept())
    await row.getByRole('button', { name: `Delete ${boxName}` }).click()
    await expect(row).toHaveCount(0)
  })

  test('logout ends the session', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill(seedEmail)
    await page.getByLabel('Password').fill(seedPassword)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/dashboard/)
    await page.getByRole('button', { name: 'Logout' }).click()
    await expect(page).toHaveURL(/\/login/)
    await page.goto('/boxes')
    await expect(page).toHaveURL(/\/login/)
  })
})
