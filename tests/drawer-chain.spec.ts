import {expect, test} from '@playwright/test';

test('opens a policy and its referenced address object', async ({page}) => {
  await page.goto('/');
  await page.getByRole('button', {name: /office office-net/i}).click();
  await expect(page.getByRole('region', {name: 'Edit office'})).toBeVisible();

  await page.getByRole('button', {name: 'office-net', exact: true}).click();
  const addressEditor = page.getByRole('region', {name: 'Edit office-net'});
  await expect(addressEditor).toBeVisible();
  await expect(page.getByText('This shared object is used by 4 configuration entries.')).toBeVisible();

  await addressEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(page.getByText('Draft: 1 changes')).toBeVisible();

  await page.keyboard.press('Escape');
  await expect(addressEditor).not.toBeVisible();
  await expect(page.getByRole('region', {name: 'Edit office'})).toBeVisible();
});
