import {test,expect} from '@playwright/test';
test('administrator password settings validate confirmation and show server errors',async({page})=>{
 await page.goto('/');await page.getByRole('heading',{name:/^(Set up your scanner|Welcome back)$/}).waitFor();const setup=page.getByRole('button',{name:'Create administrator & continue'});
 if(await setup.isVisible()){await page.getByLabel('Create administrator password').fill('test-only-password-2026');await page.getByLabel('Confirm password').fill('test-only-password-2026');await setup.click()}else{await page.waitForTimeout(2100);await page.getByLabel('Administrator password',{exact:true}).fill('test-only-password-2026');await page.getByRole('button',{name:'Sign in',exact:true}).click()}
 await page.getByRole('heading',{name:'Security overview'}).waitFor();
 await page.getByRole('button',{name:'Change administrator password',exact:true}).click();const dialog=page.getByRole('dialog',{name:'Change administrator password'});await expect(dialog).toBeVisible();
 if(test.info().project.name==='desktop')await dialog.screenshot({path:'docs/images/change-password.png'});
 await dialog.getByLabel('Current password',{exact:true}).fill('test-only-password-2026');await dialog.getByLabel('New password',{exact:true}).fill('new-test-password-2026');await dialog.getByLabel('Confirm new password',{exact:true}).fill('different-password-only');await dialog.getByRole('button',{name:'Change password',exact:true}).click();await expect(dialog.getByRole('alert')).toContainText('do not match');
 let fail=true;await page.route('**/api/account/password',route=>route.fulfill({status:fail?403:200,json:fail?{error:'Current password is incorrect.'}:{authenticated:true}}));
 await dialog.getByLabel('Confirm new password',{exact:true}).fill('new-test-password-2026');await dialog.getByRole('button',{name:'Change password',exact:true}).click();await expect(dialog.getByRole('alert')).toContainText('Current password is incorrect');
 fail=false;await dialog.getByRole('button',{name:'Change password',exact:true}).click();await expect(dialog).toHaveCount(0);await expect(page.getByText('Password changed. Other signed-in sessions have been signed out.')).toBeVisible();
 await page.getByRole('button',{name:'Change administrator password',exact:true}).click();await expect(dialog.getByLabel('Current password',{exact:true})).toHaveValue('');await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
});
