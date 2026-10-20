import {test,expect} from '@playwright/test';
test('theme preference persists across pages, reload and sign out',async({page})=>{
 await page.emulateMedia({colorScheme:'light'});
 await page.goto('/');await page.getByRole('heading',{name:/^(Set up your scanner|Welcome back)$/}).waitFor();
 const toggle=page.getByRole('button',{name:'Dark mode',exact:true});
 await toggle.click();await expect(toggle).toHaveAttribute('aria-pressed','true');
 await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
 const setup=page.getByRole('button',{name:'Create administrator & continue'});
 if(await setup.isVisible()){
 await page.getByLabel('Create administrator password').fill('test-only-password-2026');
 await page.getByLabel('Confirm password').fill('test-only-password-2026');await setup.click();
 }else{await page.waitForTimeout(2100);await page.getByLabel('Administrator password').fill('test-only-password-2026');await page.getByRole('button',{name:'Sign in',exact:true}).click()}
 await expect(page.getByRole('heading',{name:'Security overview'})).toBeVisible();
 await expect(toggle).toHaveAttribute('aria-pressed','true');
 await expect(page.locator('.panel').first()).toHaveCSS('background-color','rgb(25, 37, 56)');
 await page.screenshot({path:`../test-results/theme-dark-${test.info().project.name}.png`,fullPage:true});
 await page.getByRole('button',{name:'Scan profiles',exact:true}).click();await page.getByRole('button',{name:/^(New profile|Create scan profile)$/}).first().click();
 await expect(page.locator('.modal').first()).toHaveCSS('background-color','rgb(25, 37, 56)');
 await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.reload();await expect(page.getByRole('heading',{name:'Scan profiles',exact:true})).toHaveCount(0); // Navigation starts at Overview.
 await expect(page.getByRole('heading',{name:'Security overview'})).toBeVisible();await expect(toggle).toHaveAttribute('aria-pressed','true');
 await toggle.click();await expect(page.locator('html')).toHaveAttribute('data-theme','light');
 await page.reload();await expect(page.getByRole('heading',{name:'Security overview'})).toBeVisible();await expect(toggle).toHaveAttribute('aria-pressed','false');
 await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page.getByRole('heading',{name:'Welcome back'})).toBeVisible();await expect(toggle).toHaveAttribute('aria-pressed','false');
});
