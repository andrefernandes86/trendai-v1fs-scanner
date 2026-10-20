import {test,expect} from '@playwright/test';
test('profile policy editor and responsive toolbar remain usable',async({page})=>{
 await page.goto('/');
 const setup=page.getByRole('button',{name:'Create administrator & continue'});
 if(await setup.isVisible()){
  await page.getByLabel('Create administrator password').fill('test-only-password-2026');
  await page.getByLabel('Confirm password').fill('test-only-password-2026');await setup.click();
 }else{await page.waitForTimeout(2100); // Respect server authentication throttle.
 await page.getByLabel('Administrator password').fill('test-only-password-2026');await page.getByRole('button',{name:'Sign in',exact:true}).click()}
 await expect(page.getByRole('heading',{name:'Security overview'})).toBeVisible();
 await expect(page.getByTestId('scan-metric-now')).toContainText('Scanning now');
 await expect(page.getByTestId('scan-metric-now')).toContainText('0');
 await expect(page.getByLabel('Auto-refresh interval')).toBeVisible();
 await page.getByLabel('Auto-refresh interval').selectOption('0');
 for(const id of ['source','clean','malicious','failed']){const result=await page.request.put('/api/mounts/e2e-'+id,{data:{id:'e2e-'+id,name:'E2E '+id,kind:'blob',account:'e2etestaccount',container:'e2e-'+id,authType:'sas',secret:'sig=test-only'}});expect(result.ok()).toBeTruthy()}
 const existing=await (await page.request.get('/api/profiles')).json();
 if(!existing.some((p:any)=>p.id==='e2e-policy')){const result=await page.request.put('/api/profiles/e2e-policy',{data:{id:'e2e-policy',name:'E2E policy',sourceMount:'e2e-source',goodMount:'e2e-clean',badMount:'e2e-malicious',failedMount:'e2e-failed',scanIntervalSeconds:30,enabled:false,revision:0}});expect(result.ok()).toBeTruthy()}
 await page.reload();await expect(page.getByRole('heading',{name:'Security overview'})).toBeVisible();
 await page.getByRole('button',{name:'Scan profiles',exact:true}).click();
 await expect(page.getByRole('heading',{name:'E2E policy',exact:true})).toBeVisible();
 const cardOverflow=await page.locator('.source-card').evaluate(el=>el.scrollWidth>el.clientWidth+2);expect(cardOverflow).toBe(false);
 await page.screenshot({path:`../test-results/cards-${test.info().project.name}.png`,fullPage:true});

 await expect(page.getByLabel('Auto-refresh interval')).toHaveCount(0);
 const create=page.getByRole('button',{name:'Create scan profile',exact:true});if(await create.isVisible()){await create.click()}else{await page.getByRole('button',{name:'New profile',exact:true}).click()}
 await expect(page.getByRole('heading',{name:'7. Exclusions & hold rules'})).toBeVisible();
 await page.getByRole('button',{name:'Add rule',exact:true}).click();
 await page.getByLabel('Rule name (unique)', {exact:true}).fill('skip-images');
 await page.getByLabel('Path/filename pattern').fill('*.png');
 await page.getByRole('combobox',{name:'Action',exact:true}).selectOption('exclude');
 await expect(page.getByLabel('Scan failed destination')).toBeVisible();
 await expect(page.getByRole('heading',{name:'8. Failed-file recovery'})).toBeVisible();
 await expect(page.getByLabel('Wait between recovery cycles (seconds)',{exact:true})).toBeDisabled();
 await page.getByLabel('Automatically rescan isolated unknown files',{exact:true}).check();
 await expect(page.getByLabel('Wait between recovery cycles (seconds)',{exact:true})).toBeEnabled();
 await page.screenshot({path:`../test-results/profile-${test.info().project.name}.png`,fullPage:true});
 const overflowing=await page.locator('[role="dialog"]').evaluate(el=>el.scrollWidth>el.clientWidth+2);expect(overflowing).toBe(false);
 await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.getByRole('button',{name:'File activity',exact:true}).click();
 await expect(page.getByLabel('Auto-refresh interval')).toHaveValue('0');
 await expect(page.getByRole('button',{name:'Preview cleanup',exact:true})).toBeVisible();
 await expect(page.getByRole('link',{name:'Export CSV',exact:true})).toBeVisible();
});
