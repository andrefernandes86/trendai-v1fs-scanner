import {test,expect} from '@playwright/test';
test('scanner response toggles separately and record refresh stays open with visible errors',async({page})=>{
 await page.goto('/');await page.getByRole('heading',{name:/^(Set up your scanner|Welcome back)$/}).waitFor();
 const setup=page.getByRole('button',{name:'Create administrator & continue'});if(await setup.isVisible()){await page.getByLabel('Create administrator password').fill('test-only-password-2026');await page.getByLabel('Confirm password').fill('test-only-password-2026');await setup.click()}else{await page.waitForTimeout(2100);await page.getByLabel('Administrator password').fill('test-only-password-2026');await page.getByRole('button',{name:'Sign in',exact:true}).click()}
 await expect(page.getByRole('heading',{name:'Security overview'})).toBeVisible();await page.getByLabel('Auto-refresh interval').selectOption('0');
 const record={id:'response-demo',key:'example-document.txt',profileName:'Document scanning',state:'QUARANTINED',verdict:'MALICIOUS',size:69,destination:'https://examplestorage.blob.core.windows.net/malicious/example-document.txt',scanResponseRecorded:true,detections:[]};
 await page.route('**/api/jobs/page?**',route=>route.fulfill({json:{items:[record],total:1,offset:0,limit:100}}));
 let failed=false,posts=0;
 await page.route('**/api/jobs/response-demo',route=>route.fulfill({status:failed?503:200,json:failed?{error:'Saved record temporarily unavailable'}:{...record,detections:[{name:'EICAR_TEST_FILE',engine:'ATSE'}]}}));
 await page.route('**/api/jobs/response-demo/scan-result',route=>route.fulfill({json:{response:{scanResult:1,foundMalwares:[{malwareName:'EICAR_TEST_FILE'}]}}}));
 page.on('request',req=>{if(req.url().includes('/recover'))posts++});
 await page.getByRole('button',{name:'File activity',exact:true}).click();await page.getByRole('button',{name:'example-document.txt',exact:true}).click();
 const drawer=page.getByRole('dialog',{name:'Record details'});
 await expect(drawer.locator('pre')).not.toBeVisible();
 await drawer.getByRole('button',{name:'Show scanner response',exact:true}).click();await expect(drawer.locator('#scanner-response-panel')).toContainText('EICAR_TEST_FILE');
 await drawer.getByRole('button',{name:'Hide scanner response',exact:true}).click();await expect(drawer.locator('#scanner-response-panel')).toHaveCount(0);
 failed=true;await drawer.getByRole('button',{name:'Refresh detection details',exact:true}).click();await expect(drawer.getByRole('alert')).toContainText('Saved record temporarily unavailable');
 failed=false;await drawer.getByRole('button',{name:'Refresh detection details',exact:true}).click();await expect(drawer.getByRole('status')).toContainText('Detection details refreshed');await expect(drawer.getByText('EICAR_TEST_FILE',{exact:true})).toBeVisible();await expect(drawer).toBeVisible();expect(posts).toBe(0);
 await drawer.getByRole('button',{name:'Show scanner response',exact:true}).click();await drawer.getByRole('button',{name:'Refresh detection details',exact:true}).click();await expect(drawer.locator('#scanner-response-panel')).toContainText('EICAR_TEST_FILE');
 if(test.info().project.name==='desktop')await drawer.screenshot({path:'docs/images/record-details.png'});
});
