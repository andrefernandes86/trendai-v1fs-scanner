import {test,expect} from '@playwright/test';
test('scan errors allow explicit resubmission and manual delivery',async({page})=>{
 await page.goto('/');const setup=page.getByRole('button',{name:'Create administrator & continue'});await page.getByRole('heading',{name:/^(Set up your scanner|Welcome back)$/}).waitFor();
 if(await setup.isVisible()){await page.getByLabel('Create administrator password').fill('test-only-password-2026');await page.getByLabel('Confirm password').fill('test-only-password-2026');await setup.click()}else{await page.waitForTimeout(2100);await page.getByLabel('Administrator password',{exact:true}).fill('test-only-password-2026');await page.getByRole('button',{name:'Sign in',exact:true}).click()}
 await page.getByRole('heading',{name:'Security overview'}).waitFor();
 await page.route('**/api/jobs/page?**',r=>r.fulfill({json:{items:[{id:'failed-example',key:'example-report.csv',state:'HELD',verdict:'UNKNOWN',size:100,profileName:'Example',integrity:{phase:'COMPLETED'}}],total:1,offset:0,limit:100}}));
 let action='';await page.route('**/api/jobs/failed-example/resolve',r=>{action=r.request().postDataJSON().action;return r.fulfill({json:{jobId:'new-request'}})});
 await page.getByRole('button',{name:'File activity',exact:true}).click();await page.getByRole('button',{name:'Resubmit / move…',exact:true}).click();
 const dialog=page.getByRole('dialog',{name:'Resolve scan error'});await expect(dialog.getByLabel('Action')).toHaveValue('rescan');
 await dialog.getByLabel('Action').selectOption('clean');await expect(dialog).toContainText('does not mean the file is clean');
 if(test.info().project.name==='desktop')await dialog.screenshot({path:'../docs/images/resolve-scan-error.png'});
 await dialog.getByRole('button',{name:'Confirm and queue'}).click();expect(action).toBe('clean');
 await page.getByRole('button',{name:'Resubmit / move…',exact:true}).click();await dialog.getByRole('button',{name:'Confirm and queue'}).click();expect(action).toBe('rescan');
});
