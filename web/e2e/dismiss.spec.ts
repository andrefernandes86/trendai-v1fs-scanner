import {test,expect} from '@playwright/test';
test('held review includes hidden missing files and dismisses without browser confirmation',async({page})=>{
 await page.goto('/');await page.getByRole('heading',{name:/^(Set up your scanner|Welcome back)$/}).waitFor();
 if(await page.getByRole('button',{name:'Create administrator & continue'}).isVisible()){await page.getByLabel('Create administrator password').fill('test-only-password-2026');await page.getByLabel('Confirm password').fill('test-only-password-2026');await page.getByRole('button',{name:'Create administrator & continue'}).click()}else{await page.waitForTimeout(2100);await page.getByLabel('Administrator password',{exact:true}).fill('test-only-password-2026');await page.getByRole('button',{name:'Sign in',exact:true}).click()}
 await page.getByRole('heading',{name:'Security overview'}).waitFor();await page.getByLabel('Auto-refresh interval').selectOption('0');
 let state='HELD',calls=0,deny=true;
 const file=()=>({id:'missing-file',key:'deleted-example.csv',state,hidden:true,size:123,verdict:'UNKNOWN',profileName:'Example profile',error:'Source is unavailable.'});
 await page.route('**/api/assurance',r=>r.fulfill({json:{heldFiles:state==='HELD'?1:0,alerts:[],unaccountedSourceVersions:0}}));
 await page.route('**/api/jobs/page?**',r=>{const q=new URL(r.request().url()).searchParams;const items=q.get('visibility')==='visible'||q.get('state')&&q.get('state')!==state?[]:[file()];return r.fulfill({json:{items,total:items.length,offset:0,limit:100}})});
 await page.route('**/api/jobs/missing-file/acknowledge',r=>{calls++;if(deny)return r.fulfill({status:409,json:{error:'A related scan is active.'}});state='ACKNOWLEDGED';return r.fulfill({json:{acknowledged:true,dismissedRecords:2}})});
 page.on('dialog',()=>{throw new Error('Dismissal must use an in-app dialog')});
 await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByRole('button',{name:'Review files',exact:true}).click();await expect(page.getByLabel('Record visibility')).toHaveValue('all');await expect(page.getByRole('button',{name:'deleted-example.csv',exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Dismiss — stop retrying',exact:true}).click();const d=page.getByRole('dialog',{name:'Dismiss file from queue',exact:true});await expect(d.getByText(/even if the file no longer exists/)).toBeVisible();await d.getByRole('button',{name:'Cancel',exact:true}).click();expect(calls).toBe(0);
 await page.getByRole('button',{name:'Dismiss — stop retrying',exact:true}).click();await d.getByRole('button',{name:'Dismiss and stop retrying',exact:true}).click();await expect(d.getByRole('alert')).toContainText('A related scan is active');deny=false;await d.getByRole('button',{name:'Cancel',exact:true}).click();await page.getByRole('button',{name:'Dismiss — stop retrying',exact:true}).click();
 if(test.info().project.name==='desktop')await d.screenshot({path:'../docs/images/dismiss-held-file.png',animations:'disabled'});
 await d.getByRole('button',{name:'Dismiss and stop retrying',exact:true}).click();await expect(d).toHaveCount(0);await expect(page.getByRole('button',{name:'deleted-example.csv',exact:true})).toHaveCount(0);await expect(page.getByText('Dismissed 2 record(s). Scanning and retries stopped; history preserved.')).toBeVisible();
 await page.getByLabel('Filter job state').selectOption('ACKNOWLEDGED');await expect(page.getByRole('button',{name:'deleted-example.csv',exact:true})).toBeVisible();if(test.info().project.name==='desktop')await page.screenshot({path:'../docs/images/file-acknowledged.png',animations:'disabled'});
 await page.getByRole('button',{name:'Overview',exact:true}).click();await expect(page.getByText('Held for review',{exact:true}).locator('..')).toContainText('0');
});
