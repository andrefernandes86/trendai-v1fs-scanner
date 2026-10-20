// Documentation instance only. Seed one synthetic HELD job before capturing.
// Uses the demonstration administrator created by capture-guide.mjs, never production.
import {chromium,expect} from '../web/node_modules/@playwright/test/index.mjs';
const base='http://127.0.0.1:18097';
const browser=await chromium.launch({headless:true});
try {
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 await page.goto(base);await page.getByLabel('Administrator password').fill('documentation-only-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await page.getByRole('heading',{name:'Security overview'}).waitFor();
 await page.getByRole('button',{name:'File activity',exact:true}).click();
 await page.getByLabel('Filter job state').selectOption('HELD');
 await expect(page.getByRole('button',{name:'Acknowledge — stop scanning',exact:true})).toBeVisible();
 await page.locator('.brand img').evaluate(img=>img.decode());
 await page.screenshot({path:new URL('../docs/images/held-acknowledge.png',import.meta.url).pathname});
 page.once('dialog',dialog=>dialog.dismiss());
 await page.getByRole('button',{name:'Acknowledge — stop scanning',exact:true}).click();
 await expect(page.getByRole('button',{name:'Acknowledge — stop scanning',exact:true})).toBeVisible();
 page.once('dialog',dialog=>dialog.accept());
 await page.getByRole('button',{name:'Acknowledge — stop scanning',exact:true}).click();
 await expect(page.getByText('Acknowledged. Scanning and recovery stopped for this file version; file and history preserved.')).toBeVisible();
 await page.getByLabel('Filter job state').selectOption('ACKNOWLEDGED');
 await expect(page.getByText('Scanning stopped by administrator',{exact:true})).toBeVisible();
 await expect(page.getByRole('button',{name:'Retry',exact:true})).toHaveCount(0);
 await page.screenshot({path:new URL('../docs/images/file-acknowledged.png',import.meta.url).pathname});
 console.log('Acknowledgement confirmation/cancellation and final state verified.');
} finally {await browser.close()}
