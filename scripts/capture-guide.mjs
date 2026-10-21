// Generate real-UI guide screenshots against a NEW isolated documentation instance.
// Never run against production: this script creates demonstration configuration.
import {chromium} from '../web/node_modules/@playwright/test/index.mjs';
import {mkdir} from 'node:fs/promises';
const base=process.env.GUIDE_BASE_URL||'http://127.0.0.1:18097';
if(base!=='http://127.0.0.1:18097')throw new Error('Use the isolated documentation instance on port 18097.');
const output=new URL('../docs/images/',import.meta.url);await mkdir(output,{recursive:true});
const browser=await chromium.launch({headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000},deviceScaleFactor:1});
try{
 await page.goto(base);await page.getByLabel('Create administrator password').fill('documentation-only-password');await page.getByLabel('Confirm password').fill('documentation-only-password');await page.getByRole('button',{name:'Create administrator & continue'}).click();await page.getByRole('heading',{name:'Security overview'}).waitFor();
 for(const [id,name] of [['incoming','Incoming files'],['clean','Clean files'],['malicious','Malicious files'],['failed','Scan failed']]){
  const r=await page.request.put(base+'/api/mounts/guide-'+id,{data:{id:'guide-'+id,name,kind:'blob',account:'examplestorage',container:id,authType:'sas',secret:'sig=documentation-placeholder'}});if(!r.ok())throw new Error(await r.text());
 }
 const r=await page.request.put(base+'/api/profiles/guide-profile',{data:{id:'guide-profile',name:'Document scanning',sourceMount:'guide-incoming',goodMount:'guide-clean',badMount:'guide-malicious',failedMount:'guide-failed',scanIntervalSeconds:30,enabled:false,revision:0,pml:true,activeContent:true,digest:true,scannedTags:'scanned=true',cleanTags:'verdict=clean',maliciousTags:'verdict=malicious'}});if(!r.ok())throw new Error(await r.text());
 await page.reload();await page.getByRole('heading',{name:'Security overview'}).waitFor();await page.getByLabel('Auto-refresh interval').selectOption('0');
 async function shot(name){await page.locator('.brand img').evaluate(img=>img.decode());await page.waitForTimeout(200);await page.screenshot({path:new URL(name,output).pathname,fullPage:false})}
 await shot('overview.png');await page.getByRole('button',{name:'Dark mode',exact:true}).click();await shot('overview-dark.png');await page.getByRole('button',{name:'Dark mode',exact:true}).click();
 await page.getByRole('button',{name:'Storage connections',exact:true}).click();await shot('storage-connections.png');
 await page.getByRole('button',{name:'Add connection',exact:true}).click();await shot('add-connection.png');await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.getByRole('button',{name:'Vision One config',exact:true}).click();await shot('scanner-settings.png');
 await page.getByRole('button',{name:'Scan profiles',exact:true}).click();await shot('scan-profile.png');await page.getByText('View details',{exact:true}).click();await shot('scan-profile-expanded.png');
 await page.getByRole('button',{name:'Edit profile',exact:true}).click();
 async function step(name){await page.getByRole('button',{name:new RegExp('^Step \\d: '+name+'$')}).click()}
 async function dialogShot(name){await page.getByRole('dialog',{name:'Scan profile',exact:true}).screenshot({path:new URL(name,output).pathname})}
 await dialogShot('profile-source.png');await shot('profile-routing.png');
 await step('Destinations');await dialogShot('profile-destinations.png');
 await step('Schedule');await dialogShot('profile-schedule.png');
 await step('Protection');await dialogShot('profile-protection.png');
 await page.getByLabel('Enable archive extraction and member scans',{exact:false}).check();await page.getByText('Archive settings',{exact:true}).click();await page.getByLabel('Maximum archive layers',{exact:false}).fill('20');await page.getByLabel('Maximum archive layers',{exact:false}).blur();await page.getByRole('heading',{name:'Archive scanning',exact:true}).locator('..').screenshot({path:new URL('profile-archives.png',output).pathname});
 await step('Options');await dialogShot('profile-options.png');await page.getByText('Large-file handling',{exact:true}).click();await page.locator('details.profile-option-group').filter({has:page.locator('summary',{hasText:'Large-file handling'})}).screenshot({path:new URL('profile-large-files.png',output).pathname});
 await step('Review');await dialogShot('profile-review.png');await page.getByRole('button',{name:'Cancel',exact:true}).click();
 // Synthetic illustrative activity records; no real storage files or credentials are used.
 await page.route('**/api/jobs/page?**',async route=>{const all=[{id:'guide-held',key:'example-report.csv',profileName:'Document scanning',size:3500000000,state:'HELD',verdict:'UNKNOWN',createdAt:'2026-10-21T03:45:00Z',error:'Download retries exhausted; source retained.'},{id:'guide-completed',key:'example-report.csv',profileName:'Document scanning',size:3500000000,state:'COMPLETED',verdict:'CLEAN',createdAt:'2026-10-20T20:30:00Z'}];const q=new URL(route.request().url()).searchParams;const items=q.get('issues')==='scan_errors'?all.filter(x=>x.state==='HELD'):all;await route.fulfill({json:{items,total:items.length,offset:0,limit:100}})});
 await page.getByRole('button',{name:'File activity',exact:true}).click();await shot('file-activity.png');await page.getByLabel('Scan issue filter').selectOption('scan_errors');await shot('file-activity-errors.png');
 await page.getByRole('button',{name:'Storage explorer',exact:true}).click();await page.locator('.explorer-toolbar select').selectOption('guide-incoming');await shot('storage-explorer.png');
 await page.getByRole('button',{name:'Audit log',exact:true}).click();await shot('audit-log.png');
 await page.getByRole('button',{name:'Sizing calculator',exact:true}).click();await shot('sizing-calculator.png');await page.getByText('Size units and a worked example',{exact:true}).click();await page.locator('.sizing-legend').screenshot({path:new URL('sizing-legend.png',output).pathname});
}finally{await browser.close()}
