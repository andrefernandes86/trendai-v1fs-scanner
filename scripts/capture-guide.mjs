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
 async function shot(name){await page.screenshot({path:new URL(name,output).pathname,fullPage:false})}
 await shot('overview.png');
 await page.getByRole('button',{name:'Storage connections',exact:true}).click();await shot('storage-connections.png');
 await page.getByRole('button',{name:'Add connection',exact:true}).click();await shot('add-connection.png');await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.getByRole('button',{name:'Vision One config',exact:true}).click();await shot('scanner-settings.png');
 await page.getByRole('button',{name:'Scan profiles',exact:true}).click();await shot('scan-profile.png');
 await page.getByRole('button',{name:'Edit profile',exact:true}).click();await shot('profile-routing.png');await page.locator('.profile-section').filter({has:page.getByRole('heading',{name:'2. Destinations',exact:true})}).screenshot({path:new URL('profile-destinations.png',output).pathname});await page.getByRole('heading',{name:'Large files & size policy',exact:true}).locator('..').screenshot({path:new URL('profile-large-files.png',output).pathname});await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.getByRole('button',{name:'File activity',exact:true}).click();await shot('file-activity.png');
 await page.getByRole('button',{name:'Sizing calculator',exact:true}).click();await shot('sizing-calculator.png');
}finally{await browser.close()}
