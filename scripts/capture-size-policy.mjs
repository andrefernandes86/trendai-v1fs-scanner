// Fresh isolated documentation instance only; no production data or credentials.
import {chromium} from '../web/node_modules/@playwright/test/index.mjs';
const base='http://127.0.0.1:18097';
const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1800},deviceScaleFactor:1});
try {
 await page.goto(base);await page.getByLabel('Create administrator password').fill('documentation-only-password');await page.getByLabel('Confirm password').fill('documentation-only-password');await page.getByRole('button',{name:'Create administrator & continue'}).click();await page.getByRole('heading',{name:'Security overview'}).waitFor();
 for(const id of ['source','clean','malicious','failed']){const r=await page.request.put(base+'/api/mounts/size-'+id,{data:{id:'size-'+id,name:{source:'Incoming files',clean:'Clean files',malicious:'Malicious files',failed:'Scan failed'}[id],kind:'blob',account:'examplestorage',container:id,authType:'sas',secret:'sig=documentation-placeholder'}});if(!r.ok())throw new Error(await r.text())}
 const r=await page.request.put(base+'/api/profiles/size-policy',{data:{id:'size-policy',name:'Document scanning',sourceMount:'size-source',goodMount:'size-clean',badMount:'size-malicious',failedMount:'size-failed',scanIntervalSeconds:10,enabled:false,revision:0}});if(!r.ok())throw new Error(await r.text());
 await page.reload();await page.getByRole('heading',{name:'Security overview'}).waitFor();await page.getByLabel('Auto-refresh interval').selectOption('0');await page.getByRole('button',{name:'Scan profiles',exact:true}).click();
 const step=name=>page.getByRole('button',{name:new RegExp('^Step \\d: '+name+'$')});
 async function open(){await page.getByRole('button',{name:'Edit profile',exact:true}).click();await step('Options').click();await page.getByText('Large-file handling',{exact:true}).click()}
 const group=()=>page.locator('details.profile-option-group').filter({has:page.locator('summary',{hasText:/^Large-file handling$/})});
 async function shot(file){await group().screenshot({path:new URL('../docs/images/'+file,import.meta.url).pathname,animations:'disabled',style:'.profile-stepper,.profile-wizard .form-footer{position:static!important}'})}
 await open();await shot('profile-large-files.png');await page.getByLabel('Compressed files above scan-size limit',{exact:true}).selectOption('custom');await page.getByRole('combobox',{name:'Oversized compressed-file destination',exact:true}).selectOption('size-failed');await page.getByLabel('Oversized compressed-file subfolder (optional)',{exact:false}).fill('large-archives');await shot('profile-compressed-routing.png');
 await step('Review').click();await page.getByRole('dialog',{name:'Scan profile',exact:true}).screenshot({path:new URL('../docs/images/profile-review.png',import.meta.url).pathname});await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.getByRole('button',{name:'Dark mode',exact:true}).click();await open();await page.getByLabel('Compressed files above scan-size limit',{exact:true}).selectOption('clean');await shot('profile-large-files-dark.png');await page.getByRole('button',{name:'Cancel',exact:true}).click();
}finally{await browser.close()}
