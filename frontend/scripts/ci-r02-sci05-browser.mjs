// Isolated real Chromium/component test. No login, real patient, or clinical activation.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=path.join(process.env.RUNNER_TEMP,'sci05-browser-evidence');
const data=JSON.parse(await fs.readFile(path.join(process.env.RUNNER_TEMP,'sci05-response.json'),'utf8'));
const html=path.join(root,'sci05-synthetic-ci.html');
const entry=path.join(root,'sci05-synthetic-ci.tsx');
const {chromium}=await import(pathToFileURL(path.join(process.env.SCI05_TOOLS,'node_modules/playwright-core/index.mjs')).href);
let server,browser;
try {
 await fs.mkdir(output,{recursive:true});
 await fs.writeFile(html,'<!doctype html><html><head><meta charset="utf-8"></head><body><div id="root"></div><script type="module" src="/sci05-synthetic-ci.tsx"></script></body></html>',{flag:'wx'});
 await fs.writeFile(entry,`import React from 'react';
import {createRoot} from 'react-dom/client';
import {CephaloAnalysisWorkbenchPanel} from './src/features/ortho/components/CephaloAnalysisWorkbenchPanel';
import {useOrthoStore} from './src/features/ortho/stores/useOrthoStore';
const P={bg:'#fff',bgPanel:'#fff',bgCard:'#f4f4f4',bgInput:'#eee',border:'#ddd',borderFocus:'#333',text:'#222',textMuted:'#555',textDim:'#777',accent:'#2457aa',accentSuccess:'#16803d',accentWarning:'#9b6200',accentError:'#b00',shadow:'none',shadowLg:'none'};
const root=createRoot(document.getElementById('root')!);
(window as any).showFixture=(data:any,analysis:'steiner'|'tweed')=>{
 useOrthoStore.getState().setAnglesData(data);
 root.render(<CephaloAnalysisWorkbenchPanel P={P} analysis={analysis}/>);
};
`,{flag:'wx'});
 server=await createServer({root,configFile:false,plugins:[react()],server:{host:'127.0.0.1',port:5189,strictPort:true}});
 await server.listen();
 browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:900}});
 const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',route=>{const u=new URL(route.request().url());return u.hostname==='127.0.0.1'?route.continue():route.abort()});
 await page.goto('http://127.0.0.1:5189/sci05-synthetic-ci.html');
 await page.waitForFunction(()=>typeof window.showFixture==='function');
 for (const [mode,key,count] of [['steiner','steiner',15],['tweed','tweed_merrifield',4]]) {
  await page.evaluate(({data,mode})=>window.showFixture(data,mode),{data,mode});
  const rows=page.locator('[data-r19-metric]');
  await rows.first().waitFor();
  await page.waitForFunction(count=>document.querySelectorAll('[data-r19-metric]').length===count,count);
  const cells=rows.locator('td:nth-child(2)');
  await page.waitForFunction(count=>Array.from(document.querySelectorAll('[data-r19-metric] td:nth-child(2)')).length===count && Array.from(document.querySelectorAll('[data-r19-metric] td:nth-child(2)')).every(x=>x.textContent.includes('12')),count);
  assert.equal(await cells.count(),count);
  await page.screenshot({path:path.join(output,mode+'-valid.png'),fullPage:true});
  const bad=structuredClone(data);
  bad.scientific_read_path.protocol_profiles[key].rows[0].classification_authority=true;
  await page.evaluate(({data,mode})=>window.showFixture(data,mode),{data:bad,mode});
  await page.waitForFunction(count=>Array.from(document.querySelectorAll('[data-r19-metric] td:nth-child(2)')).length===count && Array.from(document.querySelectorAll('[data-r19-metric] td:nth-child(2)')).every(x=>x.textContent.trim()==='NC'),count);
  await page.screenshot({path:path.join(output,mode+'-blocked.png'),fullPage:true});
  console.log('SCI05_BROWSER_PASS',mode,count,'valid rows, tampered profile all NC');
 }
 assert.deepEqual(errors,[]);
} finally {
 if(browser)await browser.close();
 if(server)await server.close();
 await fs.rm(html,{force:true});
 await fs.rm(entry,{force:true});
}
