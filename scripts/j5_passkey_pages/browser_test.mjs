import assert from "node:assert/strict";
import http from "node:http";
import {randomBytes} from "node:crypto";
import {readFile,writeFile} from "node:fs/promises";
import {chromium} from "playwright-core";
import worker from "./_worker.mjs";
const token=randomBytes(32).toString("hex");
const env={LAB_ORIGIN:"",LAB_ACCESS_TOKEN:token};
const server=http.createServer(async(req,res)=>{try{const r=await worker.fetch(new Request(env.LAB_ORIGIN+req.url,{method:req.method,headers:req.headers}),env);res.writeHead(r.status,Object.fromEntries(r.headers));res.end(Buffer.from(await r.arrayBuffer()));}catch{res.writeHead(500);res.end();}});
await new Promise(r=>server.listen(0,"127.0.0.1",r));
env.LAB_ORIGIN="http://localhost:"+server.address().port;
const req=new Request(env.LAB_ORIGIN);
const auth="Basic "+Buffer.from("lab:"+token).toString("base64");
try{
assert.equal((await worker.fetch(req,{})).status,503);
assert.equal((await worker.fetch(req,env)).status,401);
assert.equal((await worker.fetch(new Request(env.LAB_ORIGIN,{headers:{Authorization:"Basic bad"}}),env)).status,401);
assert.equal((await worker.fetch(new Request("https://wrong.invalid",{headers:{Authorization:auth}}),env)).status,503);
assert.equal((await worker.fetch(new Request(env.LAB_ORIGIN,{method:"POST",headers:{Authorization:auth}}),env)).status,404);
const ok=await worker.fetch(new Request(env.LAB_ORIGIN,{headers:{Authorization:auth}}),env);
assert.equal(ok.status,200);assert.equal(ok.headers.get("Cache-Control"),"no-store");assert.ok(ok.headers.get("Content-Security-Policy").includes("connect-src 'none'"));assert.ok(!(await ok.text()).includes(token));
console.log("LAB_GATE_7_PASS");
const browser=await chromium.launch({headless:true});
try{
const context=await browser.newContext({httpCredentials:{username:"lab",password:token},acceptDownloads:true});
const page=await context.newPage();
page.on("console",msg=>{if(msg.text().startsWith("LAB_BROWSER_ERROR"))console.log(msg.text());});
const session=await context.newCDPSession(page);
await session.send("WebAuthn.enable");
await session.send("WebAuthn.addVirtualAuthenticator",{options:{protocol:"ctap2",transport:"internal",hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
await page.goto(env.LAB_ORIGIN);
await page.locator("#create").click();
await page.locator("#sign").waitFor({state:"visible"});
await page.waitForFunction(()=>!document.querySelector("#sign").disabled||document.querySelector("#status").textContent.startsWith("Échec"));assert.equal(await page.locator("#sign").isEnabled(),true,"registration failed");
await page.locator("#sign").click();
await page.waitForFunction(()=>!document.querySelector("#export").disabled||document.querySelector("#status").textContent.startsWith("Échec"));assert.equal(await page.locator("#export").isEnabled(),true,"assertion failed");
const [download]=await Promise.all([page.waitForEvent("download"),page.locator("#export").click()]);
await download.saveAs(process.env.RUNNER_TEMP+"/passkey-lab-proof.json");
console.log("BROWSER_VIRTUAL_AUTHENTICATOR_EXPORT_PASS");
await context.close();
}finally{await browser.close();}
}finally{server.close();}
