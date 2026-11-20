import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createApp} from './server.mjs';
test('registration, permissions, expiration, revocation and persistence',async()=>{
 const app=await createApp({ADMIN_USERNAME:'owner',ADMIN_PASSWORD:'test-only-strong-password',SQLITE_PATH:':memory:'});
 await new Promise(r=>app.server.listen(0,'127.0.0.1',r));
 const base=`http://127.0.0.1:${app.server.address().port}`;
 const call=async(path,body={},token='')=>{const r=await fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${token}`},body:JSON.stringify(body)});return {status:r.status,...await r.json()};};
 try{
 assert.equal((await call('/admin/licenses')).status,401);
 assert.equal((await call('/admin/login',{username:'owner',password:'wrong-password-value'})).status,401);
 const admin=(await call('/admin/login',{username:'owner',password:'test-only-strong-password'})).token;
 const keys={};for(const term of ['1 day','3 days','1 week','1 month','1 year','lifetime']){const r=await call('/admin/generate',{term},admin);assert.equal(r.status,200);assert.match(r.key,/^\d{5}-\d{5}-\d{5}-\d{3}$/);keys[term]=r.key;}
 let rows=(await call('/admin/licenses',{},admin)).licenses;assert.equal(rows.length,6);assert.ok(rows.every(l=>l.redeemed_at===null&&l.expires_at===null));
 const credentials={username:'customer',password:'customer-test-password'};
 const registered=await call('/register',{...credentials,key:keys['1 day']});assert.equal(registered.status,200);assert.ok(registered.remainingSeconds>86390&&registered.remainingSeconds<=86400);
 assert.equal((await call('/register',{username:'otheruser',password:'customer-test-password',key:keys['1 day']})).status,400);
 assert.equal((await call('/login',{...credentials,password:'incorrect-pass-value'})).status,401);
 const customer=(await call('/login',credentials)).token;assert.ok(customer);
 for(const path of ['/admin/licenses','/admin/generate','/admin/revoke','/admin/expiration','/admin/discord'])assert.equal((await call(path,{key:keys['1 day'],term:'lifetime'},customer)).status,403);
 assert.equal((await call('/me',{},admin)).status,403);
 await call('/admin/discord',{url:'https://discord.gg/example'},admin);assert.equal((await call('/me',{},customer)).discord,'https://discord.gg/example');
 assert.equal((await call('/admin/discord',{url:'https://evil.example'},admin)).status,400);
 await call('/admin/expiration',{key:keys['1 day'],expiresAt:Date.now()-1000},admin);
 assert.equal((await call('/me',{},customer)).status,403);assert.equal((await call('/login',credentials)).status,403);
 await call('/admin/expiration',{key:keys['1 day'],expiresAt:Date.now()+3600000},admin);assert.equal((await call('/me',{},customer)).status,200);
 await call('/admin/revoke',{key:keys['1 day']},admin);assert.equal((await call('/me',{},customer)).status,403);assert.equal((await call('/login',credentials)).status,403);
 const lifetime=await call('/register',{username:'lifetimeuser',password:'customer-test-password',key:keys.lifetime});assert.equal(lifetime.remainingSeconds,null);assert.equal(lifetime.expiresAt,null);
 await call('/logout',{},lifetime.token);assert.equal((await call('/me',{},lifetime.token)).status,401);
 const races=await Promise.all(['raceone','racetwo'].map(username=>call('/register',{username,password:'customer-test-password',key:keys['3 days']})));assert.deepEqual(races.map(x=>x.status).sort(),[200,400]);
 console.log('PASS: all six terms; redemption starts term; duplicate/racing redemption; login; permissions; expiration; revocation; lifetime; logout; Discord validation');
 }finally{await app.close();}
});
