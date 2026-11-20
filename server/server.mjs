import http from 'node:http';
import {randomBytes,randomInt,scrypt as scryptCb,timingSafeEqual,createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {pathToFileURL} from 'node:url';
const scrypt=promisify(scryptCb), digest=s=>createHash('sha256').update(s).digest('hex');
export async function createApp(env=process.env){
 if(!env.ADMIN_USERNAME||!env.ADMIN_PASSWORD||env.ADMIN_PASSWORD.length<16) throw Error('Set ADMIN_USERNAME and ADMIN_PASSWORD (at least 16 characters).');
 if(env.NODE_ENV==='production'&&!env.DATABASE_URL) throw Error('Production requires PostgreSQL DATABASE_URL');
 let db,pool;
 if(env.DATABASE_URL){const {default:pg}=await import('pg');pool=new pg.Pool({connectionString:env.DATABASE_URL});db=await pool.connect();}
 else {const {DatabaseSync}=await import('node:sqlite');db=new DatabaseSync(env.SQLITE_PATH||'xrclient.sqlite');db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;');}
 const query=async(sql,args=[])=>{if(pool){let n=0;return (await db.query(sql.replace(/\?/g,()=>'$'+(++n)),args)).rows;}const q=db.prepare(sql);return /^\s*(SELECT|INSERT.*RETURNING)/is.test(sql)?q.all(...args): (q.run(...args),[]);};
 for(const sql of [
 'CREATE TABLE IF NOT EXISTS licenses (key TEXT PRIMARY KEY, term TEXT NOT NULL, seconds BIGINT, redeemed_at BIGINT, expires_at BIGINT, revoked INTEGER NOT NULL DEFAULT 0)',
 'CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, license_key TEXT UNIQUE NOT NULL REFERENCES licenses(key))',
 'CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL, expires_at BIGINT NOT NULL)',
 'CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, value TEXT NOT NULL)',
 'CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at BIGINT NOT NULL)',
 'CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, at BIGINT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL)']) await query(sql);
 const now=()=>Date.now(), terms={'1 day':86400,'3 days':259200,'1 week':604800,'1 month':2592000,'1 year':31536000,'lifetime':null};
 const fail=(status,message)=>{throw Object.assign(Error(message),{status});};
 const hashPassword=async p=>{const salt=randomBytes(16).toString('hex');return salt+':'+(await scrypt(p,salt,64)).toString('hex');};
 const verify=async(p,h)=>{const [salt,value]=h.split(':');return timingSafeEqual(await scrypt(p,salt,64),Buffer.from(value,'hex'));};
 const adminHash=await hashPassword(env.ADMIN_PASSWORD);
 const dummyHash=await hashPassword(randomBytes(32).toString('hex'));
 const audit=async(action,target)=>query('INSERT INTO audit VALUES (?,?,?,?,?)',[randomBytes(16).toString('hex'),now(),env.ADMIN_USERNAME,action,target]);
 const issue=async(username,role)=>{const token=randomBytes(32).toString('hex');await query('INSERT INTO sessions VALUES (?,?,?,?)',[digest(token),username,role,now()+(role==='admin'?3600000:86400000)]);return token;};
 const status=async username=>{const [l]=await query('SELECT l.* FROM licenses l JOIN users u ON u.license_key=l.key WHERE u.username=?',[username]);if(!l||l.revoked||l.redeemed_at===null||(l.expires_at!==null&&Number(l.expires_at)<=now())) fail(403,'License expired or revoked');const [d]=await query('SELECT value FROM settings WHERE id=?',['discord']);return {username,term:l.term,expiresAt:l.expires_at===null?null:Number(l.expires_at),remainingSeconds:l.expires_at===null?null:Math.max(0,Math.floor((Number(l.expires_at)-now())/1000)),serverTime:now(),discord:d?.value||''};};
 let queue=Promise.resolve();
 const server=http.createServer((req,res)=>{const task=async()=>{res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');try{
 const url=new URL(req.url,'http://localhost'),path=url.pathname;
 if(path==='/health'&&req.method==='GET'){await query('SELECT 1');res.end('{"ok":true}');return;}
 if(req.method!=='POST') fail(404,'Not found');
 let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>8192)fail(413,'Request too large');}let b;try{b=JSON.parse(raw||'{}');}catch{fail(400,'Invalid JSON');}if(!b||typeof b!=='object'||Array.isArray(b))fail(400,'Invalid request');
 let result={ok:true};
 if(['/register','/login','/admin/login'].includes(path)){
 const address=env.NODE_ENV==='production'?String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',').pop().trim():req.socket.remoteAddress;
 for(const id of [digest('ip:'+address),digest('user:'+String(b.username).toLowerCase())]){const [a]=await query('SELECT * FROM attempts WHERE id=?',[id]);if(a&&Number(a.reset_at)>now()&&a.count>=20)fail(429,'Too many attempts; retry in 15 minutes');await query('INSERT INTO attempts(id,count,reset_at) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET count=excluded.count,reset_at=excluded.reset_at',[id,a&&Number(a.reset_at)>now()?a.count+1:1,a&&Number(a.reset_at)>now()?Number(a.reset_at):now()+900000]);}
 if(typeof b.username!=='string'||!/^[a-zA-Z0-9_]{3,32}$/.test(b.username)||typeof b.password!=='string'||b.password.length<12||b.password.length>128)fail(400,'Use a 3–32 character username (letters, digits, underscore) and a 12–128 character password');
 b.username=b.username.toLowerCase();
 if(path==='/admin/login'){const valid=await verify(b.password,adminHash);if(b.username!==env.ADMIN_USERNAME.toLowerCase()||!valid)fail(401,'Invalid admin credentials');result={token:await issue(b.username,'admin')};}
 else if(path==='/register'){
 if(typeof b.key!=='string'||!/^\d{5}-\d{5}-\d{5}-\d{3}$/.test(b.key))fail(400,'License format: 12345-12345-12345-123');
 const password=await hashPassword(b.password);await query('BEGIN');try{const [l]=await query('SELECT * FROM licenses WHERE key=?'+(pool?' FOR UPDATE':''),[b.key]);if(!l||l.revoked||l.redeemed_at!==null)fail(400,'License unavailable');if((await query('SELECT username FROM users WHERE username=?',[b.username])).length)fail(409,'Username unavailable');const start=now();await query('UPDATE licenses SET redeemed_at=?,expires_at=? WHERE key=?',[start,l.seconds===null?null:start+Number(l.seconds)*1000,b.key]);await query('INSERT INTO users VALUES (?,?,?)',[b.username,password,b.key]);await query('COMMIT');}catch(e){await query('ROLLBACK');throw e;}result={token:await issue(b.username,'customer'),...await status(b.username)};
 }else {const [u]=await query('SELECT * FROM users WHERE username=?',[b.username]);const valid=await verify(b.password,u?.password||dummyHash);if(!u||!valid)fail(401,'Invalid credentials');result={...await status(b.username),token:await issue(b.username,'customer')};}
 }else{
 const token=String(req.headers.authorization||'').replace(/^Bearer /,'');const [session]=await query('SELECT * FROM sessions WHERE token_hash=?',[digest(token)]);if(!session||Number(session.expires_at)<=now())fail(401,'Please sign in again');
 if(path==='/logout'){await query('DELETE FROM sessions WHERE token_hash=?',[digest(token)]);}
 else if(path.startsWith('/admin/')){
 if(session.role!=='admin')fail(403,'Administrator access required');
 if(path==='/admin/licenses'){result={licenses:await query('SELECT l.*,u.username FROM licenses l LEFT JOIN users u ON u.license_key=l.key ORDER BY l.key LIMIT 1000')};}
 else if(path==='/admin/generate'){if(!Object.hasOwn(terms,b.term))fail(400,'Invalid license term');const key=[5,5,5,3].map(n=>Array.from({length:n},()=>randomInt(10)).join('')).join('-');await query('INSERT INTO licenses(key,term,seconds) VALUES (?,?,?)',[key,b.term,terms[b.term]]);await audit('generate',key);result={key,term:b.term};}
 else if(path==='/admin/revoke'){if(!(await query('SELECT key FROM licenses WHERE key=?',[b.key])).length)fail(404,'License not found');await query('UPDATE licenses SET revoked=1 WHERE key=?',[b.key]);await audit('revoke',b.key);}
 else if(path==='/admin/expiration'){if(b.expiresAt!==null&&(!Number.isSafeInteger(b.expiresAt)||b.expiresAt<0||b.expiresAt>8640000000000000))fail(400,'Invalid expiration');const [l]=await query('SELECT * FROM licenses WHERE key=?',[b.key]);if(!l||l.redeemed_at===null)fail(400,'Redeem the license before editing its expiration');await query('UPDATE licenses SET expires_at=? WHERE key=?',[b.expiresAt,b.key]);await audit('expiration',b.key);}
 else if(path==='/admin/discord'){let u;try{u=new URL(b.url);}catch{fail(400,'Enter an HTTPS Discord invite');}if(u.protocol!=='https:'||!['discord.gg','discord.com'].includes(u.hostname)||u.username||u.password)fail(400,'Enter an HTTPS discord.gg or discord.com URL');await query('INSERT INTO settings VALUES (?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',['discord',u.href]);await audit('discord',u.href);}
 else fail(404,'Not found');
 }else if(path==='/me'){if(session.role!=='customer')fail(403,'Customer session required');result=await status(session.username);}else fail(404,'Not found');
 }
 res.end(JSON.stringify(result));
 }catch(e){res.statusCode=e.status||500;res.end(JSON.stringify({error:e.status?e.message:'Server error'}));if(!e.status)console.error('Request failed:',e.code||e.name);}};queue=queue.then(task,task);});
 server.requestTimeout=15000;server.headersTimeout=10000;
 return {server,close:async()=>{await new Promise(r=>server.close(r));if(pool){db.release();await pool.end();}else db.close();}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const app=await createApp();app.server.listen(Number(process.env.PORT||8787),process.env.NODE_ENV==='production'?'0.0.0.0':'127.0.0.1',()=>console.log('XRClient licensing server ready'));}
