import {lockConnectionSlot} from './manager-schema.js';
import {isIP} from 'node:net';
import OAuth2Server from '@node-oauth/oauth2-server';
import {randomUUID,randomBytes} from 'node:crypto';
import {scopes,loadPrincipal,connection,rateLimit} from './access.js';
import {digest,fault,transaction} from './context.js';
const random=()=>randomBytes(32).toString('base64url');
const esc=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function page(title,body){return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · WolfCRM</title><style>body{font:17px system-ui;background:#f4f5f6;color:#17202c;max-width:600px;margin:8vh auto;padding:24px}main{background:white;padding:28px;border-radius:16px}label{display:block;margin:18px 0}input,select,button{font:inherit;padding:12px;max-width:100%;box-sizing:border-box}input{width:100%}button{cursor:pointer;margin:12px 12px 0 0}li{margin:12px 0}small{color:#526174}</style><main><h1>${esc(title)}</h1>${body}</main></html>`;}
export function browserHeaders(res,callbackOrigins=[]){res.set({'Cache-Control':'no-store','Pragma':'no-cache','Referrer-Policy':'strict-origin','X-Frame-Options':'DENY','X-Content-Type-Options':'nosniff','Content-Security-Policy':`default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${callbackOrigins.join(' ')}; frame-ancestors 'none'; base-uri 'none'`});}
export function installOAuth({app,pool,env,verifyIdentity}){
 const origin=env.MCP_PUBLIC_ORIGIN;const resource=origin+'/mcp';
 const cookieName=origin.startsWith('https:')?'__Host-wolf-mcp':'wolf-mcp-local';
 const redirects=JSON.parse(env.MCP_REDIRECT_URIS||'[]');
 if(!Array.isArray(redirects)||redirects.some(uri=>{try{const u=new URL(uri);return u.hash||u.username||u.password||!(u.protocol==='https:'||(env.NODE_ENV!=='production'&&u.protocol==='http:'&&['localhost','127.0.0.1'].includes(u.hostname)));}catch{return true;}}))throw new Error('Invalid MCP_REDIRECT_URIS');
 const trustedHops=Number(env.MCP_TRUST_PROXY_HOPS||0);
 if(!Number.isInteger(trustedHops)||trustedHops<0||trustedHops>3)throw new Error('MCP_TRUST_PROXY_HOPS must be 0–3');
 const rateIdentity=req=>{const forwarded=String(req.headers['x-forwarded-for']||'').split(',').map(s=>s.trim()).filter(isIP);const chain=[...forwarded,req.socket.remoteAddress];return chain[Math.max(0,chain.length-1-trustedHops)]||req.socket.remoteAddress;};
 const run=fn=>async(req,res)=>{browserHeaders(res,[...new Set(redirects.map(uri=>new URL(uri).origin))]);try{if(env.MCP_ENABLED!=='true')throw fault(503,'mcp_disabled');await rateLimit(pool,'oauth:'+rateIdentity(req),120);await fn(req,res);}catch(e){res.status(e.status||e.code&&Number.isInteger(e.code)&&e.code||500).json({error:typeof e.name==='string'&&e.name.endsWith('_error')?e.name:typeof e.code==='string'?e.code:'oauth_error',error_description:e.status&&e.status<500?e.message:'Unable to authorize. Please retry.'});}};
 const model={
  generateAccessToken:random,generateRefreshToken:random,generateAuthorizationCode:random,
  async getClient(id,secret){if(secret)return false;const row=(await pool.query('SELECT * FROM mcp_clients WHERE id=$1',[id])).rows[0];return row?{id:row.id,redirectUris:row.redirect_uris,grants:['authorization_code','refresh_token']}:false;},
  validateScope:(_user,_client,requested)=>requested?.length&&requested.every(s=>Object.hasOwn(scopes,s))?requested:false,
  async saveAuthorizationCode(code,client,user){await pool.query('INSERT INTO mcp_codes(hash,connection_id,redirect_uri,challenge,expires_at) VALUES($1,$2,$3,$4,$5)',[digest(code.authorizationCode),user.id,code.redirectUri,code.codeChallenge,code.expiresAt]);return {...code,client,user};},
  async getAuthorizationCode(code){const row=(await pool.query(`SELECT c.*,g.client_id,g.scopes FROM mcp_codes c JOIN mcp_connections g ON g.id=c.connection_id WHERE c.hash=$1 AND c.used_at IS NULL FOR UPDATE OF c`,[digest(code)])).rows[0];if(!row)return false;await connection(pool,row.connection_id);return {authorizationCode:code,expiresAt:row.expires_at,redirectUri:row.redirect_uri,codeChallenge:row.challenge,codeChallengeMethod:'S256',scope:row.scopes,client:{id:row.client_id},user:{id:row.connection_id}};},
  async revokeAuthorizationCode(code){return !!(await pool.query('UPDATE mcp_codes SET used_at=now() WHERE hash=$1 AND used_at IS NULL',[digest(code.authorizationCode)])).rowCount;},
  async getRefreshToken(token){const row=(await pool.query(`SELECT t.*,g.client_id FROM mcp_tokens t JOIN mcp_connections g ON g.id=t.connection_id WHERE t.refresh_hash=$1 AND t.used_at IS NULL FOR UPDATE OF t`,[digest(token)])).rows[0];if(!row)return false;await connection(pool,row.connection_id);return {refreshToken:token,refreshTokenExpiresAt:row.refresh_expires_at,scope:row.scopes,client:{id:row.client_id},user:{id:row.connection_id}};},
  async revokeToken(token){return !!(await pool.query('UPDATE mcp_tokens SET used_at=now() WHERE refresh_hash=$1 AND used_at IS NULL',[digest(token.refreshToken)])).rowCount;},
  async saveToken(token,client,user){const grant=await connection(pool,user.id);if(grant.audience!==resource)throw fault(400,'invalid_target');await pool.query('INSERT INTO mcp_tokens(access_hash,refresh_hash,connection_id,scopes,access_expires_at,refresh_expires_at) VALUES($1,$2,$3,$4,$5,$6)',[digest(token.accessToken),digest(token.refreshToken),user.id,JSON.stringify(token.scope),token.accessTokenExpiresAt,token.refreshTokenExpiresAt]);return {...token,client,user};}
 };
 const oauth=new OAuth2Server({model,authorizationCodeLifetime:120,accessTokenLifetime:600,refreshTokenLifetime:30*86400,requirePKCE:true,enablePlainPKCE:false,allowEmptyState:false});
 const metadata={issuer:origin,authorization_endpoint:origin+'/oauth/authorize',token_endpoint:origin+'/oauth/token',registration_endpoint:origin+'/oauth/register',revocation_endpoint:origin+'/oauth/revoke',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:Object.keys(scopes),authorization_response_iss_parameter_supported:true};
 app.get('/.well-known/oauth-authorization-server',(_req,res)=>res.json(metadata));
 for(const path of ['/.well-known/oauth-protected-resource','/.well-known/oauth-protected-resource/mcp'])app.get(path,(_req,res)=>res.json({resource,authorization_servers:[origin],scopes_supported:Object.keys(scopes),bearer_methods_supported:['header'],resource_name:'WolfCRM'}));
 app.post('/oauth/register',run(async(req,res)=>{
  const b=req.body||{};
  if(b.token_endpoint_auth_method&&b.token_endpoint_auth_method!=='none'||!Array.isArray(b.redirect_uris)||!b.redirect_uris.length||b.redirect_uris.length>5||b.redirect_uris.some(uri=>!redirects.includes(uri)))throw fault(400,'invalid_redirect_uri','Register the exact callback URI with the WolfCRM operator first.');
  if(b.grant_types?.some(x=>!['authorization_code','refresh_token'].includes(x))||b.response_types?.some(x=>x!=='code'))throw fault(400,'invalid_client_metadata');
  const id=randomUUID(),name=String(b.client_name||'MCP client').slice(0,100);
  await pool.query('INSERT INTO mcp_clients(id,name,redirect_uris) VALUES($1,$2,$3)',[id,name,JSON.stringify(b.redirect_uris)]);
  res.status(201).json({client_id:id,client_name:name,redirect_uris:b.redirect_uris,token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']});
 }));
 const form=(pending,csrf,body)=>`<form method="post" action="/oauth/authorize"><input type="hidden" name="request_id" value="${esc(pending.id)}"><input type="hidden" name="csrf" value="${esc(csrf)}">${body}</form>`;
 app.get('/oauth/authorize',run(async(req,res)=>{
  const p=req.query,client=await model.getClient(p.client_id);
  if(!client||!client.redirectUris.includes(p.redirect_uri)||!redirects.includes(p.redirect_uri))throw fault(400,'invalid_redirect_uri');
  if(p.response_type!=='code'||p.resource!==resource||p.code_challenge_method!=='S256'||typeof p.code_challenge!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(p.code_challenge)||typeof p.state!=='string'||!p.state||p.state.length>2048)throw fault(400,'invalid_request');
  const requested=String(p.scope||'crm:read').split(' ').filter(Boolean);if(!model.validateScope(null,null,requested))throw fault(400,'invalid_scope');
  const pending={id:randomUUID()},cookie=random(),csrf=random();
  await pool.query('INSERT INTO mcp_browser_requests(id,cookie_hash,csrf_hash,params) VALUES($1,$2,$3,$4)',[pending.id,digest(cookie),digest(csrf),JSON.stringify({...p,scope:requested.join(' ')})]);
  res.cookie(cookieName,cookie,{httpOnly:true,secure:origin.startsWith('https:'),sameSite:'lax',path:'/',maxAge:600000});
  res.type('html').send(page('Connect to WolfCRM',form(pending,csrf,'<label>Email<input name="email" type="email" autocomplete="username" maxlength="254" required></label><label>Password<input name="password" type="password" autocomplete="current-password" maxlength="256" required></label><button name="step" value="login">Sign in</button>')));
 }));
 app.post('/oauth/authorize',run(async(req,res)=>{
  if(req.get('origin')!==origin)throw fault(403,'invalid_origin');
  const cookie=String(req.headers.cookie||'').split(';').map(v=>v.trim()).find(v=>v.startsWith(cookieName+'='))?.slice(cookieName.length+1);
  const b=req.body||{};if(typeof b.request_id!=='string'||!/^[\da-f-]{36}$/i.test(b.request_id)||typeof b.csrf!=='string'||!cookie)throw fault(403,'invalid_browser_session');
  if(b.step==='login')await rateLimit(pool,'login:'+String(b.email||'').trim().toLowerCase(),8);
  const response=await transaction(pool,async()=>{
   const pending=(await pool.query('SELECT * FROM mcp_browser_requests WHERE id=$1 AND cookie_hash=$2 AND csrf_hash=$3 AND expires_at>now() FOR UPDATE',[b.request_id,digest(cookie),digest(b.csrf)])).rows[0];if(!pending)throw fault(403,'invalid_browser_session');
   if(b.step==='login'){
    const user=await verifyIdentity(String(b.email||'').slice(0,254),String(b.password||'').slice(0,256));if(!user)throw fault(401,'invalid_login');
    const actor=await loadPrincipal(pool,user.id);await pool.query('UPDATE mcp_browser_requests SET user_id=$2 WHERE id=$1',[pending.id,actor.userId]);
    const client=(await pool.query('SELECT name FROM mcp_clients WHERE id=$1',[pending.params.client_id])).rows[0];
    return {html:page('Approve AI connection',`<p><strong>${esc(client.name)}</strong> requests access as ${esc(actor.userEmail)}.</p>`+form(pending,b.csrf,`<label>Company<select name="company_id"><option value="${esc(actor.companyId)}">${esc(actor.companyName)}</option></select></label><ul>${pending.params.scope.split(' ').map(s=>`<li>${esc(scopes[s])}</li>`).join('')}</ul><p>Access lasts up to 30 days. Current WolfCRM permissions always apply. Revoke at any time in AI Connections.</p><button name="step" value="approve">Approve access</button><button name="step" value="deny">Deny</button>`))};
   }
   if(!pending.user_id||!['approve','deny'].includes(b.step))throw fault(400,'invalid_request');
   const actor=await loadPrincipal(pool,pending.user_id);if(b.company_id!==actor.companyId)throw fault(403,'company_not_authorized');
   const redirect=new URL(pending.params.redirect_uri);redirect.searchParams.set('state',pending.params.state);redirect.searchParams.set('iss',origin);
   if(b.step==='deny')redirect.searchParams.set('error','access_denied');
   else {
    await lockConnectionSlot(pool,actor.companyId);const id=randomUUID();await pool.query('INSERT INTO mcp_connections(id,user_id,company_id,client_id,scopes,audience) VALUES($1,$2,$3,$4,$5,$6)',[id,actor.userId,actor.companyId,pending.params.client_id,JSON.stringify(pending.params.scope.split(' ')),resource]);
    const request=new OAuth2Server.Request({method:'GET',query:pending.params,headers:{},body:{}}),response=new OAuth2Server.Response();
    const code=await oauth.authorize(request,response,{authenticateHandler:{handle:()=>({id})}});redirect.searchParams.set('code',code.authorizationCode);
    await pool.query("INSERT INTO mcp_audit(connection_id,company_id,user_id,operation,outcome) VALUES($1,$2,$3,'connection.approved','success')",[id,actor.companyId,actor.userId]);
   }
   await pool.query('DELETE FROM mcp_browser_requests WHERE id=$1',[pending.id]);return {redirect:redirect.toString()};
  });
  if(response.html)res.type('html').send(response.html);else {res.clearCookie(cookieName,{path:'/',httpOnly:true,secure:origin.startsWith('https:'),sameSite:'lax'});res.redirect(303,response.redirect);}
 }));
 app.post('/oauth/token',run(async(req,res)=>{
  if(req.body.resource!==resource)throw fault(400,'invalid_target');
  if(!['authorization_code','refresh_token'].includes(req.body.grant_type))throw fault(400,'unsupported_grant_type');
  const response=await transaction(pool,async()=>{
   if(req.body.grant_type==='refresh_token'){
    const row=(await pool.query(`SELECT t.connection_id,t.used_at,g.client_id FROM mcp_tokens t JOIN mcp_connections g ON g.id=t.connection_id WHERE t.refresh_hash=$1 FOR UPDATE OF t`,[digest(String(req.body.refresh_token||''))])).rows[0];
    if(row?.used_at&&row.client_id===req.body.client_id){await pool.query('UPDATE mcp_connections SET revoked_at=now() WHERE id=$1',[row.connection_id]);return {replay:true};}
   }
   const output=new OAuth2Server.Response();await oauth.token(new OAuth2Server.Request(req),output,{requireClientAuthentication:{authorization_code:false,refresh_token:false}});return output.body;
  });
  if(response.replay)throw fault(400,'invalid_grant','Refresh token replay revoked this connection. Reconnect.');res.json(response);
 }));
 app.post('/oauth/revoke',run(async(req,res)=>{
  const token=String(req.body.token||''),client=String(req.body.client_id||'');
  await pool.query(`UPDATE mcp_connections g SET revoked_at=now() FROM mcp_tokens t WHERE t.connection_id=g.id AND g.client_id=$2 AND (t.access_hash=$1 OR t.refresh_hash=$1)`,[digest(token),client]);res.status(200).json({});
 }));
 return {resource,metadata};
}
