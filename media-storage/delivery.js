import {randomBytes,createHash} from 'node:crypto';
import {once} from 'node:events';
import {fail} from './domain.js';

const digest=value=>createHash('sha256').update(value).digest('hex');
export function createStorageDelivery({pool,bucket,authorize,env=process.env}) {
  const active=new Map(),sources=new Map();
  function registerSource(name,{authorize,bucket:sourceBucket}={}){
    if(!/^[a-z][a-z0-9_]{0,63}$/.test(name)||typeof authorize!=='function'||sources.has(name))throw Error('invalid_delivery_source');
    sources.set(name,{authorize,bucket:sourceBucket});
  }
  async function issue(db,actor,file,purpose,thumbnailId=null,source=null) {
    if(!actor.sessionToken)fail(401,'session_required','Sign in again to open this file.');
    let origin;
    try{const value=env.PUBLIC_BACKEND_URL||env.MCP_PUBLIC_ORIGIN||(env.RAILWAY_PUBLIC_DOMAIN?`https://${env.RAILWAY_PUBLIC_DOMAIN}`:null);origin=new URL(value);if(origin.username||origin.password||origin.search||origin.hash||origin.pathname!=='/'||!(origin.protocol==='https:'||(env.NODE_ENV!=='production'&&origin.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(origin.hostname))))throw Error();}catch{fail(503,'delivery_origin_unavailable','File delivery is unavailable. Please retry.');}
    const token=randomBytes(32).toString('base64url');
    await db.query('INSERT INTO storage_delivery_tickets(token_hash,user_id,company_id,session_hash,file_id,thumbnail_id,purpose,conversation_id,source_kind,source_id,source_variant) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[digest(token),actor.userId,actor.companyId,digest(actor.sessionToken),source?null:file.id,thumbnailId,purpose,actor.commsConversationId||null,source?.kind||null,source?.id||null,source?.variant||null]);
    return new URL('/api/storage/delivery/'+token,origin.origin).href;
  }
  async function issueSource(actor,kind,id,{purpose='preview',variant=null}={}){
    const source=sources.get(kind);
    if(!source||!['preview','stream','download'].includes(purpose))fail(404,'delivery_unavailable','File delivery is unavailable.');
    const file=await source.authorize(actor,id,variant,purpose);
    return issue(pool,actor,file,purpose,null,{kind,id,variant});
  }
  async function current(token) {
    if(!/^[A-Za-z0-9_-]{43}$/.test(token))fail(404,'delivery_unavailable','File access expired. Open the file again.');
    const ticket=(await pool.query('SELECT * FROM storage_delivery_tickets WHERE token_hash=$1 AND expires_at>now()',[digest(token)])).rows[0];
    if(!ticket)fail(404,'delivery_unavailable','File access expired. Open the file again.');
    const sessions=(await pool.query('SELECT token FROM sessions WHERE user_id=$1',[ticket.user_id])).rows;
    if(!sessions.some(s=>digest(s.token)===ticket.session_hash))fail(401,'session_expired','Sign in again to open this file.');
    const actor={userId:ticket.user_id,companyId:ticket.company_id,commsConversationId:ticket.conversation_id};
    const source=ticket.source_kind?sources.get(ticket.source_kind):null;
    if(ticket.source_kind&&!source)fail(404,'delivery_unavailable','File delivery is unavailable.');
    const file=source?await source.authorize(actor,ticket.source_id,ticket.source_variant,ticket.purpose):await authorize(actor,ticket.file_id,ticket.purpose,ticket.thumbnail_id);
    return {ticket,actor,file,deliveryBucket:source?.bucket||bucket};
  }
  async function serve(req,res) {
    let controller,timer,body,group,user,checking=false;
    const cancel=()=>controller?.abort();
    try{
      const {ticket,file,deliveryBucket}=await current(req.params.token);user=ticket.user_id;
      const range=req.get('Range');
      if(range&&!/^bytes=(?:\d+-\d*|-\d+)$/.test(range))fail(416,'invalid_range','Request one byte range at a time.');
      if(!deliveryBucket?.open)fail(503,'delivery_unavailable','File streaming is temporarily unavailable.');
      controller=new AbortController();group=active.get(user)||new Set();group.add(controller);active.set(user,group);
      res.once('close',cancel);
      // Recheck permission windows and source audience during long transfers.
      // Explicit account/access changes also abort immediately through revokeUser.
      timer=setInterval(async()=>{if(checking)return;checking=true;try{await current(req.params.token);}catch{cancel();res.destroy();}finally{checking=false;}},1000);timer.unref();
      const response=await deliveryBucket.open(file,range,controller.signal);body=response.Body;
      await current(req.params.token); // Provider latency must not bypass a change.
      res.status(response.ContentRange?206:200);
      res.set({'Cache-Control':'private, no-store, max-age=0','Pragma':'no-cache','Content-Security-Policy':"sandbox; default-src 'none'",'X-Content-Type-Options':'nosniff','Accept-Ranges':'bytes','Content-Type':file.mime_type||'application/octet-stream',
        'Content-Disposition':`${ticket.purpose==='download'?'attachment':'inline'}; filename*=UTF-8''${encodeURIComponent(file.original_filename||'file').replace(/'/g,'%27')}`});
      if(Number.isFinite(response.ContentLength))res.set('Content-Length',String(response.ContentLength));
      if(response.ContentRange)res.set('Content-Range',response.ContentRange);
      if(req.method==='HEAD'){body?.destroy?.();res.end();return;}
      for await(const chunk of body){
        if(controller.signal.aborted)throw Error('delivery_revoked');
        if(!res.write(chunk))await once(res,'drain',{signal:controller.signal});
      }
      res.end();
    }catch(error){
      if(res.headersSent){res.destroy();return;}
      const status=error.status|| (error.$metadata?.httpStatusCode===416?416:503);
      res.status(status).set('Cache-Control','private, no-store').json({error:error.code||'delivery_unavailable',message:error.status?error.message:'File delivery is unavailable. Open the file again.'});
    }finally{clearInterval(timer);body?.destroy?.();res.removeListener('close',cancel);group?.delete(controller);if(user&&!group?.size)active.delete(user);}
  }
  async function revokeUser(userId){for(const controller of active.get(userId)||[])controller.abort();await pool.query('DELETE FROM storage_delivery_tickets WHERE user_id=$1',[userId]);}
  return {issue,serve,revokeUser,registerSource,issueSource};
}
