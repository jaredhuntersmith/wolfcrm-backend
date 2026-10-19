import {AsyncLocalStorage} from 'node:async_hooks';
import {IncomingMessage,ServerResponse} from 'node:http';
import {Socket} from 'node:net';
import {randomUUID,createHash} from 'node:crypto';
export const internalActor=Symbol('wolf.mcp.actor');
const storage=new AsyncLocalStorage();
const requestCleanupStorage=new AsyncLocalStorage();
// Canonical services may release an async scoped database lease after res.json.
// An internal dispatch must await that cleanup before its MCP receipt can use
// the same transaction (notably RESET ROLE for finance RLS).
export function trackRequestCleanup(work){
 const pending=requestCleanupStorage.getStore();
 if(pending){pending.add(work);work.catch(()=>{});}
 return work;
}

export const digest=value=>createHash('sha256').update(typeof value==='string'?value:JSON.stringify(value)).digest('hex');
export function fault(status,code,message=code){return Object.assign(new Error(message),{status,code});}
// Only in-process MCP operations enter this context. Ordinary requests use the pool unchanged.
export function transactionalPool(raw){
  return new Proxy(raw,{get(target,key){
    if(key==='query')return async(...args)=>{
      const ctx=storage.getStore();if(ctx?.db){if(!ctx.active)throw fault(500,'transaction_closed');return ctx.db.query(...args);}
      if(!ctx?.boundedRead)return target.query(...args);
      const db=await target.connect();try{await db.query("SET statement_timeout='15s'");return await db.query(...args);}finally{try{await db.query('RESET statement_timeout');}finally{db.release();}}
    };
    if(key==='connect')return async()=>{
      const ctx=storage.getStore();if(!ctx?.db)return target.connect();if(!ctx.active)throw fault(500,'transaction_closed');
      const name='mcp_'+randomUUID().replaceAll('-','');let active=false,released=false;
      return {query:async(sql,...args)=>{
        if(!ctx.active||released)throw fault(500,'transaction_closed');
        const command=typeof sql==='string'?sql.trim().toUpperCase():'';
        if(command==='BEGIN'){if(active)throw fault(500,'nested_transaction');active=true;return ctx.db.query(`SAVEPOINT ${name}`);}
        if(command==='COMMIT'){if(!active)throw fault(500,'transaction_missing');active=false;return ctx.db.query(`RELEASE SAVEPOINT ${name}`);}
        if(command==='ROLLBACK'){if(!active)return;active=false;await ctx.db.query(`ROLLBACK TO SAVEPOINT ${name}`);return ctx.db.query(`RELEASE SAVEPOINT ${name}`);}
        return ctx.db.query(sql,...args);
      },release(){if(active)throw fault(500,'unfinished_business_transaction');released=true;}};
    };
    const value=target[key];return typeof value==='function'?value.bind(target):value;
  }});
}
export const isDraftOnly=()=>storage.getStore()?.draftOnly===true;
export const withDraftOnly=fn=>storage.run({...storage.getStore(),draftOnly:true},fn);
export const boundedRead=fn=>storage.run({boundedRead:true},fn);
// Wake existing outbox processors only after the outermost successful commit.
// Async callbacks inherited from a completed/rolled-back transaction must never
// reuse its released PostgreSQL client.
export function afterCommit(callback){
 const ctx=storage.getStore();
 if(ctx?.db){if(!ctx.active)throw fault(500,'transaction_closed');ctx.afterCommit.push(callback);}
 else storage.exit(callback);
}
export async function transaction(pool,fn){
 const parent=storage.getStore(),db=await pool.connect(),ctx={db,active:true,afterCommit:[]};let result;
 try {await db.query('BEGIN');await db.query("SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='5s'; SET LOCAL idle_in_transaction_session_timeout='20s'");
  result=await storage.run(ctx,()=>fn(db));const committed=await db.query('COMMIT');
  if(!['COMMIT','RELEASE'].includes(committed.command))throw fault(500,'transaction_aborted');
 }catch(e){await db.query('ROLLBACK');throw e;}finally{ctx.active=false;db.release();}
 if(parent?.db){if(!parent.active)throw fault(500,'transaction_closed');parent.afterCommit.push(...ctx.afterCommit);}
 else for(const callback of ctx.afterCommit)storage.exit(()=>{try{const work=callback();if(work?.catch)work.catch(()=>console.warn('[mcp] committed worker wake deferred to periodic processor'));}catch{console.warn('[mcp] committed worker wake deferred to periodic processor');}});
 return result;
}
// Internal requests cannot be constructed via HTTP headers. Run the canonical middleware
// and handlers, including current capability/record checks, without minting a CRM session.
export function dispatch(app,actor,method,path,body,{financeSpaceId}={}){
  if(financeSpaceId!==undefined&&!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(financeSpaceId))throw fault(400,'invalid_finance_space');
  return new Promise((resolve,reject)=>{
    const req=new IncomingMessage(new Socket());req.method=method;req.url=path;
    req.headers={host:'internal.wolf.invalid','content-type':'application/json',...(financeSpaceId?{'x-finance-space':financeSpaceId}:{}),...(body!==undefined?{'content-length':String(Buffer.byteLength(JSON.stringify(body)))}:{})};
    req.body=body||{};req._body=true;req[internalActor]=actor;
    const res=new ServerResponse(req);let data='';
    res.write=chunk=>{data+=chunk;return true;};
    const pending=new Set();
    const finish=async(error)=>{try{while(pending.size){const batch=[...pending];pending.clear();await Promise.all(batch);}if(error)throw error;const value=data?JSON.parse(data):null;if(res.statusCode>=400)throw fault(res.statusCode,value?.error||'workflow_failed',value?.message);resolve(value);}catch(e){reject(e);}};
    res.end=chunk=>{if(chunk)data+=chunk;queueMicrotask(()=>finish());return res;};
    requestCleanupStorage.run(pending,()=>app.handle(req,res,error=>queueMicrotask(()=>finish(error||fault(503,'workflow_unavailable')))));
  });
}
