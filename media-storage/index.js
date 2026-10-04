import { installStorageSchema } from './schema.js';
import { createStorageBucket } from './bucket.js';
import { createStorageService } from './service.js';
import { StorageError } from './domain.js';
export async function installMediaStorage({app,pool,authRequired,bucket=createStorageBucket(),env=process.env,startWorker=true,accessPredicate=null,onAccess=null,onRequest=null}) {
  await installStorageSchema(pool);
  const service=createStorageService({pool,bucket,env,accessPredicate,onAccess});
  const route=(method,path,fn)=>app[method]('/api/storage'+path,authRequired,async(req,res)=>{
    res.set('Cache-Control','private, no-store');
    try {if(onRequest)await onRequest(req);res.json(await fn(req));}catch(e){if(e instanceof StorageError||(Number.isInteger(e.status)&&e.status>=400&&e.status<500))res.status(e.status).json({error:e.code,message:e.message});else {console.error('[storage]',e.code||e.name);res.status(503).json({error:'storage_unavailable',message:'Storage is temporarily unavailable. Please retry.'});}}
  });
  route('get','/usage',r=>service.usage(r));
  route('get','/files',r=>service.list(r,r.query));
  route('post','/files/verify',r=>service.verify(r,r.body.ids));
  route('post','/uploads',r=>service.begin(r,r.body));
  route('post','/files/:id/parts',r=>service.part(r,r.params.id,r.body.part_number));
  route('post','/files/:id/complete',r=>service.complete(r,r.params.id));
  route('post','/files/:id/thumbnail',r=>service.thumbnailBegin(r,r.params.id,r.body));
  route('post','/files/:id/thumbnail/complete',r=>service.thumbnailComplete(r,r.params.id,r.body.id));
  route('get','/files/:id/thumbnail',r=>service.thumbnailAccess(r,r.params.id));
  route('get','/files/:id',r=>service.get(r,r.params.id));
  route('patch','/files/:id',r=>service.patch(r,r.params.id,r.body));
  route('post','/files/:id/access',r=>service.access(r,r.params.id,r.body.purpose,r.body.conversation_id));
  route('post','/files/:id/transfer-started',r=>service.transferStarted(r,r.params.id,r.body.receipt_id));
  route('post','/files/:id/download-complete',r=>service.acknowledge(r,r.params.id,r.body.receipt_id));
  route('put','/files/:id/state',r=>service.state(r,r.params.id,r.body));
  route('delete','/files/:id',r=>service.remove(r,r.params.id,r.query.everywhere==='true'));
  route('get','/folders',r=>service.folders(r));
  route('post','/folders',r=>service.saveFolder(r,null,r.body));
  route('patch','/folders/:id',r=>service.saveFolder(r,r.params.id,r.body));
  route('delete','/folders/:id',r=>service.removeFolder(r,r.params.id));
  route('get','/activity',r=>service.activity(r,r.query));
  let running=false;
  const tick=async()=>{if(running)return;running=true;try{await service.cleanup();}catch{console.error('[storage] cleanup deferred');}finally{running=false;}};
  const timer=startWorker?setInterval(tick,60000):null;timer?.unref();if(startWorker)void tick();
  return {...service,stop:()=>clearInterval(timer)};
}
