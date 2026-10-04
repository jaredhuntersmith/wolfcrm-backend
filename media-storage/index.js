import { installStorageSchema } from './schema.js';
import { createStorageBucket } from './bucket.js';
import { createStorageService } from './service.js';
import { StorageError } from './domain.js';
export async function installMediaStorage({app,pool,authRequired,bucket=createStorageBucket(),env=process.env,startWorker=true}) {
  await installStorageSchema(pool);
  const service=createStorageService({pool,bucket,env});
  const route=(method,path,fn)=>app[method]('/api/storage'+path,authRequired,async(req,res)=>{
    res.set('Cache-Control','private, no-store');
    try {res.json(await fn(req));}catch(e){if(e instanceof StorageError)res.status(e.status).json({error:e.code,message:e.message});else {console.error('[storage]',e.code||e.name);res.status(503).json({error:'storage_unavailable',message:'Storage is temporarily unavailable. Please retry.'});}}
  });
  route('get','/usage',r=>service.usage(r));
  route('get','/files',r=>service.list(r,r.query));
  route('post','/files/verify',r=>service.verify(r,r.body.ids));
  route('post','/uploads',r=>service.begin(r,r.body));
  route('post','/files/:id/parts',r=>service.part(r,r.params.id,r.body.part_number));
  route('post','/files/:id/complete',r=>service.complete(r,r.params.id));
  route('get','/files/:id',r=>service.get(r,r.params.id));
  route('patch','/files/:id',r=>service.patch(r,r.params.id,r.body));
  route('post','/files/:id/access',r=>service.access(r,r.params.id,r.body.purpose));
  route('post','/files/:id/download-complete',r=>service.acknowledge(r,r.params.id,r.body.receipt_id));
  route('put','/files/:id/state',r=>service.state(r,r.params.id,r.body));
  route('delete','/files/:id',r=>service.remove(r,r.params.id));
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
