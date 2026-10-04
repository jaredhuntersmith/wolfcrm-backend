import {randomUUID,createHash} from 'node:crypto';
import {authorizeConversation,loadActor,requireCapability,can,fail,id,mutate,audit,publish} from './access.js';
import {hydrateSources} from './sources.js';
import {takeRateLimit} from './rate-limits.js';

export async function installJobHuddles({app,pool,authRequired,messages,calls}) {
 await pool.query(`CREATE TABLE IF NOT EXISTS comms_job_huddles(conversation_id text PRIMARY KEY REFERENCES conversations(id),company_id uuid NOT NULL REFERENCES companies(id),job_id text NOT NULL,audience_key text NOT NULL,created_by uuid NOT NULL REFERENCES users(id),created_at timestamptz NOT NULL DEFAULT now());CREATE INDEX IF NOT EXISTS comms_job_huddle_target ON comms_job_huddles(company_id,job_id,audience_key,created_at DESC); UPDATE conversations c SET source_kind=CASE WHEN h.company_id=c.company_id THEN 'job' ELSE 'invalid' END,source_id=h.job_id FROM comms_job_huddles h WHERE h.conversation_id=c.id AND c.source_kind IS NULL AND c.source_id IS NULL;`);
 async function prepare(input,jobID){return mutate(pool,input,async(db,actor)=>{
  for(const capability of ['schedule.view','jobs.view','communications.calls','communications.send','communications.share'])requireCapability(actor,capability);
  const job=(await db.query(`SELECT * FROM schedule_events WHERE id=$1 AND company_id=$2 AND to_jsonb(schedule_events)->>'deleted_at' IS NULL`,[id(jobID),actor.companyId])).rows[0];if(!job)fail(404,'job_unavailable');
  const assigned=[...new Set([...(Array.isArray(job.worker_user_ids)?job.worker_user_ids:[]),...(Array.isArray(job.sales_user_ids)?job.sales_user_ids:[])].filter(value=>typeof value==='string'&&/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i.test(value)))].slice(0,100);
  const users=(await db.query('SELECT id FROM users WHERE id=ANY($1::uuid[]) AND company_id=$2 AND deleted_at IS NULL',[assigned,actor.companyId])).rows;
  const audience=[actor.userId];for(const user of users){const member=await loadActor(db,{userId:user.id,companyId:actor.companyId});if(can(member,'schedule.view')&&can(member,'jobs.view')&&can(member,'communications.calls')&&!audience.includes(user.id))audience.push(user.id);}
  audience.sort();const audienceKey=createHash('sha256').update(audience.join(':')).digest('hex');
  await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['job-huddle:'+actor.companyId+':'+job.id+':'+audienceKey]);
  let conversation=(await db.query(`SELECT c.id FROM comms_job_huddles h JOIN conversations c ON c.id=h.conversation_id WHERE h.company_id=$1 AND h.job_id=$2 AND h.audience_key=$3 AND c.deleted_at IS NULL AND c.archived_at IS NULL AND (SELECT array_agg(cp.user_id ORDER BY cp.user_id) FROM conversation_participants cp WHERE cp.conversation_id=c.id AND cp.left_at IS NULL)=$4::uuid[] ORDER BY h.created_at DESC LIMIT 1`,[actor.companyId,job.id,audienceKey,audience])).rows[0]?.id;
  if(!conversation){
   conversation=randomUUID();await db.query(`INSERT INTO conversations(id,company_id,title,is_group,created_by,scope,source_kind,source_id) VALUES($1,$2,'Job Huddle',true,$3,'group_dm','job',$4)`,[conversation,actor.companyId,actor.userId,job.id]);
   for(const user of audience)await db.query('INSERT INTO conversation_participants(id,conversation_id,user_id) VALUES($1,$2,$3)',[randomUUID(),conversation,user]);
   await db.query('INSERT INTO comms_job_huddles(conversation_id,company_id,job_id,audience_key,created_by) VALUES($1,$2,$3,$4,$5)',[conversation,actor.companyId,job.id,audienceKey,actor.userId]);
   await messages.sendInTransaction(db,actor,conversation,{client_key:'job-context:'+conversation,cards:[{source_type:'job',source_id:job.id}],body:'Job Huddle · assigned team'});
   await audit(db,actor,'job_huddle_created','conversation',conversation,{job_id:job.id});await publish(db,actor,conversation,'conversation.created',conversation);
  }
  return {conversation_id:conversation,eligible_count:audience.length};
 });}
 async function context(input,conversation){const c=await authorizeConversation(pool,input,conversation);const link=(await pool.query('SELECT job_id FROM comms_job_huddles WHERE conversation_id=$1 AND company_id=$2',[c.id,c.actor.companyId])).rows[0];if(!link)return {context:null};return {context:(await hydrateSources(pool,c.actor,[{id:'context',source_type:'job',source_id:link.job_id}])).get('context')};}
 const route=(method,path,fn)=>app[method]('/api/comms'+path,authRequired,async(req,res)=>{res.set('Cache-Control','private, no-store');try{await takeRateLimit(pool,req,{bucket:method==='post'?'call_create':'read',limit:method==='post'?12:240});res.json(await fn(req));}catch(e){if(!e.status)console.error('[comms_job_huddle]',e.code||e.name);res.status(e.status||503).json({error:e.status?e.code:'job_huddle_unavailable',message:e.status?e.message:'The job huddle is temporarily unavailable.'});}});
 route('get','/conversations/:id/job-context',r=>context(r,r.params.id));
 route('post','/jobs/:id/huddle',async r=>{
  if(!calls.configured)fail(503,'calling_not_configured','Calling is not configured.');
  const prepared=await prepare(r,r.params.id),actor=await loadActor(pool,r);
  const call=await calls.create(actor,{id:r.body.id,kind:'huddle',media:'audio',conversation_id:prepared.conversation_id,invitee_ids:[]});
  return {...prepared,call};
 });
 return {prepare,context};
}

// The media-domain wrapper is also used for join, token refresh and participant
// reconciliation. The canonical source guard also protects text/history and
// follows nested meeting sources; this wrapper retains defense for old mappings.
export async function authorizeCommsCallConversation(db,actor,conversation,options){
 const c=await authorizeConversation(db,actor,conversation,options);
 const source=(await db.query('SELECT job_id FROM comms_job_huddles WHERE conversation_id=$1 AND company_id=$2',[c.id,c.actor.companyId])).rows[0];
 if(source){requireCapability(c.actor,'schedule.view');requireCapability(c.actor,'jobs.view');if(!(await db.query(`SELECT 1 FROM schedule_events WHERE id=$1 AND company_id=$2 AND to_jsonb(schedule_events)->>'deleted_at' IS NULL`,[source.job_id,c.actor.companyId])).rowCount)fail(404,'job_unavailable');}
 return c;
}
