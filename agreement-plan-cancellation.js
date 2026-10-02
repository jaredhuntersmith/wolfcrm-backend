import {QuoteContractError} from "./quote-contract-domain.js";

const fail=(code,message,status=409)=>{throw new QuoteContractError(code,message,status);};
const uuid=value=>{if(typeof value!=="string"||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))fail("plan_request_invalid","A valid request ID is required.",400);return value.toLowerCase();};
async function txn(pool,run){const db=await pool.connect();try{await db.query('BEGIN');const result=await run(db);await db.query('COMMIT');return result;}catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}}

export async function installAgreementPlanCancellation({app,pool,service,plans,billing,authRequired,requireCapability,startWorker=true}) {
  await pool.query(`ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS cancel_requested_at TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS agreement_plan_cancellation_requests(
      enrollment_id UUID NOT NULL REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT,
      request_id UUID NOT NULL,actor_type TEXT NOT NULL,actor_id TEXT,
      state TEXT NOT NULL DEFAULT 'pending',message TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(enrollment_id,request_id));
    CREATE INDEX IF NOT EXISTS agreement_plan_cancellation_pending_idx ON agreement_plan_cancellation_requests(updated_at) WHERE state='pending';`);
  async function locks(db,enrollment){
    await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`payment:${enrollment.company_id}:${enrollment.collection_key}`]);
    await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`plan-billing:${enrollment.id}`]);
  }
  async function response(enrollment,message=null){return{status:enrollment.canceled_at?'canceled':'cancellation_pending',enrollment:await plans.detail(pool,enrollment),...(message?{message}:{})};}
  async function finish(enrollmentID){
    let result;
    try{result=await billing.preparePendingCancellation(enrollmentID);}
    catch(error){result={ready:false,message:error instanceof QuoteContractError?error.message:'The provider outcome could not be confirmed. Recheck cancellation; existing payment evidence remains saved.'};}
    const preliminary=(await pool.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1',[enrollmentID])).rows[0];
    if(!result.ready){await pool.query("UPDATE agreement_plan_cancellation_requests SET message=$2,updated_at=now() WHERE enrollment_id=$1 AND state='pending'",[enrollmentID,result.message]);await pool.query("UPDATE agreement_plan_enrollments SET billing_error_code='plan_cancellation_pending',billing_error_since=COALESCE(billing_error_since,now()) WHERE id=$1 AND canceled_at IS NULL",[enrollmentID]);return response(preliminary,result.message);}
    return txn(pool,async db=>{
      await locks(db,preliminary);
      const enrollment=(await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1 FOR UPDATE',[enrollmentID])).rows[0];
      if(enrollment.canceled_at)return response(enrollment);
      if(enrollment.service_plan_id)fail('plan_membership_active','This membership is already active. Use its signed cancellation policy.');
      const unknown=(await db.query("SELECT 1 FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND state<>'complete' AND kind NOT IN ('invoice.void','invoice.delete','checkout.expire') LIMIT 1",[enrollmentID])).rowCount;
      const collectible=(await db.query("SELECT 1 FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND state<>'canceled' LIMIT 1",[enrollmentID])).rowCount;
      const setup=(await db.query("SELECT 1 FROM agreement_plan_setups WHERE enrollment_id=$1 AND state NOT IN ('succeeded','expired','canceled') LIMIT 1",[enrollmentID])).rowCount;
      const money=(await db.query("SELECT 1 FROM payment_records WHERE enrollment_id=$1 AND status IN ('succeeded','processing','refunded','partially_refunded','disputed') LIMIT 1",[enrollmentID])).rowCount;
      if(unknown||collectible||setup||money)return response(enrollment,'A provider outcome still needs review before another tier can be selected. No refund was made.');
      await db.query('SELECT id FROM quote_agreements WHERE id=$1 FOR UPDATE',[enrollment.plan_agreement_id]);
      const saved=(await db.query("UPDATE agreement_plan_enrollments SET canceled_at=now(),state='canceled',billing_error_code=NULL,billing_error_since=NULL,updated_at=now() WHERE id=$1 RETURNING *",[enrollmentID])).rows[0];
      await db.query("UPDATE quote_agreements SET decision='superseded',updated_at=now() WHERE id=$1",[enrollment.plan_agreement_id]);
      await db.query("UPDATE agreement_plan_cancellation_requests SET state='complete',message=NULL,updated_at=now() WHERE enrollment_id=$1",[enrollmentID]);
      const request=(await db.query('SELECT actor_type,actor_id FROM agreement_plan_cancellation_requests WHERE enrollment_id=$1 ORDER BY created_at LIMIT 1',[enrollmentID])).rows[0];
      await service.event(db,enrollment.base_agreement_id,'plan_pending_canceled',{actor_type:request.actor_type,actor_id:request.actor_id,payload:{enrollment_id:enrollmentID,plan_agreement_id:enrollment.plan_agreement_id}});
      await service.event(db,enrollment.plan_agreement_id,'plan_pending_canceled',{actor_type:request.actor_type,actor_id:request.actor_id,payload:{enrollment_id:enrollmentID,retained_signatures:true}});
      return{status:'canceled',enrollment:await plans.detail(db,saved)};
    });
  }
  async function cancel(enrollment,raw,actor){
    const requestID=uuid(raw?.request_id);if(Object.keys(raw).some(key=>key!=='request_id'))fail('plan_request_invalid','Submit only the cancellation request ID.',400);
    const saved=await txn(pool,async db=>{
      await locks(db,enrollment);enrollment=(await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1 AND company_id=$2 FOR UPDATE',[enrollment.id,enrollment.company_id])).rows[0];
      if(enrollment.service_plan_id)fail('plan_membership_active','This membership is already active. Use its signed cancellation policy.');
      await db.query('INSERT INTO agreement_plan_cancellation_requests(enrollment_id,request_id,actor_type,actor_id) VALUES($1,$2,$3,$4) ON CONFLICT(enrollment_id,request_id) DO NOTHING',[enrollment.id,requestID,actor.type,actor.id]);
      if(enrollment.canceled_at){await db.query("UPDATE agreement_plan_cancellation_requests SET state='complete',message=NULL,updated_at=now() WHERE enrollment_id=$1",[enrollment.id]);return enrollment;}
      const current=(await db.query("UPDATE agreement_plan_enrollments SET cancel_requested_at=COALESCE(cancel_requested_at,now()),state='cancellation_pending',updated_at=now() WHERE id=$1 RETURNING *",[enrollment.id])).rows[0];
      return current;
    });
    return saved.canceled_at?response(saved):finish(saved.id);
  }
  async function publicCancel(token,enrollmentID,body){const {row,role}=await service.loadPublic(pool,token);if(role!=='customer')fail('plan_primary_customer_required','The primary customer must cancel this pending enrollment.',403);const enrollment=await plans.load(pool,row,uuid(enrollmentID));await service.rate(pool,`plan-cancel:${enrollment.id}`,30,3600);return cancel(enrollment,body,{type:'customer',id:role});}
  async function staffCancel(req,enrollmentID,body){const enrollment=(await pool.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1 AND company_id=$2',[uuid(enrollmentID),req.companyId])).rows[0];if(!enrollment)fail('plan_enrollment_unavailable','This enrollment is unavailable.',404);return cancel(enrollment,body,{type:'staff',id:req.userId});}
  async function processPending(){const rows=(await pool.query("SELECT enrollment_id FROM agreement_plan_cancellation_requests WHERE state='pending' GROUP BY enrollment_id ORDER BY min(updated_at),enrollment_id LIMIT 20")).rows;for(const row of rows)await finish(row.enrollment_id);}
  const wrap=fn=>async(req,res)=>{res.set({'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer'});try{res.json(await fn(req));}catch(error){if(error instanceof QuoteContractError)return res.status(error.status).json({error:error.code,message:error.message});console.error('[plan-cancel] operation pending',{code:error?.code||'internal'});res.status(503).json({error:'plan_cancel_unavailable',message:'Cancellation could not be confirmed. Existing payment and agreement records remain saved.'});}};
  const publicWrite=(req,res,next)=>{if(!req.is('application/json'))return res.status(415).json({error:'json_required'});if(req.headers.origin&&req.headers.origin!==service.env.QUOTE_PUBLIC_BASE_URL?.replace(/\/$/,''))return res.status(403).json({error:'origin_not_allowed'});next();};
  app.post('/api/public/agreements/:token/enrollments/:id/cancel',publicWrite,wrap(req=>publicCancel(req.params.token,req.params.id,req.body)));
  if(authRequired&&requireCapability)app.post('/api/service-plan-enrollments/:id/cancel',authRequired,requireCapability('payments.collect'),wrap(req=>staffCancel(req,req.params.id,req.body)));
  let timer,running=false;if(startWorker){timer=setInterval(async()=>{if(running)return;running=true;try{await processPending();}catch{console.error('[plan-cancel] retry pending');}finally{running=false;}},60000);timer.unref();}
  return{publicCancel,staffCancel,processPending,stop:()=>clearInterval(timer)};
}
