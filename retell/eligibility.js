import {digest,fault} from '../mcp/context.js';
import {missingRules,readConfig,inServiceArea,normalizeText} from './config.js';
const same=(a,b)=>JSON.stringify([...a].sort())===JSON.stringify([...b].sort());
export async function loadLead(db,actor,id){
 if(!id)return null;
 const row=(await db.query('SELECT * FROM contacts WHERE id=$1 AND company_id=$2',[id,actor.companyId])).rows[0];
 if(!row)throw fault(404,'lead_unavailable');return row;
}
export async function evaluateEligibility({db,app,actor,input}){
 const c=readConfig(actor.retell.config),lead=await loadLead(db,actor,input.lead_id),inside=inServiceArea(input.address,c);
 const quoteMissing=missingRules(c,'quote'),jobMissing=missingRules(c,'job');
 const quote={eligible:false,reason:null,configuration_required:quoteMissing},job={eligible:false,reason:null,configuration_required:jobMissing};
 const base={quote_visit:quote,direct_job:job,recommended_path:'none',requires_quote_acceptance:c.require_quote_acceptance,requires_deposit:c.require_deposit,configuration_required:[]};
 const result={eligibility:base,inside,lead,config:c,quoteMissing,jobMissing,row:null,profile:null,lineItems:null,duration:null,state:null,jobContext:null};
 const finish=()=>{base.recommended_path=job.eligible?'job':quote.eligible?'quote':'none';base.configuration_required=[...new Set([...quoteMissing.map(x=>'quote: '+x),...jobMissing.map(x=>'job: '+x)])];return result;};
 if(!inside){quote.reason=job.reason='outside_service_area_or_missing_zip';return finish();}
 quote.eligible=c.quote_enabled&&!quoteMissing.length;quote.reason=quote.eligible?null:quoteMissing.length?'configuration_required':'quote_visits_disabled';
 if(quote.eligible){const active=(await db.query('SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL AND id=ANY($2::uuid[])',[actor.companyId,c.quote_worker_ids])).rows;
  if(active.length!==new Set(c.quote_worker_ids).size){quote.eligible=false;quote.reason='configuration_required';quoteMissing.push('active quote workers');}}
 if(!c.job_enabled||jobMissing.length){job.reason=jobMissing.length?'configuration_required':'job_booking_disabled';return finish();}
 if(!lead){job.reason='lead_id_required_for_direct_job';return finish();}
 if(normalizeText(lead.address||'')!==normalizeText(input.address)){job.reason='lead_address_requires_review';return finish();}
 if(!input.services?.length){job.reason='services_required';return finish();}
 if(!app.locals.agreementBooking||!app.locals.agreements){job.reason='configuration_required';jobMissing.push('agreement booking service');return finish();}
 const rows=(await db.query(`SELECT * FROM quote_agreements WHERE company_id=$1 AND contact_id=$2 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id=$3) ORDER BY created_at DESC LIMIT 20`,[actor.companyId,lead.id,input.agreement_id||null])).rows;
 for(const row of rows){
  const lines=row.snapshot.pricing?.line_items||[];
  if(!same(input.services.map(normalizeText),lines.map(l=>normalizeText(l.name)))&&!same(input.services,lines.map(l=>l.service_id)))continue;
  const latest=(await db.query('SELECT id FROM quote_agreements WHERE company_id=$1 AND quote_id=$2 AND revoked_at IS NULL ORDER BY revision DESC LIMIT 1',[actor.companyId,row.quote_id])).rows[0];
  if(latest?.id===row.id){result.row=row;break;}
 }
 if(input.agreement_id&&!result.row){job.reason='matching_agreement_unavailable';return finish();}
 if(result.row){
  // A Riley policy can permit new direct work; it cannot waive obligations in an issued agreement.
  const row=result.row,state=await app.locals.agreements.state(db,row);result.state=state;result.duration=row.snapshot.duration_minutes??null;result.lineItems=row.snapshot.pricing?.line_items||[];
  base.requires_quote_acceptance=true;base.requires_deposit=c.require_deposit||(row.snapshot.pricing?.deposit_cents||0)>0;
  if(c.require_deposit&&(row.snapshot.pricing?.deposit_cents||0)<=0){job.reason='configuration_required';jobMissing.push('an agreement with an explicit deposit amount');return finish();}
  if(!state.can_view_availability){job.reason=state.signing!=='submitted'?'agreement_acceptance_required':!['paid','not_required'].includes(state.deposit)?'confirmed_deposit_required':'agreement_review_or_existing_booking';return finish();}
 }else{
  if(c.require_quote_acceptance){job.reason='accepted_quote_required';return finish();}
  if(c.require_deposit){job.reason='configuration_required';jobMissing.push('a published agreement defining and recording the required deposit');return finish();}
  const catalog=(await db.query('SELECT id,name FROM saved_services WHERE company_id=$1 AND archived_at IS NULL ORDER BY id LIMIT 501',[actor.companyId])).rows;
  if(catalog.length>500){job.reason='configuration_required';jobMissing.push('service catalog review');return finish();}
  const lines=[];for(const requested of input.services){const matches=catalog.filter(s=>s.id===requested||normalizeText(s.name)===normalizeText(requested));if(matches.length!==1){job.reason='service_requires_quote';return finish();}lines.push({service_id:matches[0].id,name:matches[0].name});}
  const profiles=c.direct_job_profiles.filter(p=>same(p.service_ids,lines.map(l=>l.service_id))&&p.property_type===input.property_type);
  if(!input.property_type||!input.stories){job.reason='property_type_and_stories_required';return finish();}
  if(profiles.length!==1){job.reason='configuration_required';jobMissing.push('one direct-job duration profile for these services and property type');return finish();}
  const profile=profiles[0];if(input.stories>profile.max_stories||profile.max_window_count!==null&&(input.window_count===undefined||input.window_count>profile.max_window_count)){job.reason='property_requires_quote';return finish();}
  result.profile=profile;result.duration=profile.duration_minutes;result.lineItems=lines;
 }
 const company=(await db.query('SELECT customer_booking_settings,timezone FROM companies WHERE id=$1',[actor.companyId])).rows[0],raw=company.customer_booking_settings||{};
 for(const field of ['minimum_notice_minutes','horizon_days','start_increment_minutes','buffer_before_minutes','buffer_after_minutes'])if(raw[field]===undefined)jobMissing.push(field);
 if(company.timezone!=='America/New_York')jobMissing.push('Schedule timezone America/New_York');
 if(actor.retell.config.job_rules_hash!==digest(raw))jobMissing.push('re-acknowledge changed Schedule booking rules');
 if(!Number.isInteger(result.duration)||result.duration<1)jobMissing.push('job duration');
 if(jobMissing.length){job.reason='configuration_required';return finish();}
 try{result.jobContext=await app.locals.agreementBooking.validateBookingReadiness(db,actor.companyId,{duration_minutes:result.duration,line_items:result.lineItems});}
 catch(e){if(!e.status)throw e;job.reason='configuration_required';jobMissing.push(e.code||'qualified staffing and Schedule rules');return finish();}
 job.eligible=true;return finish();
}
