import {z} from 'zod';
import {fault} from '../mcp/context.js';

export const adsWebhookFields={
 'facebook_ads.changed':['receipt_id','account_id','entity_id','level','status','target','currency','timezone'],
 'facebook_ads.metric':['evaluation_id','account_id','entity_id','level','metric','value','metrics','period','currency','timezone','evaluated_at'],
};
export const isAdsWebhookEvent=type=>Object.hasOwn(adsWebhookFields,type);

// Project only durable, company-owned business facts. Reused immediately before
// delivery so a queued payload cannot outlive revocation/account deselection.
export async function projectAdsWebhookEvent({pool,service,actor,event}){
 if(!service||event.company_id!==actor.companyId||!isAdsWebhookEvent(event.event_type))throw fault(403,'ads_event_unavailable');
 let data;
 if(event.event_type==='facebook_ads.changed'){
  const id=z.uuid().safeParse(event.payload?.receipt_id);
  if(!id.success)throw fault(409,'ads_receipt_unconfirmed');
  const receipt=(await pool.query("SELECT id,account_id,entity_id,level,status,target,result FROM facebook_ads_receipts WHERE id=$1 AND company_id=$2 AND entity_id=$3 AND status='confirmed'",[id.data,actor.companyId,event.subject_id])).rows[0];
  if(!receipt)throw fault(409,'ads_receipt_unconfirmed');
  const {a}=await service.account(actor,receipt.account_id);
  data={receipt_id:receipt.id,account_id:receipt.account_id,entity_id:receipt.entity_id,level:receipt.level,status:'confirmed',target:receipt.target,currency:a.currency,timezone:a.timezone_name};
 }else{
  const id=z.uuid().safeParse(event.payload?.evaluation_id);
  if(!id.success)throw fault(409,'ads_evaluation_unconfirmed');
  const evaluation=(await pool.query("SELECT * FROM facebook_ads_evaluations WHERE id=$1 AND company_id=$2 AND entity_id=$3 AND status='fired'",[id.data,actor.companyId,event.subject_id])).rows[0];
  if(!evaluation||evaluation.node_id!==event.payload?.trigger_node_id)throw fault(409,'ads_evaluation_unconfirmed');
  // The durable event records the rule that fired. Editing/deleting the graph
  // later must not relabel its account or metric using a newer node config.
  const rule=z.object({account_id:z.string().regex(/^\d+$/),level:z.enum(['campaign','adset','ad']),metric:z.string().min(1)}).parse(event.payload);
  const {a}=await service.account(actor,rule.account_id);
  data={evaluation_id:evaluation.id,account_id:rule.account_id,entity_id:evaluation.entity_id,level:rule.level,metric:rule.metric,value:evaluation.details.values?.[rule.metric]??null,metrics:evaluation.details.values,period:evaluation.details.period,currency:evaluation.details.currency||a.currency,timezone:event.payload.timezone||a.timezone_name,evaluated_at:event.payload.evaluated_at};
 }
 return {data,sourceRef:{kind:'facebook_ads_event',id:event.id}};
}
