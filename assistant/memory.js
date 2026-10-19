import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {fault,transaction} from '../mcp/context.js';

export const memoryInput=z.object({id:z.uuid().optional(),expected_revision:z.number().int().positive().optional(),body:z.string().trim().min(1).max(30000),kind:z.enum(['preference','inferred']),provenance:z.string().trim().min(1).max(1000),enabled:z.boolean().default(true)}).strict();
const secret=/\b(?:sk-[a-zA-Z0-9_-]{16,}|Bearer\s+[a-zA-Z0-9_.-]{16,}|-----BEGIN[^\n]*PRIVATE KEY|password\s*[:=]|api[_ -]?key\s*[:=])/i;
export function createMemoryService(pool){
 const list=async a=>({items:(await pool.query('SELECT id,body,kind,provenance,enabled,revision,created_at,updated_at FROM wolf_assistant_memories WHERE company_id=$1 AND user_id=$2 ORDER BY updated_at DESC LIMIT 200',[a.companyId,a.userId])).rows});
 async function save(a,raw,{fromAssistant=false}={}){
  const i=memoryInput.parse(raw);if(secret.test(i.body)||secret.test(i.provenance))throw fault(400,'secret_not_allowed');
  return transaction(pool,async db=>{
   const settings=(await db.query('SELECT memory_enabled FROM wolf_assistant_settings WHERE company_id=$1 AND user_id=$2 FOR UPDATE',[a.companyId,a.userId])).rows[0];
   if(fromAssistant){const context=(await db.query('SELECT c.memory_enabled FROM wolf_assistant_runs r JOIN wolf_assistant_conversations c ON c.id=r.conversation_id WHERE r.id=$1 AND r.user_id=$2 AND r.company_id=$3',[a.assistantInvocation?.runId||null,a.userId,a.companyId])).rows[0];if(!settings?.memory_enabled||!context?.memory_enabled)throw fault(403,'memory_disabled');}
   if(i.id){
    if(!i.expected_revision)throw fault(400,'memory_revision_required');
    const row=(await db.query('UPDATE wolf_assistant_memories SET body=$4,kind=$5,provenance=$6,enabled=$7,revision=revision+1,updated_at=now() WHERE id=$1 AND company_id=$2 AND user_id=$3 AND revision=$8 RETURNING *',[i.id,a.companyId,a.userId,i.body,i.kind,i.provenance,i.enabled,i.expected_revision])).rows[0];if(!row)throw fault(409,'memory_changed');return row;
   }
   if(Number((await db.query('SELECT count(*) n FROM wolf_assistant_memories WHERE company_id=$1 AND user_id=$2',[a.companyId,a.userId])).rows[0].n)>=200)throw fault(409,'memory_limit_reached');
   return (await db.query('INSERT INTO wolf_assistant_memories(id,company_id,user_id,body,kind,provenance,enabled) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[randomUUID(),a.companyId,a.userId,i.body,i.kind,i.provenance,i.enabled])).rows[0];
  });
 }
 const remove=async(a,id)=>{await pool.query('DELETE FROM wolf_assistant_memories WHERE id=$1 AND company_id=$2 AND user_id=$3',[z.uuid().parse(id),a.companyId,a.userId]);return {deleted:true,conversations_deleted:false};};
 return {list,save,remove};
}
