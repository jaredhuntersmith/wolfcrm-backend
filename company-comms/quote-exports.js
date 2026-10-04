import {installRateLimits,takeRateLimit} from './rate-limits.js';
import {createHash,randomUUID} from 'node:crypto';
import {loadActor,requireCapability,mutate,uuid,fail,audit} from './access.js';
import {validateShares} from './sources.js';
const version=row=>createHash('sha256').update(JSON.stringify(row)).digest('hex');
export async function installCommsQuoteExports({app,pool,authRequired,storage}){
 await installRateLimits(pool);
 await pool.query(`ALTER TABLE stored_files ADD COLUMN IF NOT EXISTS source_protected boolean NOT NULL DEFAULT false;
 CREATE TABLE IF NOT EXISTS comms_quote_exports(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),quote_id uuid NOT NULL REFERENCES quotes(id),created_by uuid NOT NULL REFERENCES users(id),source_version text NOT NULL,format text NOT NULL CHECK(format IN ('pdf','images')),asset_ids uuid[] NOT NULL,created_at timestamptz NOT NULL DEFAULT now());`);
 async function quote(db,input,quoteID){const actor=await loadActor(db,input);for(const cap of ['communications.share','quotes.export','quotes.view','quotes.share','storage.upload','storage.share'])requireCapability(actor,cap);await validateShares(db,actor,[{source_type:'quote',source_id:uuid(quoteID)}]);const row=(await db.query('SELECT * FROM quotes WHERE id=$1 AND company_id=$2',[quoteID,actor.companyId])).rows[0];return {actor,row,version:version(row)};}
 const wrap=fn=>async(req,res)=>{res.set('Cache-Control','private, no-store');try{await takeRateLimit(pool,req);res.json(await fn(req));}catch(e){if(!e.status)console.error('[comms_export]',e.code||e.name);res.status(e.status||503).json({error:e.status?e.code:'quote_export_unavailable',message:e.status?e.message:'Quote export is temporarily unavailable. Please retry.'});}};
 app.get('/api/comms/quotes/:id/export-context',authRequired,wrap(async r=>{const q=await quote(pool,r,r.params.id);return {version:q.version,quote_id:q.row.id,contact_id:q.row.contact_id};}));
 app.post('/api/comms/quotes/:id/exports',authRequired,wrap(r=>mutate(pool,r,async(db,actor)=>{
  const q=await quote(db,actor,r.params.id);if(q.version!==r.body.source_version)fail(409,'quote_changed','The quote changed. Prepare a new export before sharing.');
  const exportID=uuid(r.body.id),format=r.body.format;if(!['pdf','images'].includes(format))fail(400,'invalid_export_format');
  const old=(await db.query('SELECT * FROM comms_quote_exports WHERE id=$1',[exportID])).rows[0];if(old){if(old.company_id!==actor.companyId||old.created_by!==actor.userId||old.quote_id!==q.row.id)fail(409,'idempotency_conflict');return {id:old.id,asset_ids:old.asset_ids,files:(await db.query('SELECT * FROM stored_files WHERE id=ANY($1::uuid[])',[old.asset_ids])).rows.map(({object_key,upload_id,...file})=>file)};}
  if(!Array.isArray(r.body.files)||!r.body.files.length||r.body.files.length>100||format==='pdf'&&r.body.files.length!==1)fail(400,'invalid_export_pages');
  const files=[];
  for(const input of r.body.files){if(format==='pdf'&&input.mime_type!=='application/pdf'||format==='images'&&input.mime_type!=='image/png')fail(400,'invalid_export_mime');
   const fileID=uuid(input.id);if((await db.query('SELECT 1 FROM stored_files WHERE id=$1',[fileID])).rowCount)fail(409,'export_asset_exists');
   const reserved=await storage.reserveInTransaction(db,actor,{...input,display_name:input.original_filename,visibility:'private'},{sourceProtected:true});
   await db.query(`INSERT INTO comms_asset_provenance(asset_id,company_id,source_type,source_id,context_type,source_version) VALUES($1,$2,'quote',$3,'quote',$4)`,[fileID,actor.companyId,q.row.id,q.version]);
   await db.query('UPDATE stored_files SET source_protected=true WHERE id=$1',[fileID]);files.push({...reserved.file,source_protected:true});
  }
  await db.query(`INSERT INTO comms_quote_exports(id,company_id,quote_id,created_by,source_version,format,asset_ids) VALUES($1,$2,$3,$4,$5,$6,$7)`,[exportID,actor.companyId,q.row.id,actor.userId,q.version,format,files.map(f=>f.id)]);
  await audit(db,actor,'quote_export_reserved','quote',q.row.id,{export_id:exportID,format,pages:files.length});return {id:exportID,asset_ids:files.map(f=>f.id),files};
 })));
}
