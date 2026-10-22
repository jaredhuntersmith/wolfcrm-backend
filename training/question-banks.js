import {randomUUID} from 'node:crypto';
import {fail,string,uuid} from './contract.js';
import {normalizeQuiz} from './quiz-contract.js';
import {actorFor,audit,requireTraining,trainingMutation} from './service.js';

function inputFor(body){
  const scope=body?.scope??'personal';
  if(!['personal','company'].includes(scope))fail(400,'invalid_bank_scope');
  const title=string(body?.title,200),category=string(body?.category??'',100,{required:false});
  const question=normalizeQuiz({questions:[body?.question]}).questions[0];
  const imageIDs=[...new Set([question.image_file_id,...question.options.map(option=>option.image_file_id)].filter(Boolean))];
  if(imageIDs.length&&!body?.source_definition_id)fail(400,'bank_media_source_required');
  const sourceDefinitionID=imageIDs.length?uuid(body?.source_definition_id):null;
  return {scope,title,category,question,imageIDs,sourceDefinitionID};
}
async function validatedImages(db,actor,input,{requireSourceOwnership=true}={}){
  if(!input.imageIDs.length)return;
  const source=(await db.query(`SELECT created_by,scope,archived_at FROM training_definitions
    WHERE company_id=$1 AND id=$2`,[actor.companyId,input.sourceDefinitionID])).rows[0];
  if(!source||source.scope==='personal'&&source.created_by!==actor.userId||
    requireSourceOwnership&&(source.archived_at||source.created_by!==actor.userId&&!actor.isCompanyOwner))
    fail(404,'source_definition_not_found');
  const refs=(await db.query(`SELECT ar.file_id FROM training_asset_refs ar
    JOIN stored_files f ON f.company_id=ar.company_id AND f.id=ar.file_id
    WHERE ar.company_id=$1 AND ar.definition_id=$2 AND ar.file_id=ANY($3::uuid[])
      AND ar.purpose='content' AND f.source_scope='training' AND f.source_protected
      AND f.visibility='private' AND f.cloud_status='active' AND f.mime_type LIKE 'image/%'`,
  [actor.companyId,input.sourceDefinitionID,input.imageIDs])).rows;
  if(refs.length!==input.imageIDs.length)fail(409,'bank_media_unavailable');
}
function visible(actor,row){
  if(!row||row.scope==='personal'&&row.created_by!==actor.userId)fail(404,'question_not_found');
  return row;
}
function writable(actor,row){
  visible(actor,row);
  if(row.created_by!==actor.userId&&!actor.isCompanyOwner)fail(403,'author_only');
  if(row.archived_at)fail(409,'question_archived');
}
function revision(value){if(!Number.isInteger(value)||value<1)fail(400,'invalid_revision');return value;}
function dto(row){return {id:row.id,scope:row.scope,title:row.title,category:row.category,
  question:row.question,source_definition_id:row.source_definition_id,
  revision:row.revision,created_by:row.created_by,updated_at:row.updated_at};}

export function createQuestionBankService({pool}){
  return {
    async list(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');
      const rows=(await pool.query(`SELECT * FROM training_question_banks
        WHERE company_id=$1 AND archived_at IS NULL AND (scope='company' OR created_by=$2)
        ORDER BY updated_at DESC,id LIMIT 100`,[actor.companyId,actor.userId])).rows;
      return {items:rows.map(dto)};},
    async get(req,id){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');
      const row=(await pool.query(`SELECT * FROM training_question_banks WHERE company_id=$1 AND id=$2 AND archived_at IS NULL`,[actor.companyId,uuid(id)])).rows[0];
      return dto(visible(actor,row));},
    async create(req,body){const input=inputFor(body);
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{await validatedImages(db,actor,input);const id=randomUUID();const row=(await db.query(`INSERT INTO training_question_banks
        (id,company_id,created_by,scope,category,title,question,source_definition_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [id,actor.companyId,actor.userId,input.scope,input.category,input.title,JSON.stringify(input.question),input.sourceDefinitionID])).rows[0];
        await audit(db,actor,'question_bank.created',{details:{bank_id:id,scope:input.scope}});return dto(row);});},
    async update(req,id,body){const input=inputFor(body),expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const row=(await db.query(`SELECT * FROM training_question_banks WHERE company_id=$1 AND id=$2 FOR UPDATE`,[actor.companyId,uuid(id)])).rows[0];
        writable(actor,row);if(row.revision!==expected)fail(409,'stale_revision');
        await validatedImages(db,actor,input);
        const updated=(await db.query(`UPDATE training_question_banks SET scope=$3,category=$4,title=$5,question=$6,source_definition_id=$7,
          revision=revision+1,updated_at=now() WHERE company_id=$1 AND id=$2 RETURNING *`,
        [actor.companyId,row.id,input.scope,input.category,input.title,JSON.stringify(input.question),input.sourceDefinitionID])).rows[0];
        await audit(db,actor,'question_bank.updated',{details:{bank_id:row.id,revision:updated.revision}});return dto(updated);});},
    async import(req,id,body){
      const targetID=uuid(body?.definition_id);
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{
        const target=(await db.query(`SELECT created_by,scope,archived_at FROM training_definitions
          WHERE company_id=$1 AND id=$2 FOR UPDATE`,[actor.companyId,targetID])).rows[0];
        if(!target||target.archived_at||target.scope==='personal'&&target.created_by!==actor.userId||
          target.created_by!==actor.userId&&!actor.isCompanyOwner)fail(404,'definition_not_found');
        const bank=(await db.query(`SELECT * FROM training_question_banks
          WHERE company_id=$1 AND id=$2 AND archived_at IS NULL`,[actor.companyId,uuid(id)])).rows[0];
        visible(actor,bank);
        const imageIDs=[...new Set([bank.question.image_file_id,...bank.question.options.map(option=>option.image_file_id)].filter(Boolean))];
        if(imageIDs.length){
          await validatedImages(db,actor,{imageIDs,sourceDefinitionID:bank.source_definition_id},{requireSourceOwnership:false});
          for(const fileID of imageIDs)await db.query(`INSERT INTO training_asset_refs
            (id,company_id,file_id,created_by,purpose,definition_id)
            VALUES($1,$2,$3,$4,'content',$5)
            ON CONFLICT(company_id,file_id,definition_id) WHERE definition_id IS NOT NULL DO NOTHING`,
          [randomUUID(),actor.companyId,fileID,actor.userId,targetID]);
        }
        const question={...bank.question,id:randomUUID()};
        await audit(db,actor,'question_bank.imported',{definitionID:targetID,
          details:{bank_id:bank.id,question_id:question.id,image_count:imageIDs.length}});
        return {question};
      });},
    async archive(req,id,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const row=(await db.query(`SELECT * FROM training_question_banks WHERE company_id=$1 AND id=$2 FOR UPDATE`,[actor.companyId,uuid(id)])).rows[0];
        writable(actor,row);if(row.revision!==expected)fail(409,'stale_revision');
        await db.query(`UPDATE training_question_banks SET archived_at=now(),updated_at=now() WHERE company_id=$1 AND id=$2`,[actor.companyId,row.id]);
        await audit(db,actor,'question_bank.archived',{details:{bank_id:row.id}});return {id:row.id,archived:true};});}
  };
}
