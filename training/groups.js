import {randomUUID} from 'node:crypto';
import {fail,string,uuid} from './contract.js';
import {actorFor,eligibleAssignees,requireTraining,trainingMutation} from './service.js';

function input(body){
  const kind=string(body?.kind,20);
  if(!['team','department','group'].includes(kind))fail(400,'invalid_group_kind');
  const name=string(body?.name,120);
  if(!Array.isArray(body?.member_ids)||body.member_ids.length>500)fail(400,'invalid_group_members');
  const memberIDs=[...new Set(body.member_ids.map(uuid))].sort();
  return {kind,name,memberIDs};
}

async function replaceMembers(db,actor,groupID,memberIDs){
  if(memberIDs.length){
    await eligibleAssignees(db,actor,memberIDs);
    const employees=(await db.query(`SELECT count(*)::integer AS n FROM users
      WHERE company_id=$1 AND id=ANY($2::uuid[]) AND role='employee' AND deleted_at IS NULL`,
      [actor.companyId,memberIDs])).rows[0].n;
    if(employees!==memberIDs.length)fail(400,'invalid_group_members');
  }
  await db.query(`DELETE FROM training_audience_members WHERE company_id=$1 AND group_id=$2`,[actor.companyId,groupID]);
  for(const id of memberIDs)await db.query(`INSERT INTO training_audience_members(company_id,group_id,employee_id)
    VALUES($1,$2,$3)`,[actor.companyId,groupID,id]);
}

export function createAudienceGroupService({pool}){
  return {
    async list(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.assign');
      const rows=(await pool.query(`SELECT g.id,g.name,g.kind,g.revision,count(m.employee_id)::integer AS member_count
        FROM training_audience_groups g LEFT JOIN training_audience_members m
          ON m.company_id=g.company_id AND m.group_id=g.id
        WHERE g.company_id=$1 AND g.archived_at IS NULL
        GROUP BY g.id ORDER BY g.kind,g.name,g.id LIMIT 500`,[actor.companyId])).rows;
      return {items:rows};},
    async get(req,id){const actor=await actorFor(pool,req);if(!actor.isCompanyOwner)fail(403,'owner_only');
      const row=(await pool.query(`SELECT id,name,kind,revision,archived_at FROM training_audience_groups
        WHERE company_id=$1 AND id=$2`,[actor.companyId,uuid(id)])).rows[0];
      if(!row)fail(404,'audience_not_found');
      const members=(await pool.query(`SELECT employee_id FROM training_audience_members WHERE company_id=$1 AND group_id=$2 ORDER BY employee_id`,
        [actor.companyId,row.id])).rows;
      return {...row,member_ids:members.map(item=>item.employee_id)};},
    async create(req,body){
      const {kind,name,memberIDs}=input(body),id=randomUUID();
      return trainingMutation(pool,req,[],async (db,actor)=>{if(!actor.isCompanyOwner)fail(403,'owner_only');
        await db.query(`INSERT INTO training_audience_groups(id,company_id,name,kind,created_by) VALUES($1,$2,$3,$4,$5)`,
          [id,actor.companyId,name,kind,actor.userId]);
        await replaceMembers(db,actor,id,memberIDs);
        return {id,kind,name,revision:1,member_ids:memberIDs};});},
    async update(req,id,body){
      const {kind,name,memberIDs}=input(body),groupID=uuid(id),expected=body?.expected_revision;
      if(!Number.isInteger(expected)||expected<1)fail(400,'invalid_revision');
      return trainingMutation(pool,req,[],async (db,actor)=>{if(!actor.isCompanyOwner)fail(403,'owner_only');
        const row=(await db.query(`SELECT revision,kind,archived_at FROM training_audience_groups
          WHERE company_id=$1 AND id=$2 FOR UPDATE`,[actor.companyId,groupID])).rows[0];
        if(!row)fail(404,'audience_not_found');if(row.archived_at)fail(409,'audience_archived');
        if(row.revision!==expected)fail(409,'stale_revision');
        if(row.kind!==kind)fail(409,'group_kind_immutable');
        await replaceMembers(db,actor,groupID,memberIDs);
        await db.query(`UPDATE training_audience_groups SET name=$3,revision=revision+1,updated_at=now()
          WHERE company_id=$1 AND id=$2`,[actor.companyId,groupID,name]);
        return {id:groupID,kind,name,revision:expected+1,member_ids:memberIDs};});},
    async archive(req,id,body){
      const groupID=uuid(id),expected=body?.expected_revision;
      if(!Number.isInteger(expected)||expected<1)fail(400,'invalid_revision');
      return trainingMutation(pool,req,[],async (db,actor)=>{if(!actor.isCompanyOwner)fail(403,'owner_only');
        const row=(await db.query(`SELECT revision,archived_at FROM training_audience_groups
          WHERE company_id=$1 AND id=$2 FOR UPDATE`,[actor.companyId,groupID])).rows[0];
        if(!row)fail(404,'audience_not_found');if(row.archived_at)fail(409,'audience_archived');
        if(row.revision!==expected)fail(409,'stale_revision');
        await db.query(`UPDATE training_audience_groups SET archived_at=now(),revision=revision+1,updated_at=now()
          WHERE company_id=$1 AND id=$2`,[actor.companyId,groupID]);
        return {id:groupID,archived:true,revision:expected+1};});}
  };
}
