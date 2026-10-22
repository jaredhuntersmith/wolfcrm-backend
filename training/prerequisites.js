import {fail,uuid} from './contract.js';

export function prerequisiteIDs(value){
  if(value==null)return null;
  if(!Array.isArray(value)||value.length>20)fail(400,'invalid_assignment_prerequisites');
  const ids=value.map(uuid);
  if(new Set(ids).size!==ids.length)fail(400,'duplicate_assignment_prerequisite');
  return ids.sort();
}

// Prerequisites are existing immutable assignments. Edges are inserted only
// for a new assignment, so the graph follows creation order and cannot cycle.
export async function validatePrerequisites(db,actor,ids,recipientIDs){
  if(!ids?.length)return;
  const assignments=(await db.query(`SELECT id,assigned_by FROM training_assignments
    WHERE company_id=$1 AND id=ANY($2::uuid[]) FOR KEY SHARE`,[actor.companyId,ids])).rows;
  if(assignments.length!==ids.length)fail(404,'assignment_prerequisite_not_found');
  if(!actor.isCompanyOwner&&assignments.some(row=>row.assigned_by!==actor.userId))fail(403,'assignment_prerequisite_scope_denied');
  const members=(await db.query(`SELECT assignment_id,employee_id FROM training_recipients
    WHERE company_id=$1 AND assignment_id=ANY($2::uuid[]) AND employee_id=ANY($3::uuid[])`,
  [actor.companyId,ids,recipientIDs])).rows;
  if(members.length!==ids.length*recipientIDs.length)fail(409,'assignment_prerequisite_recipient_missing');
}

export async function attachPrerequisites(db,actor,assignmentID,ids){
  for(const id of ids??[])await db.query(`INSERT INTO training_assignment_prerequisites
    (company_id,assignment_id,prerequisite_assignment_id) VALUES($1,$2,$3)`,[actor.companyId,assignmentID,id]);
  if(!ids?.length)return;
  const children=(await db.query(`SELECT DISTINCT child.assignment_id FROM training_linked_runs lr
    JOIN training_recipients parent ON parent.company_id=lr.company_id AND parent.id=lr.parent_recipient_id
    JOIN training_recipients child ON child.company_id=lr.company_id AND child.id=lr.child_recipient_id
    WHERE lr.company_id=$1 AND parent.assignment_id=$2`,[actor.companyId,assignmentID])).rows;
  for(const child of children)for(const id of ids)await db.query(`INSERT INTO training_assignment_prerequisites
    (company_id,assignment_id,prerequisite_assignment_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
  [actor.companyId,child.assignment_id,id]);
}

export async function prerequisiteState(db,actor,row){
  const items=(await db.query(`SELECT p.prerequisite_assignment_id AS assignment_id,r.id AS recipient_id,
    COALESCE(r.status,'missing') AS status,v.title FROM training_assignment_prerequisites p
    LEFT JOIN training_recipients r ON r.company_id=p.company_id AND r.assignment_id=p.prerequisite_assignment_id
      AND r.employee_id=$3
    JOIN training_assignments a ON a.company_id=p.company_id AND a.id=p.prerequisite_assignment_id
    JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
    WHERE p.company_id=$1 AND p.assignment_id=$2
    ORDER BY v.title,p.prerequisite_assignment_id`,[actor.companyId,row.assignment_id,row.employee_id])).rows;
  return {items,blocked:items.some(item=>item.status!=='completed')};
}

export async function requirePrerequisites(db,actor,row){
  const state=await prerequisiteState(db,actor,row);
  if(state.blocked)fail(409,'assignment_prerequisite_incomplete','Complete the required earlier assignments first.');
}
