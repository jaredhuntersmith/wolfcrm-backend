import {actorFor,requireTraining} from './service.js';

export function createVideoReviewService({pool}){
  return {
    async list(req){
      const actor=await actorFor(pool,req);
      requireTraining(actor,'training.review');
      const result=await pool.query(`
        WITH pending AS (
          SELECT c.id,c.company_id,c.recipient_id,c.version_id,c.block_id,
            NULL::text AS checkpoint_id,'knowledge_check'::text AS kind,c.submitted_at
          FROM training_video_checks c WHERE c.company_id=$1 AND c.status='awaiting_manual'
          UNION ALL
          SELECT a.id,a.company_id,a.recipient_id,a.version_id,a.block_id,
            a.checkpoint_id,'checkpoint'::text AS kind,a.submitted_at
          FROM training_video_checkpoint_attempts a
          WHERE a.company_id=$1 AND a.status='awaiting_manual' AND NOT a.unlocked
        )
        SELECT p.id,p.recipient_id,p.block_id,p.checkpoint_id,p.kind,p.submitted_at,
          v.title,r.employee_name_snapshot AS employee_name
        FROM pending p
        JOIN training_recipients r ON r.company_id=p.company_id AND r.id=p.recipient_id
        JOIN training_versions v ON v.company_id=p.company_id AND v.id=p.version_id
        WHERE r.employee_id<>$2 AND ($3::boolean OR EXISTS (
          SELECT 1 FROM training_supervisor_grants g
          WHERE g.company_id=p.company_id AND g.supervisor_id=$2 AND g.employee_id=r.employee_id
        ))
        ORDER BY p.submitted_at ASC,p.id ASC LIMIT 100`,
      [actor.companyId,actor.userId,actor.isCompanyOwner]);
      return {items:result.rows};
    }
  };
}
