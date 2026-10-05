import {sourceAccessSQL} from '../company-comms/sources.js';
// Reuse the canonical CRM/Stage/Task/Note policy before a reference can cause a
// search hit. Neither an inaccessible source name nor its existence is exposed.
export function referenceSearchSQL(actor,term) {
 return `EXISTS(SELECT 1 FROM notes_blocks sb CROSS JOIN LATERAL (
 SELECT CASE sb.type WHEN 'quote_card' THEN 'quote' WHEN 'page_link' THEN 'note' WHEN 'child_page' THEN 'note' WHEN 'database' THEN 'note' ELSE sb.type END source_type,
 COALESCE(sb.payload->>'source_id',sb.payload->>'target_id') source_id,sb.payload->>'context_type' context_type
 ) sr WHERE sb.page_id=n.id AND sb.deleted_at IS NULL AND (${sourceAccessSQL(actor,'sr')}) AND (
 CASE sr.source_type
 WHEN 'contact' THEN (SELECT x.name FROM contacts x WHERE x.id::text=sr.source_id AND x.company_id=$2)
 WHEN 'stage_entry' THEN (SELECT cx.name FROM opportunities x JOIN contacts cx ON cx.id::text=x.contact_id AND cx.company_id=x.company_id WHERE x.id=sr.source_id AND x.company_id=$2)
 WHEN 'job' THEN (SELECT x.title FROM schedule_events x WHERE x.id=sr.source_id AND x.company_id=$2)
 WHEN 'quote' THEN (SELECT x.title FROM quotes x WHERE x.id::text=sr.source_id AND x.company_id=$2)
 WHEN 'task' THEN (SELECT x.title FROM todo_tasks x JOIN users ux ON ux.id=x.user_id WHERE x.id=sr.source_id AND ux.company_id=$2)
 WHEN 'service_plan' THEN (SELECT x.plan_name FROM service_plans x WHERE x.id::text=sr.source_id AND x.company_id=$2)
 WHEN 'note' THEN (SELECT x.title FROM comms_notes x WHERE x.id::text=sr.source_id AND x.company_id=$2 AND x.purged_at IS NULL)
 ELSE NULL END) ILIKE ${term})`;
}
export function inlineTagPattern(tag) {return '(^|[[:space:]])#'+tag.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'($|[^[:alnum:]_-])';}
