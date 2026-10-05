import {authorizePage} from './access.js';
const kinds=new Set(['created','edited','blocks_edited','sharing_updated','moved','archived','unarchived','trashed','restored','version_restored','database_properties_updated','database_row_updated','checklist_converted','commented','comment_updated','comment_resolved','comment_reopened','comment_deleted']);
export async function recordNoteActivity(db,actor,pageId,kind='edited') {
 await db.query('INSERT INTO notes_activity(page_id,actor_id,kind) VALUES($1,$2,$3)',[pageId,actor.userId,kinds.has(kind)?kind:'edited']);
}
export function createNotesActivity({pool}) {
 return {async list(input,pageId,q={}){
  await authorizePage(pool,input,pageId);const offset=Math.max(0,Number.parseInt(q.offset,10)||0);
  const entries=(await pool.query('SELECT a.id,a.kind,a.created_at,u.display_name AS actor_name FROM notes_activity a JOIN users u ON u.id=a.actor_id WHERE a.page_id=$1 ORDER BY a.created_at DESC,a.id DESC LIMIT 51 OFFSET $2',[pageId,offset])).rows;
  return {entries:entries.slice(0,50),next_offset:entries.length>50?offset+50:null};
 }};
}
