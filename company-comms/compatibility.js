import {takeRateLimit} from './rate-limits.js';
import {randomUUID} from 'node:crypto';
import {authorizeConversation,authorizeGroup,loadActor,requireCapability,mutate,publish,fail,id} from './access.js';
// Old clients resolve retained IDs through the same ACLs, never directly through company membership.
export function installCommsCompatibility({app,pool,authRequired}){
 const route=(method,path,fn)=>app[method]('/api/internal'+path,authRequired,async(req,res)=>{res.set('Cache-Control','private, no-store');try{await takeRateLimit(pool,req);res.json(await fn(req,app.locals.comms));}catch(e){res.status(e.status||503).json({error:e.code||'comms_unavailable',message:e.status?e.message:'Company Comms is temporarily unavailable.'});}});
 const key=r=>r.body.client_key||r.get('Idempotency-Key')||randomUUID();
 async function legacyGroup(r){const row=(await pool.query(`SELECT g.id,t.conversation_id FROM comms_groups g JOIN comms_threads t ON t.group_id=g.id AND t.kind='general' WHERE g.company_id=$2 AND (g.legacy_channel_id=$1 OR g.id::text=$1)`,[id(r.params.id),r.companyId])).rows[0];if(!row)fail(404,'channel_unavailable');await authorizeGroup(pool,r,row.id);return row;}
 async function history(r,s,conversation){const page=await s.messages.history(r,conversation,{...r.query,limit:r.query.limit||100});return Promise.all(page.messages.map(async message=>{
  // Only canonical authorized assets can be delivered; old permanent URL fields are not re-exposed.
  const attachments=[];for(const asset of message.attachments){if(asset.unavailable){attachments.push({id:randomUUID(),kind:'file',file_name:'Attachment unavailable'});continue;}
   const access=await app.locals.mediaStorage.access(r,asset.id,'preview');attachments.push({id:asset.id,kind:asset.category==='image'?'photo':asset.category==='video'?'video':'file',url:access.url,file_name:asset.display_name,mime_type:asset.mime_type,byte_size:asset.byte_size});}
  return {...message,attachments};
 }));}
 async function send(r,s,conversation){if(r.body.attachments?.length)fail(426,'update_required','Update WolfCRM to send files through private Media/Storage sharing. Existing attachments are preserved.');return s.messages.send(r,conversation,{client_key:key(r),body:r.body.body||'',asset_ids:[],cards:[]});}
 route('get','/conversations',async(r,s)=>(await s.messages.list(r)).filter(c=>['dm','group_dm'].includes(c.scope)));
 route('post','/conversations/private',(r,s)=>s.messages.create(r,{client_key:key(r),member_ids:[r.body.user_id],title:'Conversation'}));
 route('post','/conversations/group',(r,s)=>s.messages.create(r,{client_key:key(r),member_ids:r.body.participant_ids,title:r.body.title||'Group',force_new:true}));
 route('get','/conversations/:id/messages',(r,s)=>history(r,s,r.params.id));route('post','/conversations/:id/messages',(r,s)=>send(r,s,r.params.id));
 route('post','/conversations/:id/read',async(r,s)=>{const page=await s.messages.history(r,r.params.id,{limit:1});return page.messages.length?s.messages.read(r,r.params.id,{last_message_id:page.messages.at(-1).id}):{ok:true};});
 route('delete','/conversations/:id',async r=>mutate(pool,r,async(db,actor)=>{const c=await authorizeConversation(db,actor,r.params.id,{write:true});if(c.thread_id)fail(400,'use_channel_controls');await db.query('UPDATE conversation_participants SET left_at=now() WHERE conversation_id=$1 AND user_id=$2',[c.id,actor.userId]);await publish(db,actor,c.id,'membership.changed',c.id);return {ok:true};}));
 route('get','/channels',async(r,s)=>{const rows=await s.groups.list(r);const result=[];for(const g of rows.filter(x=>x.membership_status==='active')){const tree=await s.groups.detail(r,g.id);result.push({id:g.legacy_channel_id||g.id,name:g.name,description:g.description,created_by:g.original_creator_id,created_at:g.created_at,archived_at:g.archived_at,unread_count:tree.threads.find(t=>t.kind==='general')?.unread_count||0});}return result;});
 route('post','/channels',async(r,s)=>{const tree=await s.groups.create(r,{name:r.body.name,description:r.body.description||'',visibility:'invite',member_ids:[]});return {...tree.group,id:tree.group.id,created_by:tree.group.original_creator_id};});
 route('get','/channels/:id/messages',async(r,s)=>history(r,s,(await legacyGroup(r)).conversation_id));route('post','/channels/:id/messages',async(r,s)=>send(r,s,(await legacyGroup(r)).conversation_id));
 route('delete','/channels/:id',async(r,s)=>{const g=await legacyGroup(r),tree=await s.groups.detail(r,g.id);return s.groups.lifecycle(r,g.id,{action:'archive',expected_revision:tree.group.revision});});
 route('delete','/messages/:id',async(r,s)=>{const row=await s.messages.message(pool,r,r.params.id);return s.messages.edit(r,r.params.id,{expected_revision:row.revision,reason:r.body.reason},true);});
 route('post','/media/upload-url',()=>fail(426,'update_required','Update WolfCRM to upload files through Media/Storage.'));
 route('get','/media/download-url',async r=>{const actor=await loadActor(pool,r);requireCapability(actor,'communications.view');const key=String(r.query.object_key||'');const row=(await pool.query(`SELECT id FROM stored_files WHERE object_key=$1 AND company_id=$2 AND storage_provider='legacy_media'`,[key,actor.companyId])).rows[0];if(!row)fail(404,'attachment_unavailable');const access=await app.locals.mediaStorage.access(actor,row.id,'preview');return {download_url:access.url};});
}
