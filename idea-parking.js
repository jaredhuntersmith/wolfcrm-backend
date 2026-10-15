// The original table identities are retained from the legacy nested backend.
function fail(status,message){const e=new Error(message);e.status=status;throw e;}
const clean=value=>String(value??'').replace(/\s+/g,' ').trim();
const validID=value=>typeof value==='string'&&value.length>0&&value.length<=100;
const access=`(l.user_id=$1 OR (l.company_id=$2 AND (l.visibility='company' OR (l.visibility='shared' AND EXISTS(SELECT 1 FROM idea_parking_members m WHERE m.list_id=l.id AND m.user_id=$1)))))`;
export async function installIdeaParking({app,pool,authRequired}){
 await pool.query(`CREATE TABLE IF NOT EXISTS idea_parking_lists(id text PRIMARY KEY,user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,company_id uuid,name text NOT NULL,sort_order integer NOT NULL DEFAULT 0,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
 CREATE TABLE IF NOT EXISTS idea_parking_ideas(id text PRIMARY KEY,user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,company_id uuid,text text NOT NULL,list_id text REFERENCES idea_parking_lists(id) ON DELETE SET NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
 ALTER TABLE idea_parking_lists ADD COLUMN IF NOT EXISTS visibility text NOT NULL DEFAULT 'private' CHECK(visibility IN ('private','shared','company'));
 ALTER TABLE idea_parking_lists ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;
 CREATE TABLE IF NOT EXISTS idea_parking_members(list_id text NOT NULL REFERENCES idea_parking_lists(id) ON DELETE CASCADE,user_id uuid NOT NULL REFERENCES users(id),PRIMARY KEY(list_id,user_id));
 CREATE INDEX IF NOT EXISTS idea_parking_lists_audience ON idea_parking_lists(company_id,visibility,user_id);
 CREATE INDEX IF NOT EXISTS idea_parking_ideas_list ON idea_parking_ideas(list_id,user_id);
 CREATE INDEX IF NOT EXISTS idea_parking_ideas_owner ON idea_parking_ideas(user_id,created_at);`);
 const wrap=fn=>async(req,res)=>{res.set('Cache-Control','private, no-store');try{const result=await fn(req);if(result===undefined)res.sendStatus(204);else res.json(result);}catch(error){res.status(error.status||500).json({error:'idea_parking_error',message:error.status?error.message:'Ideas could not be loaded or saved.'});}};
 async function transaction(work){const db=await pool.connect();try{await db.query('BEGIN');const r=await work(db);await db.query('COMMIT');return r;}catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}}
 const args=req=>[req.userId,req.companyId||null];
 const ideaAccess=`(i.list_id IS NULL AND i.user_id=$1 OR EXISTS(SELECT 1 FROM idea_parking_lists l WHERE l.id=i.list_id AND ${access}))`;
 const listDTO=(row,user)=>({...row,can_manage:row.user_id===user});
 app.get('/api/idea-parking/people',authRequired,wrap(async req=>({people:(await pool.query('SELECT id,display_name FROM users WHERE company_id=$1 AND deleted_at IS NULL ORDER BY display_name,id',[req.companyId])).rows})));
 app.get('/api/idea-parking/lists',authRequired,wrap(async req=>(await pool.query(`SELECT l.*,ARRAY(SELECT user_id FROM idea_parking_members WHERE list_id=l.id) AS member_ids FROM idea_parking_lists l WHERE ${access} ORDER BY sort_order,created_at,id`,args(req))).rows.map(r=>listDTO(r,req.userId))));
 app.put('/api/idea-parking/lists/:id',authRequired,wrap(req=>transaction(async db=>{
  if(req.body.member_ids!==undefined&&!Array.isArray(req.body.member_ids))fail(400,'Choose valid company members.');
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",['idea-list:'+req.params.id]);
  const name=clean(req.body.name),visibility=req.body.visibility||'private',members=visibility==='shared'?[...new Set(req.body.member_ids||[])].filter(id=>id!==req.userId):[];
  if(!validID(req.params.id)||!name||name.length>120||!['private','shared','company'].includes(visibility)||members.length>200||members.some(id=>!validID(id)))fail(400,'Choose a list name and valid sharing settings.');
  if(visibility!=='private'&&!req.companyId)fail(400,'Join a company before sharing.');
  if(visibility==='shared'&&!members.length)fail(400,'Choose at least one person.');
  const old=(await db.query('SELECT * FROM idea_parking_lists WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];
  if(old&&old.user_id!==req.userId)fail(404,'Only the list owner can change its settings.');
  if(old&&req.body.expected_revision!==old.revision)fail(409,'This list changed. Reload before saving.');
  if(members.length!==(await db.query('SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL AND id::text=ANY($2::text[])',[req.companyId,members])).rowCount)fail(400,'Choose current members of your company.');
  const row=(await db.query(`INSERT INTO idea_parking_lists(id,user_id,company_id,name,sort_order,visibility) VALUES($1,$2,$3,$4,$5,$6)
   ON CONFLICT(id) DO UPDATE SET name=$4,sort_order=$5,visibility=$6,revision=idea_parking_lists.revision+1,updated_at=now() RETURNING *`,[req.params.id,req.userId,req.companyId||null,name,Number.isSafeInteger(req.body.sort_order)?req.body.sort_order:0,visibility])).rows[0];
  await db.query('DELETE FROM idea_parking_members WHERE list_id=$1',[row.id]);
  if(visibility==='shared')for(const id of members)await db.query('INSERT INTO idea_parking_members VALUES($1,$2)',[row.id,id]);
  return listDTO({...row,member_ids:visibility==='shared'?members:[]},req.userId);
 })));
 app.delete('/api/idea-parking/lists/:id',authRequired,wrap(req=>transaction(async db=>{
  const row=(await db.query('SELECT id FROM idea_parking_lists WHERE id=$1 AND user_id=$2 FOR UPDATE',[req.params.id,req.userId])).rows[0];if(!row)fail(404,'List unavailable.');
  await db.query('UPDATE idea_parking_ideas SET list_id=NULL,updated_at=now() WHERE list_id=$1',[row.id]);await db.query('DELETE FROM idea_parking_lists WHERE id=$1',[row.id]);
 })));
 app.get('/api/idea-parking/ideas',authRequired,wrap(async req=>(await pool.query(`SELECT i.*, (i.user_id=$1 OR EXISTS(SELECT 1 FROM idea_parking_lists l WHERE l.id=i.list_id AND l.user_id=$1)) AS can_edit FROM idea_parking_ideas i WHERE ${ideaAccess} AND ($3::text IS NULL OR i.list_id=$3) ORDER BY created_at DESC,id`,[...args(req),req.query.list_id||null])).rows));
 app.put('/api/idea-parking/ideas/:id',authRequired,wrap(req=>transaction(async db=>{
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",['idea:'+req.params.id]);
  const content=clean(req.body.text),list=req.body.list_id||null;
  if(!validID(req.params.id)||!content||content.length>2000||(content.match(/[\p{L}\p{N}]+(?:'[\p{L}\p{N}]+)?/gu)||[]).length>20)fail(400,'Write an idea in 20 words or fewer.');
  const old=(await db.query('SELECT * FROM idea_parking_ideas WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];
  if(old){const visible=(await db.query(`SELECT i.id FROM idea_parking_ideas i WHERE i.id=$3 AND ${ideaAccess} AND (i.user_id=$1 OR EXISTS(SELECT 1 FROM idea_parking_lists l WHERE l.id=i.list_id AND l.user_id=$1))`,[...args(req),old.id])).rowCount;if(!visible)fail(404,'Idea unavailable.');}
  if(list&&!(await db.query(`SELECT l.id FROM idea_parking_lists l WHERE l.id=$3 AND ${access} FOR SHARE`,[...args(req),list])).rowCount)fail(404,'Destination list unavailable.');
  // Only the creator can remove their contribution into a private/unfiled location.
  if(old&&old.user_id!==req.userId&&old.list_id!==list)fail(403,'Only the idea creator can move it to a different audience.');
  return (await db.query(`INSERT INTO idea_parking_ideas(id,user_id,company_id,text,list_id) VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(id) DO UPDATE SET text=$4,list_id=$5,updated_at=now() RETURNING *,true AS can_edit`,[req.params.id,req.userId,req.companyId||null,content,list])).rows[0];
 })));
 app.delete('/api/idea-parking/ideas/:id',authRequired,wrap(async req=>{
  const result=await pool.query(`DELETE FROM idea_parking_ideas i WHERE i.id=$3 AND ${ideaAccess} AND (i.user_id=$1 OR EXISTS(SELECT 1 FROM idea_parking_lists l WHERE l.id=i.list_id AND l.user_id=$1))`,[...args(req),req.params.id]);if(!result.rowCount)fail(404,'Idea unavailable.');
 }));
}
