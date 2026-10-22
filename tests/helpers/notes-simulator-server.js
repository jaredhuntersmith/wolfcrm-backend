// Explicit standalone local fixture, never imported by production and never reads DATABASE_URL.
import express from 'express';import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './comms-fixture.js';import {installCompanyComms} from '../../company-comms/index.js';import {installNotes} from '../../notes/index.js';
import {installMediaStorage} from '../../media-storage/index.js';
const port=Number(process.env.WOLF_NOTES_FIXTURE_PORT||18587);if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('invalid_fixture_port');
const fixture=await createCommsFixture(),app=express();app.use(express.json({limit:'2mb'}));
const authRequired=(req,res,next)=>{req.userId=fixture.ids.owner;req.companyId=fixture.companies.a;next();};
let comms,storage,server;
try {
comms=await installCompanyComms({app,pool:fixture.pool,authRequired,startWorker:false});const notes=await installNotes({app,pool:fixture.pool,authRequired,notifications:comms.notifications});
// Real metadata APIs on disposable PostgreSQL; no bucket, provider or background worker.
storage=await installMediaStorage({app,pool:fixture.pool,authRequired,bucket:null,env:{},startWorker:false});
for(const item of [
 {owner:'owner',category:'image',name:'Fixture Photo',mime:'image/jpeg'},
 {owner:'owner',category:'audio',name:'Fixture Music',mime:'audio/mpeg',subtype:'music'},
 {owner:'owner',category:'audio',name:'Fixture Audiobook',mime:'audio/mpeg',subtype:'audiobook'},
 {owner:'alice',category:'audio',name:'Fixture Team Audiobook',mime:'audio/mpeg',subtype:'audiobook',visibility:'company'}
]) {
 const id=await fixture.asset(item.owner,item.category);
 await fixture.pool.query('UPDATE stored_files SET display_name=$2,original_filename=$2,mime_type=$3,audio_subtype=$4,visibility=$5 WHERE id=$1',[id,item.name,item.mime,item.subtype||'music',item.visibility||'private']);
}
app.get('/fixture/user',(req,res)=>res.json({id:fixture.ids.owner,company_id:fixture.companies.a}));
const actor=await fixture.actor('owner');let doc=await notes.create(actor,{id:randomUUID(),title:'Notes QA Welcome'});
await notes.editBlocks(actor,doc.page.id,{client_key:randomUUID(),operations:[{...doc.blocks[0],payload:{text:'Local fixture only. This page exercises the real Notes API and PostgreSQL persistence.'},expected_revision:1}]});
server=app.listen(port,'127.0.0.1',()=>console.log(`NOTES_FIXTURE_READY http://127.0.0.1:${port}`));
} catch(error) { comms?.stop();storage?.stop();await fixture.close();throw error; }
async function stop(){server.close();comms.stop();storage.stop();await fixture.close();process.exit(0);}
process.once('SIGINT',stop);process.once('SIGTERM',stop);
