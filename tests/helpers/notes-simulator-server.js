// Explicit standalone local fixture, never imported by production and never reads DATABASE_URL.
import express from 'express';import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './comms-fixture.js';import {installCompanyComms} from '../../company-comms/index.js';import {installNotes} from '../../notes/index.js';
const fixture=await createCommsFixture(),app=express();app.use(express.json({limit:'2mb'}));
const authRequired=(req,res,next)=>{req.userId=fixture.ids.owner;req.companyId=fixture.companies.a;next();};
const comms=await installCompanyComms({app,pool:fixture.pool,authRequired,startWorker:false});const notes=await installNotes({app,pool:fixture.pool,authRequired,notifications:comms.notifications});
app.get('/fixture/user',(req,res)=>res.json({id:fixture.ids.owner,company_id:fixture.companies.a}));
const actor=await fixture.actor('owner');let doc=await notes.create(actor,{id:randomUUID(),title:'Notes QA Welcome'});
await notes.editBlocks(actor,doc.page.id,{client_key:randomUUID(),operations:[{...doc.blocks[0],payload:{text:'Local fixture only. This page exercises the real Notes API and PostgreSQL persistence.'},expected_revision:1}]});
const server=app.listen(18587,'127.0.0.1',()=>console.log('NOTES_FIXTURE_READY http://127.0.0.1:18587'));
async function stop(){server.close();comms.stop();await fixture.close();process.exit(0);}
process.once('SIGINT',stop);process.once('SIGTERM',stop);
