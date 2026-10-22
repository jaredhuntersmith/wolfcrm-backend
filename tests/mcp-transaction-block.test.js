import test from 'node:test';
import assert from 'node:assert/strict';
import {AsyncResource} from 'node:async_hooks';
import {transaction,transactionalPool,hasActiveBusinessTransaction,serializeBusinessTransactionBlock} from '../mcp/context.js';

test('business blocks serialize borrowed SQL, are reentrant and release after errors',async()=>{
 const trace=[];let release,started,stale;
 const gate=new Promise(r=>release=r),entered=new Promise(r=>started=r);
 const raw={connect:async()=>({query:async sql=>{trace.push(sql);return {command:sql==='COMMIT'?'COMMIT':'SELECT',rows:[]};},release(){trace.push('released');}})};
 const pool=transactionalPool(raw);
 assert.equal(hasActiveBusinessTransaction(),false);
 await transaction(pool,async()=>{
  assert.equal(hasActiveBusinessTransaction(),true);
  const resource=new AsyncResource('closed-business-context');stale=()=>resource.runInAsyncScope(()=>hasActiveBusinessTransaction());
  const first=serializeBusinessTransactionBlock(async()=>{trace.push('scope');started();await gate;await serializeBusinessTransactionBlock(()=>pool.query('REENTRANT'));trace.push('cleanup');});
  await entered;
  const ordinary=pool.query('ORDINARY');
  const failure=serializeBusinessTransactionBlock(()=>{throw new Error('synthetic block error');});
  const rejected=assert.rejects(failure,/synthetic block error/);
  const last=serializeBusinessTransactionBlock(()=>pool.query('AFTER ERROR'));
  release();await Promise.all([first,ordinary,rejected,last]);
 });
 assert.ok(trace.indexOf('scope')<trace.indexOf('REENTRANT'));
 assert.ok(trace.indexOf('cleanup')<trace.indexOf('ORDINARY'));
 assert.ok(trace.indexOf('ORDINARY')<trace.indexOf('AFTER ERROR'));
 assert.equal(trace.at(-1),'released');assert.equal(hasActiveBusinessTransaction(),false);
 assert.throws(stale,e=>e.code==='transaction_closed');
});
