import {nativeMapEditSchema,nativeLightingEditSchema,nativeBrowserEditSchema} from '../assistant/native-geometry.js';
import {taskDraftChangesSchema} from '../assistant/index.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {compactHistory,evidenceHash} from '../assistant/context.js';
import {validFieldPath,restrictFields} from '../mcp/field-policy.js';
import {aiTaskConfig} from '../assistant/automation.js';
import {createProvider,estimateMicros} from '../assistant/models.js';
import {comparableReadEvidence,retireReadEvidence} from '../assistant/reliability.js';

test('JSONB key order cannot change new receipt/evidence identity',()=>{
 assert.equal(evidenceHash({b:{z:2,a:1},a:[{y:2,x:1}]}),evidenceHash({a:[{x:1,y:2}],b:{a:1,z:2}}));
 assert.notEqual(evidenceHash({items:[1,2]}),evidenceHash({items:[2,1]}));
});
test('sales report revalidation ignores only volatile generation time',()=>{
 const report={report:{generated_at:'2026-10-20T01:00:00Z',summary:{revenue_sold_cents:1000},partial:false,failed_sources:[]},currency:'USD'};
 const reread={...report,report:{...report.report,generated_at:'2026-10-20T01:00:01Z'}};
 assert.equal(evidenceHash(comparableReadEvidence('sales_report',report)),evidenceHash(comparableReadEvidence('sales_report',reread)));
 assert.notEqual(evidenceHash(comparableReadEvidence('sales_report',report)),evidenceHash(comparableReadEvidence('sales_report',{...reread,report:{...reread.report,summary:{revenue_sold_cents:999}}})));
 assert.notEqual(evidenceHash(comparableReadEvidence('sales_report',report)),evidenceHash(comparableReadEvidence('sales_report',{...reread,report:{...reread.report,partial:true}})));
 assert.notEqual(evidenceHash(comparableReadEvidence('finance_profit_loss',report)),evidenceHash(comparableReadEvidence('finance_profit_loss',reread)));
});
test('confirmed write retires prior read values without discarding their receipts',()=>{
 const history=[{type:'function_call_output',call_id:'read',output:JSON.stringify({page:{revision:2,private:true}})},{type:'function_call_output',call_id:'other',output:JSON.stringify({ok:true})}];
 const retired=retireReadEvidence(history,[{call_id:'read',tool:'notes_page'}]);
 assert.deepEqual(JSON.parse(retired[0].output),{evidence_retired:true,capability:'notes_page',note:'A confirmed change superseded this read. Retrieve fresh authorized data before relying on it.'});
 assert.deepEqual(retired[1],history[1]);
 assert.equal(JSON.parse(history[0].output).page.revision,2);
});
test('compaction preserves call receipts and the current request',()=>{
 const history=[{role:'user',content:'Goal'},...Array.from({length:12},(_,i)=>({type:'function_call_output',call_id:String(i),output:'x'.repeat(20000)})),{role:'user',content:'Current request'}];
 const result=compactHistory(history,[{call_id:'0',tool:'contact_create',state:'completed',result:{id:'contact'}}]);
 assert.equal(result.compacted,true);assert.ok(Buffer.byteLength(JSON.stringify(result.history))<120000);
 assert.deepEqual(result.history.filter(x=>x.type==='function_call_output').map(x=>x.call_id),history.filter(x=>x.type==='function_call_output').map(x=>x.call_id));
 assert.equal(JSON.parse(result.history[1].output).record_id,'contact');assert.equal(result.history.at(-1).content,'Current request');
});
test('field restrictions reject misspellings and cover nested arrays',()=>{
 const schema={type:'object',properties:{changes:{type:'object',properties:{phone:{type:'string'}},additionalProperties:false},items:{type:'array',items:{type:'object',properties:{phone:{type:'string'}}}}},additionalProperties:false};
 assert.equal(validFieldPath(schema,'changes.phnoe'),false);assert.equal(validFieldPath(schema,'items.*.phone'),true);
 assert.throws(()=>restrictFields({items:[{phone:'private'}]},['items.*.phone'],{write:true}),e=>e.code==='field_denied');
});
test('automation configuration does not silently choose unsupported models',()=>{
 assert.equal(aiTaskConfig.safeParse({action_key:'assistant.task',execution_user_id:'a3b369b0-3f21-4b5e-828c-f312161db35a',instructions:'Report',allowed_tools:[],model:'fictional-model',reasoning:'max'}).success,false);
});
test('Responses streaming uses the chosen model, disables storage and returns usage',async()=>{
 let seen;
 const provider=createProvider({clientFactory:()=>({responses:{create:async request=>{seen=request;return (async function*(){yield {type:'response.output_text.delta',delta:'Hello'};yield {type:'response.completed',response:{output:[],usage:{input_tokens:100,output_tokens:10}}};})();}}})});
 const chunks=[];const response=await provider.respond({funding:'personal'},{model:'gpt-6.1-sol',reasoning:{effort:'low'},input:[]},{onText:async text=>chunks.push(text)});
 assert.equal(seen.store,false);assert.equal(seen.stream,true);assert.equal(seen.model,'gpt-6.1-sol');assert.deepEqual(chunks,['Hello']);assert.equal(response.usage.input_tokens,100);
 assert.equal(estimateMicros('gpt-6.1-sol',{input_tokens:100,input_tokens_details:{cached_tokens:50},output_tokens:10}),205);
});

test('funding verification never reflects provider credential diagnostics',async()=>{
 const provider=createProvider({clientFactory:()=>({models:{list:async function*(){throw Object.assign(new Error('Incorrect API key provided: sk-private-key'),{status:401});}}})});
 await assert.rejects(()=>provider.models({}),e=>e.code==='funding_verification_failed'&&!e.message.includes('sk-'));
});

test('file token preflight uses the selected funding/model and sanitizes provider diagnostics',async()=>{
 let seen,selected;
 const provider=createProvider({clientFactory:settings=>{selected=settings.funding;return {responses:{inputTokens:{count:async body=>{seen=body;return {input_tokens:1234};}}}};}});
 assert.equal(await provider.countInput({funding:'personal'},{model:'gpt-6.1-sol',input:[{role:'user',content:[{type:'input_file',filename:'private.pdf',file_data:'data:application/pdf;base64,c3ludGhldGlj'}]}],max_output_tokens:4096}),1234);
 assert.equal(selected,'personal');assert.equal(seen.model,'gpt-6.1-sol');assert.equal(seen.max_output_tokens,undefined);assert.equal(seen.input[0].content[0].type,'input_file');
 const failed=createProvider({clientFactory:()=>({responses:{inputTokens:{count:async()=>{throw new Error('Credential sk-sensitive-value');}}}})});
 await assert.rejects(failed.countInput({funding:'personal'},{model:'gpt-6.1-sol'}),e=>e.code==='file_token_count_unavailable'&&!e.message.includes('sk-'));
});

test('native command schemas match real editor domains and reject arbitrary actions and unvalidated payloads',()=>{
 const id='11111111-1111-4111-8111-111111111111';
 assert.ok(nativeMapEditSchema.safeParse({route:'map',action:'map_edit',draft_id:id,expected_revision:1,map_edit:{operation:'set_view',view:{mode:'measure',center:{latitude:38,longitude:-85}}}}).success);
 assert.equal(nativeMapEditSchema.safeParse({route:'map',action:'map_edit',draft_id:id,expected_revision:1,map_edit:{operation:'set_measurement',points:[{latitude:91,longitude:0}]}}).success,false);
 assert.ok(nativeLightingEditSchema.safeParse({route:'lighting',action:'lighting_edit',draft_id:id,expected_revision:2,lighting_edit:{operation:'set_style',style_changes:{brightness:.7,pattern:{colors:[{hex:'#FF0000'}]}},apply_scope:'selectedLayer'}}).success);
 assert.equal(nativeLightingEditSchema.safeParse({route:'lighting',action:'lighting_edit',draft_id:id,expected_revision:2,lighting_edit:{operation:'set_style',style_changes:{physical_feet:123}}}).success,false);
 assert.equal(nativeBrowserEditSchema.safeParse({route:'browser',action:'browser_edit',browser_edit:{operation:'open_url',generation:id,expected_tab_id:id,url:'javascript:alert(1)'}}).success,false);
 assert.equal(nativeBrowserEditSchema.safeParse({route:'browser',action:'browser_edit',browser_edit:{operation:'preferences',generation:id,preferences:{cookies:'secret'}}}).success,false);
 assert.equal(taskDraftChangesSchema.safeParse({alarm_snooze_minutes:17}).success,false);
 assert.ok(taskDraftChangesSchema.safeParse({due_date:'2026-10-22',has_time:false,assignee_id:'unassigned',subtasks:[{title:'Visit property',completed:false}]}).success);
});
