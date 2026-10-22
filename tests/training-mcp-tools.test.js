import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {registerTrainingTools} from '../mcp/training-tools.js';

test('training MCP tools keep caller data out of routes and require scoped typed inputs',()=>{
  const tools=new Map();
  registerTrainingTools({
    read:(name,description,schema,scope,caps,path)=>tools.set(name,{description,schema,scope,caps,path}),
    write:(name,description,schema,scope,caps,method,path,body)=>tools.set(name,{description,schema,scope,caps,method,path,body}),
  });
  assert.ok(tools.size>=20);
  for(const [name,entry] of tools){
    assert.match(name,/^training_/);
    assert.ok(entry.caps.length,'every training tool must require a training capability');
    assert.match(entry.scope,/^(crm|team):(read|write)$/);
    assert.ok(entry.path);
    assert.ok(!name.includes('video_session'),'live playback cannot be simulated by a generic tool');
  }
  const id=randomUUID(),requestKey=randomUUID();
  const assignment=tools.get('training_assignment');
  assert.equal(assignment.path(assignment.schema.parse({id})),`/api/training/recipients/${id}`);
  assert.equal(assignment.schema.safeParse({id:`${id}/../../definitions`}).success,false);
  assert.equal(assignment.schema.safeParse({id,url:'https://example.invalid'}).success,false);
  const save=tools.get('training_save_responses');
  assert.equal(save.method,'PUT');
  assert.deepEqual(save.body(save.schema.parse({id,expected_revision:2,responses:{step:true}}),requestKey),
    {expected_revision:2,responses:{step:true}});
  assert.equal(save.schema.safeParse({id,expected_revision:0,responses:{}}).success,false);
  const assigned=tools.get('training_assign');
  assert.equal(assigned.path,'/api/training/assignments');
  assert.deepEqual(assigned.body(assigned.schema.parse({definition_id:id,recipient_ids:[id]}),requestKey),
    {definition_id:id,recipient_ids:[id],request_key:requestKey});
  assert.equal(assigned.schema.safeParse({definition_id:id,audience:{kind:'team',id}}).success,true);
  assert.equal(assigned.schema.safeParse({definition_id:id,audience:{kind:'company',id}}).success,false);
  const definition=tools.get('training_definition');
  assert.deepEqual(definition.caps,['training.author'],'answer-key route requires author capability');
  assert.deepEqual(tools.get('training_reviews').caps,['training.review']);
  const grade=tools.get('training_quiz_grade');
  assert.equal(grade.schema.safeParse({id,expected_revision:1,grades:{essay:{points:2,feedback:'Good'}}}).success,true);
  assert.equal(grade.schema.safeParse({id,expected_revision:1,grades:{essay:2}}).success,false);
  const managed=tools.get('training_managed_assignments');
  assert.deepEqual(managed.caps,['training.review']);
  assert.equal(managed.path(managed.schema.parse({search:'safety & equipment'})),
    '/api/training/managed?search=safety+%26+equipment&limit=50');
  const override=tools.get('training_completion_override');
  assert.deepEqual(override.caps,['training.override']);
  assert.equal(override.schema.safeParse({id,expected_revision:1,reason:'Too short'}).success,false);
  assert.equal(override.body(override.schema.parse({id,expected_revision:1,
    reason:'Supervisor verified this work in person.'}),requestKey).reason,'Supervisor verified this work in person.');
  const bank=tools.get('training_question_bank_create');
  assert.deepEqual(bank.caps,['training.author']);
  assert.equal(bank.schema.safeParse({title:'Safety',scope:'company',question:{id:'q',type:'true_false',prompt:'Safe?',answer:true}}).success,true);
  const importBank=tools.get('training_question_bank_import');
  assert.equal(importBank.path(importBank.schema.parse({id,definition_id:id})),`/api/training/question-banks/${id}/import`);
  assert.equal(importBank.schema.safeParse({id,definition_id:`${id}/../../foreign`}).success,false);
  const onboarding=tools.get('training_onboarding_policy_create');
  assert.equal(onboarding.schema.safeParse({definition_id:id,due_after_days:7}).success,true);
  assert.equal(onboarding.schema.safeParse({course_id:id,due_after_days:7}).success,false);
  assert.equal(onboarding.schema.safeParse({definition_id:id,course_id:id,due_after_days:7}).success,false);
  const onboardingCourse=tools.get('training_onboarding_course_policy_create');
  assert.equal(onboardingCourse.schema.safeParse({course_id:id,due_after_days:7}).success,true);
  assert.equal(onboardingCourse.schema.safeParse({definition_id:id,course_id:id,due_after_days:7}).success,false);
  for(const entry of tools.values())if(entry.method)assert.equal(typeof entry.schema.extend,'function');
});
