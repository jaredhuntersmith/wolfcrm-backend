import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {createWidgetDashboard,validateWidgetSlots} from '../widget-dashboard.js';
import {TRAINING_WIDGET_KINDS} from '../training/dashboard.js';

test('custom dashboard accepts nine training cards and uses the authenticated actor', {timeout:120000}, async()=>{
  const fixture=await createCommsFixture();
  try {
    await fixture.pool.query("ALTER TABLE companies ADD COLUMN timezone text DEFAULT 'America/New_York'");
    await installTraining({app:express(),pool:fixture.pool,authRequired:(_req,_res,next)=>next()});
    const dashboard=createWidgetDashboard({pool:fixture.pool});
    const bob=await fixture.actor('bob');
    const owner=await fixture.actor('owner');
    const slots=TRAINING_WIDGET_KINDS.map(kind=>({id:kind,kind,filters:{},offset:0}));
    assert.equal(validateWidgetSlots({slots:slots.slice(0,8)}).length,8);
    const mine=await dashboard.summary(bob,{slots:slots.slice(0,8)});
    assert.deepEqual(mine.modules.map(module=>module.kind),TRAINING_WIDGET_KINDS.slice(0,8));
    assert.equal(mine.modules[0].state,'ready');
    assert.equal(mine.modules[0].value,'0');
    assert.equal(mine.modules[3].state,'unavailable');
    assert.equal(mine.modules[3].count,undefined);
    const team=await dashboard.summary(owner,{slots:[slots[8]]});
    assert.equal(team.modules[0].state,'ready');
    assert.equal(team.modules[0].value,'0 / 0');
    await assert.rejects(
      dashboard.summary(bob,{userID:fixture.ids.foreign,slots:[slots[0]]}),
      error=>error.status===403 && error.code==='widget_account_changed'
    );
  } finally {
    await fixture.close();
  }
});
