import test from 'node:test';
import assert from 'node:assert/strict';
import { PERMISSION_PRESETS, resolveAccess } from '../permissions.js';
import { validatePermissionWindows } from '../permission-windows.js';

test('new destructive/account and training administration require an explicit grant even for existing Admins',()=>{
  const protectedKeys=['team.manage_accounts','team.purge_private','storage.view_usage','storage.cleanup_company','training.author','training.publish','training.assign','training.review','training.override','training.analytics','training.certificates','training.providers'];
  for(const preset of PERMISSION_PRESETS){
    const access=resolveAccess({preset:preset.id});
    assert.equal(access.capabilities['training.view_self'],true,preset.id);
    for(const key of protectedKeys)assert.equal(access.capabilities[key],false,`${preset.id}: ${key}`);
  }
  const owner=resolveAccess({isOwner:true});
  for(const key of protectedKeys)assert.equal(owner.capabilities[key],true,key);
  const reviewer=resolveAccess({preset:'admin',overrides:{'training.review':true}});
  assert.equal(reviewer.capabilities['training.review'],true);
  assert.equal(reviewer.capabilities['training.override'],false);
  assert.equal(reviewer.capabilities['team.manage_accounts'],false);
});

test('windows constrain grants and their dependent actions with server time and company timezone',()=>{
  const permissionWindows=validatePermissionWindows({'training.view_self':{days:[1],start:'09:00',end:'17:00'}},new Set(['training.view_self']));
  const input={preset:'admin',overrides:{'training.review':true},permissionWindows,timeZone:'America/New_York'};
  assert.equal(resolveAccess({...input,now:new Date('2026-10-19T13:00:00Z')}).capabilities['training.review'],true);
  assert.equal(resolveAccess({...input,now:new Date('2026-10-19T21:00:00Z')}).capabilities['training.review'],false);
  assert.equal(resolveAccess({...input,now:new Date('2026-10-19T13:00:00Z')}).capabilities['training.author'],false);
  assert.equal(resolveAccess({...input,timeZone:'invalid'}).capabilities['training.review'],false);
  assert.throws(()=>validatePermissionWindows({'made.up':{days:[1],start:'09:00',end:'17:00'}},new Set(['training.view_self'])));
});
