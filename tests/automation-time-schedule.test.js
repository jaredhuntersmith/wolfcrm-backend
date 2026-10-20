import test from 'node:test';
import assert from 'node:assert/strict';
import {timeScheduleSchema,activationScheduleSchema,activationScheduleAllows,localScheduleInstant,dueTimeSchedule} from '../automation-time-schedule.js';
const daily={frequency:'daily',time:'19:00',timezone:'America/New_York'};
test('daily local time, company timezone, bounded catch-up and publication boundary',()=>{
 assert.equal(dueTimeSchedule(daily,'UTC',new Date('2026-10-18T23:00:29Z')).scheduled_for.toISOString(),'2026-10-18T23:00:00.000Z');
 assert.equal(dueTimeSchedule(daily,'UTC',new Date('2026-10-18T23:16:00Z')),null);
 assert.equal(dueTimeSchedule(daily,'UTC',new Date('2026-10-18T22:59:59Z')),null);
 assert.equal(dueTimeSchedule(daily,'UTC',new Date('2026-10-18T23:01:00Z'),new Date('2026-10-18T23:00:01Z')),null);
 assert.equal(dueTimeSchedule({...daily,timezone:'company'},'Asia/Kolkata',new Date('2026-10-18T13:30:00Z')).scheduled_for.toISOString(),'2026-10-18T13:30:00.000Z');
});
test('weekly and monthly select calendar dates and do not normalize short months',()=>{
 assert.equal(dueTimeSchedule({...daily,frequency:'weekly',weekdays:[1]},'UTC',new Date('2026-10-18T23:00:00Z')),null);
 assert.ok(dueTimeSchedule({...daily,frequency:'weekly',weekdays:[1]},'UTC',new Date('2026-10-19T23:00:00Z')));
 assert.equal(dueTimeSchedule({...daily,frequency:'monthly',month_day:31},'UTC',new Date('2026-04-30T23:00:00Z')),null);
 assert.ok(dueTimeSchedule({...daily,frequency:'monthly',month_day:31},'UTC',new Date('2026-03-31T23:00:00Z')));
});
test('DST missing times skip; repeated times select the first instant only',()=>{
 assert.equal(localScheduleInstant('2026-03-08','02:30','America/New_York'),null);
 assert.equal(localScheduleInstant('2026-11-01','01:30','America/New_York').toISOString(),'2026-11-01T05:30:00.000Z');
 assert.equal(dueTimeSchedule({...daily,time:'01:30'},'UTC',new Date('2026-11-01T06:30:00Z')),null);
 assert.equal(localScheduleInstant('2026-10-04','02:15','Australia/Lord_Howe'),null);
});
test('catch-up across midnight uses previous local date; invalid rules fail',()=>{
 assert.equal(dueTimeSchedule({...daily,time:'23:55',timezone:'UTC'},'UTC',new Date('2026-10-19T00:05:00Z')).date,'2026-10-18');
 for(const change of [{time:'24:00'},{timezone:'not/a-zone'},{frequency:'weekly'},{frequency:'monthly'},{missed_run_window_minutes:121}])assert.equal(timeScheduleSchema.safeParse({...daily,...change}).success,false);
});

test('activation windows enforce second boundaries and preserve open-ended once windows',()=>{
 const schedule={timezone:'UTC',windows:[{kind:'once',start_at:'2026-10-20T12:00:01Z',end_at:'2026-10-20T12:00:03Z'}]};
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-20T12:00:00.999Z')),false);
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-20T12:00:01Z')),true);
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-20T12:00:02.999Z')),true);
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-20T12:00:03Z')),false);
 assert.equal(activationScheduleAllows({timezone:'UTC',windows:[{kind:'once',end_at:'2026-10-20T12:00:03Z'}]},'UTC',new Date('2026-10-20T12:00:01Z')),true);
 assert.equal(activationScheduleSchema.safeParse({timezone:'UTC',windows:[]}).success,false);
 assert.equal(activationScheduleSchema.safeParse({timezone:'UTC',windows:[{kind:'once',start_at:'2026-10-20T12:00:03Z',end_at:'2026-10-20T12:00:01Z'}]}).success,false);
});

test('weekly windows cross midnight in local time through DST changes',()=>{
 const schedule={timezone:'America/New_York',windows:[{kind:'weekly',weekdays:[7],start_time:'23:59:58',end_time:'00:00:02'}]};
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-19T03:59:57Z')),false);
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-19T03:59:58Z')),true);
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-19T04:00:01Z')),true);
 assert.equal(activationScheduleAllows(schedule,'UTC',new Date('2026-10-19T04:00:02Z')),false);
 const repeated={timezone:'company',windows:[{kind:'weekly',weekdays:[7],start_time:'01:00:00',end_time:'02:00:00'}]};
 assert.equal(activationScheduleAllows(repeated,'America/New_York',new Date('2026-11-01T05:30:00Z')),true);
 assert.equal(activationScheduleAllows(repeated,'America/New_York',new Date('2026-11-01T06:30:00Z')),true);
});
