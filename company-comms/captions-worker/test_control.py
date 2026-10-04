import asyncio
import copy
import json
import unittest
from control import CaptionController, CaptionStop, Config, Lease, agent_identity, run_from_metadata

RUN = '11111111-1111-4111-8111-111111111111'
CALL = '22222222-2222-4222-8222-222222222222'
ROOM = 'company-fixture-call'

def payload(**changes):
    value = dict(active=True, status='active', run_id=RUN, call_id=CALL, room_name=ROOM,
                 agent_identity=agent_identity(RUN), lease_seconds=3, remaining_seconds=120,
                 participants=[{'identity':'person-a','display_name':'A'},{'identity':'person-b','display_name':'B'}], recipients=['person-a'])
    value.update(changes)
    return value

class Clock:
    now = 100.0
    def __call__(self): return self.now

class Adapter:
    def __init__(self): self.connected=False; self.stops=0; self.reconciles=0; self.closed=False
    async def connect(self): self.connected=True
    async def reconcile(self): self.reconciles+=1
    def stop_capture(self): self.stops+=1
    async def close(self): self.closed=True

class Client:
    def __init__(self): self.response=payload(); self.failures=[]; self.calls=[]
    async def lease(self,run,worker):
        self.calls.append((run,worker))
        if isinstance(self.response,Exception): raise self.response
        return copy.deepcopy(self.response)
    async def failure(self,run,worker,code): self.failures.append(code)

class ValidationTests(unittest.TestCase):
    def test_origin_secret_and_override_are_fail_closed(self):
        good={'WOLFCRM_COMMS_API_URL':'https://api.example.invalid','COMMS_CAPTIONS_WORKER_SECRET':'x'*40}
        self.assertNotIn('x'*40,repr(Config.from_env(good)))
        for origin in ['http://api.example.invalid','https://user:password@api.example.invalid','https://api.example.invalid/redirect','https://api.example.invalid?token=x','file:///tmp/test']:
            with self.subTest(origin=origin),self.assertRaises(CaptionStop): Config.from_env({**good,'WOLFCRM_COMMS_API_URL':origin})
        with self.assertRaises(CaptionStop): Config.from_env({**good,'LIVEKIT_AGENT_NAME_OVERRIDE':''})
        with self.assertRaises(CaptionStop): Config.from_env({**good,'COMMS_CAPTIONS_WORKER_SECRET':'short'})
        local={**good,'WOLFCRM_COMMS_API_URL':'http://127.0.0.1:5000'}
        with self.assertRaises(CaptionStop): Config.from_env(local)
        self.assertEqual(Config.from_env({**local,'WOLFCRM_CAPTIONS_ALLOW_LOCAL_HTTP':'1'}).api_url,local['WOLFCRM_COMMS_API_URL'])

    def test_dispatch_contains_only_run_identifier(self):
        self.assertEqual(run_from_metadata(json.dumps({'caption_run_id':RUN})),RUN)
        for value in ['{}','[]','not-json',json.dumps({'caption_run_id':RUN,'callback_url':'https://other.invalid'}),json.dumps({'caption_run_id':'invalid'})]:
            with self.subTest(value=value),self.assertRaises(CaptionStop): run_from_metadata(value)

    def test_lease_rejects_scope_expiry_empty_and_malformed_audiences(self):
        lease=Lease.parse(payload(),run_id=RUN,room_name=ROOM,requested_at=100,now=101)
        self.assertEqual(lease.expires_at,103)
        self.assertEqual(lease.recipients,('person-a',))
        variants=[dict(active=False),dict(room_name='other-room'),dict(agent_identity='spoof'),dict(recipients=[]),dict(recipients=['outsider']),dict(participants=[{'identity':'person-a'},{'identity':'person-a'}]),dict(lease_seconds=5),dict(lease_seconds=True),dict(remaining_seconds=float('inf')),dict(recipients=['person-a','person-a']),dict(participants=[{}]),dict(participants=[{'identity':'person-a\n'}])]
        for change in variants:
            with self.subTest(change=change),self.assertRaises(CaptionStop): Lease.parse(payload(**change),run_id=RUN,room_name=ROOM,requested_at=100,now=101)
        with self.assertRaises(CaptionStop): Lease.parse(payload(),run_id=RUN,room_name=ROOM,requested_at=100,now=103)

class ControllerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.clock=Clock();self.client=Client();self.adapter=Adapter()
        self.controller=CaptionController(self.client,self.adapter,RUN,ROOM,clock=self.clock)

    async def test_no_connect_without_active_lease_and_one_worker_claim(self):
        self.client.response=payload(active=False,status='consent')
        await self.controller.renew();self.assertFalse(self.adapter.connected);self.assertIsNone(self.controller.current())
        self.client.response=payload();await self.controller.renew();await self.controller.renew()
        self.assertTrue(self.adapter.connected)
        self.assertEqual(len({worker for _,worker in self.client.calls}),1)

    async def test_consent_or_network_pause_immediately_invalidates_generation_and_resumes_only_fresh(self):
        await self.controller.renew();generation=self.controller.generation
        self.client.response=payload(active=False,status='consent');await self.controller.renew()
        self.assertIsNone(self.controller.current());self.assertGreater(self.controller.generation,generation);self.assertGreater(self.adapter.stops,0)
        self.client.response=payload();await self.controller.renew();self.assertIsNotNone(self.controller.current())
        self.client.response=TimeoutError('sensitive provider detail');await self.controller.renew()
        self.assertIsNone(self.controller.current());self.assertIsNotNone(self.controller.pause_since)

    async def test_expiry_stops_capture_while_renewal_is_unavailable_and_recovery_is_bounded(self):
        await self.controller.renew();self.clock.now=104
        guard=asyncio.create_task(self.controller._expiry_loop());await asyncio.sleep(0.01)
        self.assertIsNone(self.controller.current());self.assertGreater(self.adapter.stops,0)
        self.clock.now=135;await asyncio.wait_for(guard,0.2)
        self.assertTrue(self.controller.stopped.is_set());self.assertEqual(self.controller.failure_code,'caption_worker_failed')

    async def test_server_cannot_extend_run_limit_after_pause(self):
        await self.controller.renew();deadline=self.controller.run_deadline
        self.client.response=payload(active=False,status='consent');await self.controller.renew()
        self.clock.now+=5;self.client.response=payload(remaining_seconds=999999);await self.controller.renew()
        self.assertEqual(self.controller.run_deadline,deadline)

    async def test_terminal_stop_cannot_be_revived_by_late_response(self):
        entered=asyncio.Event();release=asyncio.Event()
        async def delayed(*_): entered.set();await release.wait();return payload()
        self.client.lease=delayed
        request=asyncio.create_task(self.controller.renew());await entered.wait()
        self.controller.stop('revoked');release.set();await request
        self.assertIsNone(self.controller.current());self.assertFalse(self.adapter.connected)

    async def test_serve_closes_and_reports_only_sanitized_failure_code(self):
        async def reconcile(): self.controller.stop('stt_unavailable','stt_unavailable')
        self.adapter.reconcile=reconcile
        await asyncio.wait_for(self.controller.serve(),0.5)
        self.assertTrue(self.adapter.closed);self.assertEqual(self.client.failures,['stt_unavailable'])

if __name__ == '__main__': unittest.main()
