import asyncio
import inspect
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from livekit import rtc
from livekit.agents import AgentSession, AutoSubscribe
import worker
from control import CaptionController, agent_identity
from test_control import RUN, ROOM, Client, payload

class Publication:
    def __init__(self,sid,source=rtc.TrackSource.SOURCE_MICROPHONE,kind=rtc.TrackKind.KIND_AUDIO):
        self.sid=sid;self.source=source;self.kind=kind;self.subscribed=False
    def set_subscribed(self,value): self.subscribed=value

class Input:
    enabled=True
    def set_audio_enabled(self,value): self.enabled=value

class Session:
    all=[]
    def __init__(self): self.events={};self.input=Input();self.options=None;self.closed=False;Session.all.append(self)
    def on(self,event):
        def attach(callback): self.events[event]=callback;return callback
        return attach
    async def start(self,**options): self.options=options
    def shutdown(self,**_): self.input.enabled=False
    async def aclose(self): self.closed=True

class Room:
    def __init__(self):
        self.name=ROOM;self.events={};self.published=[];self.disconnected=False
        self.local_participant=SimpleNamespace(identity=agent_identity(RUN),send_text=self.send_text)
        self.remote_participants={
            'person-a':SimpleNamespace(identity='person-a',track_publications={'mic':Publication('mic-a'),'screen':Publication('screen-a',rtc.TrackSource.SOURCE_SCREENSHARE_AUDIO),'video':Publication('video-a',rtc.TrackSource.SOURCE_CAMERA,rtc.TrackKind.KIND_VIDEO)}),
            'person-b':SimpleNamespace(identity='person-b',track_publications={'mic':Publication('mic-b')}),
            'guest':SimpleNamespace(identity='guest',track_publications={'mic':Publication('mic-guest')})}
    def on(self,event,callback): self.events.setdefault(event,set()).add(callback)
    def off(self,event,callback): self.events.get(event,set()).discard(callback)
    async def send_text(self,content,**kwargs): self.published.append((content,kwargs))
    async def disconnect(self): self.disconnected=True

class Context:
    def __init__(self):self.room=Room();self.connect_options=None
    async def connect(self,**options):self.connect_options=options

class WorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        Session.all=[]
        self.patches=[patch.object(worker,'AgentSession',Session),patch.object(worker,'Transcriber',lambda:object())]
        for item in self.patches:item.start()
        self.ctx=Context();self.client=Client();self.adapter=worker.LiveKitAdapter(self.ctx)
        self.controller=CaptionController(self.client,self.adapter,RUN,ROOM);self.adapter.controller=self.controller
    async def asyncTearDown(self):
        self.controller.stop('test_finished');await self.adapter.close()
        for item in self.patches:item.stop()
    async def wait_published(self,count):
        for _ in range(50):
            if len(self.ctx.room.published)>=count:return
            await asyncio.sleep(0.005)
        self.fail('Expected publication did not occur')

    async def test_explicit_microphone_only_subscription_and_no_session_recording_or_output(self):
        await self.controller.renew()
        self.assertEqual(self.ctx.connect_options,{'auto_subscribe':AutoSubscribe.SUBSCRIBE_NONE})
        self.assertEqual(set(self.adapter.speakers),{'person-a','person-b'})
        a=self.ctx.room.remote_participants['person-a'].track_publications
        self.assertTrue(a['mic'].subscribed);self.assertFalse(a['screen'].subscribed);self.assertFalse(a['video'].subscribed)
        self.assertFalse(self.ctx.room.remote_participants['guest'].track_publications['mic'].subscribed)
        for session in Session.all:
            self.assertFalse(session.options['record']);self.assertFalse(session.options['session_host'])
            options=session.options['room_options']
            for key in ['video_input','text_input','audio_output','text_output']:self.assertIs(getattr(options,key),False)
            self.assertFalse(options.audio_input.pre_connect_audio)

    async def test_captions_are_targeted_with_actual_track_identity_and_stable_segment(self):
        await self.controller.renew();speaker=self.adapter.speakers['person-a']
        speaker.session.events['user_input_transcribed'](SimpleNamespace(transcript='Local test caption',is_final=False))
        speaker.session.events['user_input_transcribed'](SimpleNamespace(transcript='Local final caption',is_final=True))
        await self.wait_published(2)
        for _,options in self.ctx.room.published:
            self.assertEqual(options['destination_identities'],['person-a']);self.assertEqual(options['topic'],'lk.transcription')
            self.assertEqual(options['attributes']['wolf.participant_identity'],'person-a');self.assertEqual(options['attributes']['lk.transcribed_track_id'],'mic-a')
            self.assertEqual(options['attributes']['wolf.caption_run_id'],RUN)
        self.assertEqual(self.ctx.room.published[0][1]['attributes']['lk.segment_id'],self.ctx.room.published[1][1]['attributes']['lk.segment_id'])
        self.assertEqual(self.ctx.room.published[1][1]['attributes']['lk.transcription_final'],'true')

    async def test_consent_pause_clears_queued_text_and_all_capture_then_restarts_with_new_generation(self):
        await self.controller.renew();old=self.adapter.speakers['person-a']
        old.session.events['user_input_transcribed'](SimpleNamespace(transcript='Must be discarded',is_final=True))
        self.client.response=payload(active=False,status='consent');await self.controller.renew()
        self.assertFalse(old.session.input.enabled);self.assertTrue(old.session.closed)
        for participant in self.ctx.room.remote_participants.values():
            self.assertTrue(all(not item.subscribed for item in participant.track_publications.values()))
        await asyncio.sleep(0.02);self.assertEqual(self.ctx.room.published,[])
        self.client.response=payload();await self.controller.renew()
        old.session.events['user_input_transcribed'](SimpleNamespace(transcript='Late old transcript',is_final=True))
        current=self.adapter.speakers['person-a'];self.assertIsNot(current,old)
        current.session.events['user_input_transcribed'](SimpleNamespace(transcript='Fresh authorized caption',is_final=True))
        await self.wait_published(1);self.assertEqual(self.ctx.room.published[0][0],'Fresh authorized caption')

    async def test_expired_or_empty_recipient_lease_never_broadcasts(self):
        await self.controller.renew();speaker=self.adapter.speakers['person-a']
        self.client.response=payload(recipients=[]);await self.controller.renew()
        speaker.session.events['user_input_transcribed'](SimpleNamespace(transcript='Never broadcast',is_final=True))
        await asyncio.sleep(0.02);self.assertEqual(self.ctx.room.published,[]);self.assertTrue(self.controller.stopped.is_set())

    async def test_track_replacement_closes_old_session_and_provider_error_stops_capture(self):
        await self.controller.renew();old=self.adapter.speakers['person-a']
        self.ctx.room.remote_participants['person-a'].track_publications['mic']=Publication('replacement-mic')
        await self.adapter.reconcile();self.assertTrue(old.session.closed)
        current=self.adapter.speakers['person-a'];self.assertEqual(current.track_id,'replacement-mic')
        current.session.events['error'](SimpleNamespace(error='private provider response'))
        self.assertEqual(self.controller.failure_code,'stt_unavailable');self.assertFalse(current.session.input.enabled)

    async def test_wrong_connected_room_identity_stops_before_subscribing(self):
        self.ctx.room.local_participant.identity='forged-agent'
        await self.controller.renew();self.assertTrue(self.controller.stopped.is_set())
        self.assertEqual(self.adapter.speakers,{})

    async def test_audience_revocation_cancels_inflight_stream_then_only_new_audience_receives(self):
        await self.controller.renew()
        entered=asyncio.Event();cancelled=asyncio.Event()
        async def suspended_send(*args,**kwargs):
            entered.set()
            try:await asyncio.Future()
            except asyncio.CancelledError:cancelled.set();raise
        self.ctx.room.local_participant.send_text=suspended_send
        old=self.adapter.speakers['person-a']
        old.session.events['user_input_transcribed'](SimpleNamespace(transcript='Revoked stream',is_final=True))
        await asyncio.wait_for(entered.wait(),0.5)
        self.client.response=payload(recipients=['person-b']);await self.controller.renew()
        await asyncio.wait_for(cancelled.wait(),0.5)
        self.ctx.room.local_participant.send_text=self.ctx.room.send_text
        current=self.adapter.speakers['person-a']
        current.session.events['user_input_transcribed'](SimpleNamespace(transcript='New audience only',is_final=True))
        await self.wait_published(1)
        self.assertEqual(self.ctx.room.published[0][1]['destination_identities'],['person-b'])
        self.assertTrue(old.session.closed)

    async def test_track_event_burst_is_coalesced_and_does_not_repeat_subscriptions(self):
        await self.controller.renew()
        for _ in range(1000):self.adapter._room_changed()
        self.assertLessEqual(len(self.adapter.tasks),2)
        await asyncio.sleep(0.02)
        self.assertEqual(len(Session.all),2)

    async def test_session_start_failure_reports_sanitized_code_and_disables_tracks(self):
        with patch.object(Session,'start',side_effect=RuntimeError('provider secret and private transcript')):
            await self.controller.renew()
        self.assertEqual(self.controller.failure_code,'stt_unavailable')
        self.assertEqual(self.controller.stop_reason,'stt_unavailable')
        self.assertTrue(all(not pub.subscribed for person in self.ctx.room.remote_participants.values() for pub in person.track_publications.values()))

class InstalledSDKContractTests(unittest.TestCase):
    def test_pinned_sdk_has_required_privacy_controls_and_worker_is_named(self):
        self.assertIn('record',inspect.signature(AgentSession.start).parameters)
        self.assertIn('session_host',inspect.signature(AgentSession.start).parameters)
        self.assertIn('destination_identities',inspect.signature(rtc.LocalParticipant.send_text).parameters)
        self.assertEqual(worker.server._agent_name,'wolf-comms-captions')
        self.assertFalse(worker.server._permissions.can_publish)
        self.assertTrue(worker.server._permissions.can_publish_data)
        self.assertFalse(worker.server._permissions.hidden)

if __name__=='__main__':unittest.main()
