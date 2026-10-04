import json
import unittest
from unittest.mock import patch
from backend import BackendClient
from control import CaptionStop, Config


class Content:
    def __init__(self,chunks):self.chunks=chunks
    async def iter_chunked(self,_):
        for chunk in self.chunks:yield chunk

class Response:
    def __init__(self,status=200,chunks=None):self.status=status;self.content=Content(chunks or [b'{}'])
    async def __aenter__(self):return self
    async def __aexit__(self,*_):pass

class Session:
    def __init__(self):self.response=Response();self.requests=[];self.closed=False
    def post(self,*args,**kwargs):self.requests.append((args,kwargs));return self.response
    async def close(self):self.closed=True

class BackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config=Config('https://backend.example','x'*32)
        self.client=BackendClient(self.config);self.session=Session();self.client.session=self.session

    async def test_fixed_origin_no_redirects_and_only_claim_body(self):
        await self.client.lease('run','worker')
        args,kwargs=self.session.requests[0]
        self.assertEqual(args,('https://backend.example/api/comms/captions/worker/lease',))
        self.assertIs(kwargs['allow_redirects'],False)
        self.assertEqual(kwargs['json'],{'run_id':'run','worker_id':'worker'})
        self.assertEqual(kwargs['headers'],{'Authorization':'Bearer '+'x'*32})
        self.assertNotIn('x'*32,repr(self.config))

    async def test_bounded_fragmented_response_and_sanitized_invalid_json(self):
        self.session.response=Response(chunks=[b'{"active":',b'true}'])
        self.assertEqual(await self.client.lease('run','worker'),{'active':True})
        self.session.response=Response(chunks=[b'x'*4096]*9)
        with self.assertRaisesRegex(CaptionStop,'^oversized_lease_response$'):await self.client.lease('run','worker')
        self.session.response=Response(chunks=[b'private unexpected response'])
        with self.assertRaisesRegex(CaptionStop,'^invalid_lease_response$'):await self.client.lease('run','worker')

    async def test_redirect_and_auth_denial_terminal_transient_failure_recoverable(self):
        for status in [301,302,307,308,401,403,404]:
            self.session.response=Response(status)
            with self.assertRaisesRegex(CaptionStop,'^lease_denied$'):await self.client.lease('run','worker')
        for status in [429,500,502,503]:
            self.session.response=Response(status)
            with self.assertRaisesRegex(ConnectionError,'^backend_temporarily_unavailable$'):await self.client.lease('run','worker')

    async def test_failure_upload_is_limited_to_fixed_code_no_provider_response(self):
        with self.assertRaisesRegex(CaptionStop,'^invalid_failure_code$'):await self.client.failure('run','worker','private provider exception')
        self.assertEqual(self.session.requests,[])
        await self.client.failure('run','worker','stt_unavailable')
        self.assertEqual(self.session.requests[0][1]['json'],{'run_id':'run','worker_id':'worker','code':'stt_unavailable'})

    async def test_session_ignores_proxy_credentials_and_has_short_total_timeout(self):
        with patch('backend.aiohttp.ClientSession',return_value=self.session) as factory:
            async with BackendClient(self.config):pass
        options=factory.call_args.kwargs
        self.assertIs(options['trust_env'],False)
        self.assertEqual(options['timeout'].total,0.9)
        self.assertTrue(self.session.closed)

if __name__=='__main__':unittest.main()
