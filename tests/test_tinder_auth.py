import io
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import tinder_auth as auth
import auth_codec as codec
import tinder

CATALOG = tinder.load_json(tinder.CATALOG_PATH)


def account_args(operation):
    return argparse.Namespace(operation=operation, var=['user_id=matched-user'] if operation == 'like-user' else [],
                              query=[], body_file=None, dry_run=False, execute=True, timeout=30)


def success(token='new-token', refresh='new-refresh', user='me'):
    return {'http_status': 200, 'body': {'loginResult': {
        'authToken': token, 'refreshToken': refresh, 'userId': user, 'authTokenTtl': 60000}}}


class AuthTests(unittest.TestCase):
    def test_sms_flow_carries_latest_pending_token(self):
        config = {'auth_token': 'old-token'}
        factor, values = auth.build_step('start', {'phone': '+441234567890'}, config)
        self.assertEqual((factor, values), ('phone', {'phone': '441234567890'}))
        outcome = auth.accept_response(config, {'http_status': 200, 'body': {
            'validatePhoneOtpState': {'refreshToken': 'sms-state', 'smsSent': True, 'otpLength': 6}}})
        self.assertEqual(outcome['next_step'], 'verify-sms')
        self.assertEqual(outcome['sms_delivery'], 'unconfirmed')
        factor, fields = auth.build_step('verify-sms', {'otp': '012345'}, config)
        self.assertEqual(fields['refreshToken'], 'sms-state')
        self.assertEqual(fields['otp'], '012345')
        self.assertEqual(fields['phone'], '441234567890')
        self.assertEqual(config['auth_token'], 'old-token')
        self.assertNotIn('sms-state', json.dumps(outcome))
        self.assertNotIn('+441234567890', json.dumps(outcome))

    def test_resend_preserves_phone_and_challenge_and_requires_pending_login(self):
        config={'device_id':'same-device','_login':{'state':'validatePhoneOtpState','phone':'+441234567890','refresh_token':'pending-token','app_session_id':'same-session'}}
        factor,fields=auth.build_step('resend-sms',{},config)
        self.assertEqual(factor,'phoneOtpResend')
        self.assertEqual(fields,{'phone':'441234567890','refreshToken':'pending-token'})
        self.assertEqual(config['device_id'],'same-device')
        self.assertEqual(config['_login']['app_session_id'],'same-session')
        with self.assertRaises(auth.AuthError):
            auth.build_step('resend-sms',{}, {})
        config['_login']={'state':'validateExistingPhoneState','refresh_token':'pending-token'}
        self.assertEqual(auth.build_step('resend-sms',{},config),('existingPhoneOtpResend',{'refreshToken':'pending-token'}))

    def test_email_flow_uses_new_challenge_and_no_marketing_consent(self):
        config = {'_login': {'state': 'validatePhoneOtpState', 'phone': '+441234567890'}}
        outcome = auth.accept_response(config, {'http_status': 200, 'body': {'getEmailState': {'refreshToken': 'email-state'}}})
        self.assertEqual(outcome['next_step'], 'email')
        factor, values = auth.build_step('email', {'email': 'person@example.test'}, config)
        self.assertNotIn('marketingOptIn', values)
        auth.accept_response(config, {'http_status': 200, 'body': {'validateEmailOtpState': {'refreshToken': 'email-otp-state'}}})
        factor, values = auth.build_step('verify-email', {'otp': '123456'}, config)
        self.assertEqual(values['refreshToken'], 'email-otp-state')
        self.assertEqual(values['email'], 'person@example.test')

    def test_rotation_expiry_is_milliseconds(self):
        config = {'auth_token': 'old', 'refresh_token': 'old-refresh', '_login': {'state': 'x'}}
        result = auth.accept_response(config, success(), now=1000)
        self.assertTrue(result['authenticated'])
        self.assertEqual(config['auth_token_expires_at'], 1060)
        self.assertEqual(config['refresh_token'], 'new-refresh')
        self.assertNotIn('_login', config)
        self.assertNotIn('new-token', json.dumps(result))
        self.assertNotIn('new-refresh', json.dumps(result))

    def test_wrong_account_and_challenge_preserve_old_credentials(self):
        for response in (success(user='other'), {'http_status': 200, 'body': {'captchaState': {'referenceToken': 'secret'}}}):
            config = {'user_id': 'me', 'auth_token': 'old', 'refresh_token': 'old-refresh'}
            result = auth.accept_response(config, response)
            self.assertFalse(result['ok'])
            self.assertEqual(config['auth_token'], 'old')
            self.assertEqual(config['refresh_token'], 'old-refresh')
            self.assertNotIn('secret', json.dumps(result))

    def test_unknown_and_magic_link_states_stop(self):
        for body in ({'_unknownFields': [90]}, {'validateEmailMagicLinkOtpState': {}}, {'onboardingState': {'onboardingToken': 'secret'}}):
            result = auth.accept_response({}, {'http_status': 200, 'body': body})
            self.assertFalse(result['ok'])
            self.assertNotIn('secret', json.dumps(result))

    def test_captcha_preserves_rotated_credentials_but_blocks_use(self):
        config={'auth_token':'old','refresh_token':'old-refresh'}
        response=success()
        response['body']['loginResult']['captcha']=1
        result=auth.accept_response(config,response,now=100)
        self.assertFalse(result['ok'])
        self.assertEqual(config['refresh_token'],'new-refresh')
        self.assertTrue(config['auth_requires_action'])
        self.assertEqual(config['auth_token_expires_at'],160)

    def test_challenge_keeps_session_identity(self):
        config={}
        auth.prepare_session(config)
        first=auth.headers_for(config)
        auth.accept_response(config,{'http_status':200,'body':{'getEmailState':{'refreshToken':'new'}}})
        auth.prepare_session(config)
        second=auth.headers_for(config)
        for name in ('persistent-device-id','funnel-session-id','app-session-id'):
            self.assertEqual(first[name],second[name])

    def test_invalid_steps_do_not_request_network(self):
        with self.assertRaises(auth.AuthError):
            auth.build_step('verify-sms', {'otp': '123456'}, {})
        with self.assertRaises(auth.AuthError):
            auth.build_step('refresh', {}, {})

    def test_refresh_once_and_atomic_private_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'auth.json'
            auth.save_config(path, {'auth_token': 'old', 'refresh_token': 'old-refresh', 'auth_token_expires_at': 1, 'user_id': 'me'})
            calls=[]
            def transport(config, factor, values):
                calls.append((factor,values))
                return success()
            with patch.dict(os.environ, {}, clear=True):
                result, config = auth.ensure_session(path=path, transport=transport)
                self.assertTrue(result['renewed'])
                self.assertEqual(len(calls),1)
                self.assertEqual(calls[0], ('refreshAuth', {'refreshToken': 'old-refresh'}))
                result, config = auth.ensure_session(path=path, transport=transport)
                self.assertFalse(result['renewed'])
                self.assertEqual(len(calls),1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(auth.read_config(path)['refresh_token'], 'new-refresh')

    def test_refresh_failure_blocks_repeated_automatic_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'auth.json'
            auth.save_config(path, {'auth_token':'old','refresh_token':'saved','auth_token_expires_at':1})
            calls=[]
            def transport(*args):
                calls.append(args)
                return {'http_status':None,'transport_error':'Login request did not complete; outcome unknown. No retry was attempted.'}
            with patch.dict(os.environ, {}, clear=True):
                for _ in range(2):
                    result,_=auth.ensure_session(path=path,transport=transport)
                    self.assertFalse(result['ok'])
            self.assertEqual(len(calls),1)
            self.assertEqual(auth.read_config(path)['refresh_token'],'saved')

    def test_explicit_ambiguous_refresh_marks_action_and_preserves_old_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'auth.json'
            auth.save_config(path, {'auth_token': 'old-token', 'refresh_token': 'saved-refresh', 'user_id': 'me'})
            calls = []
            def transport(config, factor, values):
                calls.append((factor, values))
                return {'http_status': None,
                        'transport_error': 'Login request did not complete; outcome unknown. No retry was attempted.'}
            with patch.dict(os.environ, {}, clear=True):
                result = auth.run_step('refresh', {}, True, path, transport)
            persisted = auth.read_config(path)
            self.assertFalse(result['ok'])
            self.assertEqual(result['outcome'], 'unknown')
            self.assertTrue(persisted['auth_requires_action'])
            self.assertEqual(persisted['refresh_token'], 'saved-refresh')
            self.assertEqual(persisted['auth_token'], 'old-token')
            self.assertEqual(calls, [('refreshAuth', {'refreshToken': 'saved-refresh'})])
            self.assertNotIn('saved-refresh', json.dumps(result))

    def test_dry_run_never_calls_transport_or_saves_phone(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'auth.json'
            result=auth.run_step('start',{'phone':'+441234567890'},False,path,lambda *args: self.fail('network'))
            self.assertTrue(result['preview'])
            self.assertFalse(path.exists())
            self.assertNotIn('+441234567890',json.dumps(result))

    def test_transport_is_protobuf_and_no_redirects(self):
        class Response(io.BytesIO):
            code=200
            headers={}
        class Opener:
            def open(self,request,timeout):
                self.request=request
                return Response(codec._encode_message('AuthGatewayResponse', success()['body']))
        opener=Opener()
        result=auth.gateway({'device_id':'device'},'refreshAuth',{'refreshToken':'saved'},opener=opener)
        self.assertEqual(result['body']['loginResult']['authToken'],'new-token')
        self.assertEqual(opener.request.data,bytes.fromhex('52070a057361766564'))
        self.assertEqual(opener.request.get_header('Content-type'),'application/x-protobuf')
        self.assertIsNone(auth.NoRedirects().redirect_request(None,None,302,'',{},'https://example.test'))


class AutomaticRenewalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_refresh_credential_can_restore_missing_api_token(self):
        config = {'refresh_token': 'saved-refresh'}
        calls = []
        def renew(**kwargs):
            calls.append('renew')
            return {'ok': True, 'renewed': True}, {**config, 'auth_token': 'restored-token'}
        def transport(entry, url, headers, body, timeout):
            calls.append(headers['X-Auth-Token'])
            return {'ok': True, 'status': 200}
        result = tinder.execute_request(CATALOG, account_args('profile'), config, transport, renew)
        self.assertTrue(result['ok'])
        self.assertEqual(calls, ['renew', 'restored-token'])

    def test_expired_session_renews_before_post(self):
        config = {'auth_token': 'expired-token', 'refresh_token': 'saved-refresh', 'auth_token_expires_at': 1}
        events = []
        def renew(**kwargs):
            events.append(('renew', kwargs))
            return {'ok': True, 'renewed': True}, {**config, 'auth_token': 'new-token', 'refresh_token': 'new-refresh'}
        def transport(entry, url, headers, body, timeout):
            events.append(('request', entry['method'], headers['X-Auth-Token']))
            self.assertEqual(timeout, 30)
            return {'ok': True, 'status': 200, 'data': {'accepted': True}}
        result = tinder.execute_request(CATALOG, account_args('like-user'), config, transport, renew)
        self.assertTrue(result['ok'])
        self.assertEqual(events, [('renew', {}), ('request', 'POST', 'new-token')])
        self.assertEqual(config['refresh_token'], 'new-refresh')

    def test_rejected_get_renews_and_repeats_only_once(self):
        for second_status in (200, 401):
            with self.subTest(second_status=second_status):
                config = {'auth_token': 'old-token', 'refresh_token': 'saved-refresh'}
                renewals, requests = [], []
                def renew(**kwargs):
                    renewals.append(kwargs)
                    if kwargs.get('force'):
                        return {'ok': True, 'renewed': True}, {**config, 'auth_token': 'new-token'}
                    return {'ok': True, 'renewed': False}, dict(config)
                def transport(entry, url, headers, body, timeout):
                    requests.append((entry['method'], headers['X-Auth-Token']))
                    status = 401 if len(requests) == 1 else second_status
                    return {'ok': status == 200, 'status': status}
                result = tinder.execute_request(CATALOG, account_args('profile'), config, transport, renew)
                self.assertEqual(requests, [('GET', 'old-token'), ('GET', 'new-token')])
                self.assertEqual(renewals, [{}, {'force': True, 'prior_token': 'old-token'}])
                self.assertTrue(result['session_renewed'])
                self.assertEqual(result['status'], second_status)
                self.assertEqual(result['ok'], second_status == 200)

    def test_rejected_post_renews_without_repeating_mutation(self):
        config = {'auth_token': 'old-token', 'refresh_token': 'saved-refresh'}
        renewals, requests = [], []
        def renew(**kwargs):
            renewals.append(kwargs)
            if kwargs.get('force'):
                return {'ok': True, 'renewed': True}, {**config, 'auth_token': 'new-token'}
            return {'ok': True, 'renewed': False}, dict(config)
        def transport(entry, url, headers, body, timeout):
            requests.append((entry['method'], headers['X-Auth-Token']))
            return {'ok': False, 'status': 401}
        result = tinder.execute_request(CATALOG, account_args('like-user'), config, transport, renew)
        self.assertEqual(requests, [('POST', 'old-token')])
        self.assertEqual(renewals, [{}, {'force': True, 'prior_token': 'old-token'}])
        self.assertFalse(result['ok'])
        self.assertTrue(result['session_renewed'])
        self.assertTrue(result['retry_needed'])
        self.assertEqual(config['auth_token'], 'new-token')

    def test_403_does_not_force_renewal(self):
        config = {'auth_token': 'current-token', 'refresh_token': 'saved-refresh'}
        renewals, requests = [], []
        def renew(**kwargs):
            renewals.append(kwargs)
            return {'ok': True, 'renewed': False}, dict(config)
        def transport(entry, url, headers, body, timeout):
            requests.append(entry['method'])
            return {'ok': False, 'status': 403}
        result = tinder.execute_request(CATALOG, account_args('profile'), config, transport, renew)
        self.assertEqual(renewals, [{}])
        self.assertEqual(requests, ['GET'])
        self.assertEqual(result['status'], 403)
        self.assertNotIn('session_renewed', result)

    def test_failed_initial_renewal_sends_no_account_action(self):
        config = {'auth_token': 'expired-token', 'refresh_token': 'saved-refresh', 'auth_token_expires_at': 1}
        renewals = []
        def renew(**kwargs):
            renewals.append(kwargs)
            return {'ok': False, 'requires_action': True}, dict(config)
        def transport(*args):
            self.fail('Account action must not be sent after renewal failure')
        result = tinder.execute_request(CATALOG, account_args('like-user'), config, transport, renew)
        self.assertFalse(result['ok'])
        self.assertEqual(renewals, [{}])
        self.assertFalse(result['session']['ok'])

    def test_failed_forced_renewal_does_not_repeat_rejected_get(self):
        config = {'auth_token': 'old-token', 'refresh_token': 'saved-refresh'}
        renewals, requests = [], []
        def renew(**kwargs):
            renewals.append(kwargs)
            return {'ok': not kwargs.get('force', False), 'renewed': False}, dict(config)
        def transport(entry, url, headers, body, timeout):
            requests.append(entry['method'])
            return {'ok': False, 'status': 401}
        result = tinder.execute_request(CATALOG, account_args('profile'), config, transport, renew)
        self.assertEqual(requests, ['GET'])
        self.assertEqual(renewals, [{}, {'force': True, 'prior_token': 'old-token'}])
        self.assertFalse(result['ok'])
        self.assertFalse(result['session']['ok'])

    def test_session_already_renewed_does_not_renew_again_after_401(self):
        config = {'auth_token': 'expired-token', 'refresh_token': 'saved-refresh', 'auth_token_expires_at': 1}
        renewals, requests = [], []
        def renew(**kwargs):
            renewals.append(kwargs)
            return {'ok': True, 'renewed': True}, {**config, 'auth_token': 'new-token'}
        def transport(entry, url, headers, body, timeout):
            requests.append(headers['X-Auth-Token'])
            return {'ok': False, 'status': 401}
        result = tinder.execute_request(CATALOG, account_args('profile'), config, transport, renew)
        self.assertEqual(renewals, [{}])
        self.assertEqual(requests, ['new-token'])
        self.assertEqual(result['status'], 401)


if __name__=='__main__':
    unittest.main()
