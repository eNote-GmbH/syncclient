import base64
from datetime import datetime, timedelta
from getpass import getpass
from hashlib import sha1, sha256
import http.client as http_client
import json
import os
from pathlib import Path
import platform
import re
import sys
import time
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import browserid
import browserid.jwt
import browserid.utils
import browserid.verifiers.local
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fxa.core import Client as FxAClient
from fxa.core import Session as FxASession
from fxa.crypto import derive_key
from fxa.errors import ClientError as FxAClientError
from fxa import _utils as fxa_utils
import requests
from requests_hawk import HawkAuth
import six

# This is a proof of concept, in python, to get some data of some collections.
# The data stays encrypted and because we don't have the keys to decrypt it
# it just stays like that for now. The goal is simply to prove that it's
# possible to get the data out of the API"""

FXA_CONF_HOST = os.getenv("FXA_CONF_HOST", "accounts.firefox.com")
FXA_CONF_URI = "https://{}/.well-known/fxa-client-configuration".format(
    FXA_CONF_HOST)
FXA_SIGNIN_URI = "https://{}/signin".format(FXA_CONF_HOST)

FXA_CLIENT_NAME = 'Python Sync Client'
FXA_CLIENT_VERSION_MAJOR = '0.9'
FXA_CLIENT_VERSION = FXA_CLIENT_VERSION_MAJOR + '.0.dev0'
FXA_USER_AGENT_DEFAULT = ('Mozilla/5.0 ({} {}; rv:{})'
                          ' Gecko/20100101 {}/{}').format(
                              platform.system(),
                              platform.machine(),
                              FXA_CLIENT_VERSION,
                              FXA_CLIENT_NAME,
                              FXA_CLIENT_VERSION_MAJOR)

FXA_USER_AGENT = os.getenv("FXA_USER_AGENT", FXA_USER_AGENT_DEFAULT)
fxa_utils.USER_AGENT_HEADER = FXA_USER_AGENT

FXA_SESSION_FILE = os.getenv("FXA_SESSION_FILE", os.path.expanduser("~")
                             + "/.pyfxa_session.json")

SYNC_SCOPE = os.getenv('FXA_SCOPE_SYNC',
                       'https://identity.mozilla.com/apps/oldsync')

BASE64_REGEXP = re.compile(
    r'^(?:[a-zA-Z0-9/\+]{3})*([a-zA-Z0-9/\+]{2}=|[a-zA-Z0-9/\+]==)?$'
    )

HTTP_TRACE = False
HTTP_TIMING = False
HTTP_DUMP_RESPONSE = False


class CustomFxAClient(FxAClient):

    def __init__(self, server_url=None):
        super(CustomFxAClient, self).__init__(server_url)

    def login(self, email, password=None, stretchpwd=None, keys=False,
              unblock_code=None, verification_method=None, reason="signin",
              **kwargs):
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "email": email,
            "authPW": derive_key(stretchpwd, "authPW").hex(),
            "reason": reason,
        }

        url = "/account/login"
        if keys:
            url += "?keys=true"

        if unblock_code:
            body["unblockCode"] = unblock_code
        if verification_method:
            body["verificationMethod"] = verification_method

        # merge the final payload...
        body = {**kwargs, **body}

        try:
            resp = self.apiclient.post(url, body)
        except FxAClientError as e:
            if e.code == 400:
                if e.errno == 120:
                    # handle changed primary email...
                    ext = {
                        'originalLoginEmail': email
                    }
                    email = e.details.get('email')
                    return self.login(email, password=password,
                                      stretchpwd=None, keys=keys,
                                      unblock_code=unblock_code,
                                      verification_method=verification_method,
                                      reason=reason,
                                      **ext)
            raise e

        # XXX TODO: somehow sanity-check the schema on this endpoint
        return FxASession(
            client=self,
            email=email,
            stretchpwd=stretchpwd,
            uid=resp["uid"],
            token=resp["sessionToken"],
            key_fetch_token=resp.get("keyFetchToken"),
            verified=resp["verified"],
            verificationMethod=resp.get("verificationMethod"),
            auth_timestamp=resp["authAt"],
        )


def enable_http_timing():
    global HTTP_TIMING
    HTTP_TIMING = True


def disable_http_timing():
    global HTTP_TIMING
    HTTP_TIMING = False


def enable_http_dump_response():
    global HTTP_DUMP_RESPONSE
    HTTP_DUMP_RESPONSE = True


def enable_http_trace():
    http_client.HTTPConnection.debuglevel = 1


FXA_CONFIG = {}


def log_req_timing(resp, method, url):
    if HTTP_TIMING:
        perf = resp.elapsed.total_seconds()
        print('{} [request-time] {:10.6f} {} {}'.format(
            datetime.utcnow().isoformat(timespec='milliseconds'), perf,
            method.upper(), url), file=sys.stderr)

    if HTTP_DUMP_RESPONSE:
        print('=== CONTENT BEGIN ===', file=sys.stderr)
        print(resp.text, file=sys.stderr)
        print('=== CONTENT END ===', file=sys.stderr)


def hook_response(resp, *args, **kwargs):
    log_req_timing(resp, resp.request.method, resp.url)


def ensure_session(session=None):
    if session is None:
        session = requests.Session()
        session.headers['User-Agent'] = FXA_USER_AGENT
        session.hooks['response'].append(hook_response)
    return session


def auto_configure(config_key, env_key):
    global FXA_CONFIG
    if FXA_CONFIG.get(config_key) is None:
        FXA_CONFIG = ensure_session().get(FXA_CONF_URI).json()

    value = FXA_CONFIG.get(config_key)
    return os.getenv(env_key, value)


def encode_header(value):
    if isinstance(value, str):
        return value
    # Python3, it must be bytes
    if sys.version_info[0] > 2:  # pragma: no cover
        return value.decode('utf-8')
    # Python2, it must be unicode
    else:  # pragma: no cover
        return value.encode('utf-8')


def get_input(message):
    return input(message)


def read_session_cache():
    session_data = None

    if os.path.exists(FXA_SESSION_FILE):
        try:
            with open(FXA_SESSION_FILE, 'r') as fp:
                session_data = json.load(fp)
        except ValueError:
            pass

    return session_data


def write_session_cache(session_data):
    if session_data.get("uid") is None:
        raise ValueError("Refuse to store session without 'uid'")

    if session_data.get("token") is None:
        raise ValueError("Refuse to store session without 'token'")

    # don't directly serialize to file - might break JSON syntax
    session_json = json.dumps(session_data)
    with open(FXA_SESSION_FILE, 'w') as fp:
        fp.write(session_json)


def update_session_cache(key, value=None):
    session_data = read_session_cache()

    if session_data is not None:
        session_data[key] = value
        write_session_cache(session_data)


def get_fxa_session(email, fxa_server_url=None, **kwargs):
    if fxa_server_url is None:
        fxa_server_url = auto_configure(
            "auth_server_base_url", "FXA_SERVER_URL"
            )
    client = CustomFxAClient(server_url=fxa_server_url)

    # replace session object to allow hooks...
    client.apiclient._session = ensure_session()

    session_data = read_session_cache()
    update_session = session_data is None
    if session_data is None:
        session_data = {}

    s_uid = session_data.get("uid")
    s_token = session_data.get("token")
    s_keys = session_data.get("keys")
    s_device_id = session_data.get("device_id")

    keyA, keyB = (None, None)

    if s_uid and s_token and s_keys:
        fxa_session = FxASession(client, None, None, s_uid, s_token)
        fxa_session.keys = (bytes.fromhex(s_keys[0]), bytes.fromhex(s_keys[1]))
        keyA, keyB = fxa_session.keys

        try:
            fxa_session.check_session_status()
        except FxAClientError:
            metrics_ctx = get_metrics_context(client, device_id=s_device_id)

            # ask for the password - never stored...
            password = getpass("Authorization expired - please enter your"
                               " password ({}): ".format(email))
            fxa_session = client.login(email, password,
                                       metricsContext=metrics_ctx)
            fxa_session.keys = (bytes.fromhex(s_keys[0]),
                                bytes.fromhex(s_keys[1]))
            session_data["uid"] = fxa_session.uid
            session_data["token"] = fxa_session.token
            session_data["device_id"] = metrics_ctx["deviceId"]
            update_session = True

        _ = fxa_session.get_email_status()
    else:
        metrics_ctx = get_metrics_context(client, device_id=s_device_id)

        # ask for the password - never stored...
        password = getpass("Please enter your password ({}): ".format(email))
        fxa_session = client.login(email, password, keys=True,
                                   metricsContext=metrics_ctx)
        session_data["uid"] = fxa_session.uid
        session_data["token"] = fxa_session.token
        session_data["device_id"] = metrics_ctx["deviceId"]
        update_session = True

    fetch_keys = keyA is None or keyB is None

    if not fxa_session.verified:
        if fxa_session.verificationMethod == 'totp-2fa':
            # ask for the verification code
            v_code = get_input("Please enter the TOTP code: ")
            if not fxa_session.totp_verify(v_code):
                raise SyncClientError("Wrong TOTP token")
        elif fxa_session.verificationMethod == 'email':
            v_link = get_input("Please paste the sign-in confirmation link"
                               " here: ")
            v_code = extract_signin_code(fxa_session, v_link)
            fxa_session.verify_email_code(v_code)
        else:
            raise SyncClientError("Login verification method not supported: %s"
                                  % (fxa_session.verificationMethod))

    if fetch_keys:
        keyA, keyB = fxa_session.fetch_keys()
        if isinstance(keyA, six.text_type):  # pragma: no cover
            keyA = keyA.encode('utf-8')
        if isinstance(keyB, six.text_type):  # pragma: no cover
            keyB = keyB.encode('utf-8')
        session_data["keys"] = (keyA.hex(), keyB.hex())
        update_session = True

    if update_session:
        write_session_cache(session_data)

    client_name = 'CLI Session, {} {}'.format(FXA_CLIENT_NAME,
                                              FXA_CLIENT_VERSION_MAJOR)
    fxa_ensure_devicename(fxa_session, client_name)

    fxa_session._config = kwargs

    return fxa_session


def get_metrics_context(client, device_id=None):
    flow_id = None
    flow_begin = None
    headers = {
        'Accept-Language': 'en-US',
        'DNT': '1'
    }
    resp = client.apiclient._session.get(FXA_SIGNIN_URI, headers=headers)
    resp.raise_for_status()
    matched = re.search(r'data-flow-id=([a-f0-9]{64})', resp.text)
    if matched is not None:
        flow_id = matched.group(1)
    if flow_id is None:
        return {}

    matched = re.search(r'data-flow-begin=([0-9]+)', resp.text)
    if matched is not None:
        flow_begin = matched.group(1)
    if flow_begin is None:
        return {}

    if device_id is None:
        device_id = uuid4().hex

    return {
        'deviceId': device_id,
        'flowId': flow_id,
        'flowBeginTime': int(flow_begin)
    }


def extract_signin_code(fxa_session, v_link):
    query_params = parse_qs(urlparse(v_link).query)
    if 'code' not in query_params or 'uid' not in query_params:
        # must be a (tracking) redirect
        r = fxa_session.apiclient._session.get(v_link, allow_redirects=False)
        v_link = r.headers['location']
        query_params = parse_qs(urlparse(v_link).query)

    return query_params['code'][0]


def create_oauth_token(fxa_session, client_id, token_ttl=60,
                       with_refresh=False, scopes=['profile', SYNC_SCOPE]):
    # ...trade an FxA session directly for an OAuth token...
    access_type = 'offline' if with_refresh else 'online'

    body = {
        'client_id': client_id,
        'grant_type': 'fxa-credentials',
        'scope': ' '.join(scopes),
        'access_type': access_type,
        'ttl': token_ttl
    }
    token_data = fxa_session.apiclient.post("/oauth/token",
                                            body,
                                            auth=fxa_session._auth)

    if token_data.get('refresh_token') is not None:
        update_session_cache('refreshTokenId', token_data.get('refresh_token'))

    return (token_data.get('access_token'), token_data.get('refresh_token'))


def destroy_oauth_token(fxa_session, client_id, token, with_refresh=False):
    body = {
        'client_id': client_id,
        'token': token,
        'token_type_hint': ('refresh_token' if with_refresh
                            else 'access_token')
    }
    fxa_session.apiclient.post("/oauth/destroy", body)


def get_sync_client(
        fxa_session, client_id, access_token, token_ttl=45, auto_renew=False,
        token_server_url=None, http_session=None, init_crypto=True
        ):
    if not http_session:
        http_session = fxa_session.apiclient._session

    # Fetch scoped-key-data to get the key generation...
    data = {'client_id': client_id, 'scope': SYNC_SCOPE}
    scoped_key_data = fxa_session.apiclient.post('/account/scoped-key-data',
                                                 data, auth=fxa_session._auth)
    scoped_key_data = scoped_key_data[SYNC_SCOPE]
    # content:
    # {
    #   'identifier': 'https://identity.mozilla.com/apps/oldsync',
    #   'keyRotationSecret': '00000000000000000000000000000000000...',
    #   'keyRotationTimestamp': <epoch-milliseconds>
    # }
    generation = scoped_key_data['keyRotationTimestamp']

    # prepare X-KeyID header (generation + hash for keyB)
    key_hash = browserid.utils.encode_bytes(
        sha256(fxa_session.keys[1]).digest()[0:16]
        )
    key_id = '{}-{}'.format(generation, key_hash)

    if init_crypto:
        kdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None,
                   info=b'identity.mozilla.com/picl/v1/oldsync',
                   backend=backend)
        sync_key_material = kdf.derive(fxa_session.keys[1])
        sync_master_keys = [sync_key_material[:32], sync_key_material[32:]]
    else:
        sync_master_keys = None

    # get sync token...
    token_client = TokenserverClient(
        oauth_token=access_token, key_id=key_id, session=http_session,
        server_url=token_server_url
        )

    # create sync client...
    return SyncClient(token_client, keys=sync_master_keys,
                      session=http_session, sync_ttl=token_ttl,
                      auto_renew=auto_renew)


def fxa_ensure_devicename(fxa_session, name):
    devices = fxa_session.apiclient.get("/account/devices",
                                        auth=fxa_session._auth)
    my_device = None

    for fxa_device in devices:
        if fxa_device['isCurrentDevice']:
            my_device = fxa_device

    if my_device is None:
        device_data = {
            'name': name
        }
        fxa_session.apiclient.post("/account/device", device_data,
                                   auth=fxa_session._auth)
    else:
        # always update the entry
        device_data = {
            'id': my_device['id'],
            'name': name
        }
        fxa_session.apiclient.post("/account/device", device_data,
                                   auth=fxa_session._auth)


class SyncClientError(Exception):
    """An error occured in SyncClient."""


class TokenserverClient(object):
    """Client for the Firefox Sync Token Server.
    """
    def __init__(self, oauth_token, key_id, server_url=None,
                 verify=None, session=None):
        self.oauth_token = oauth_token
        self.key_id = key_id
        self.server_url = server_url or auto_configure(
            "sync_tokenserver_base_url", "TOKENSERVER_URL"
            )
        self.verify = verify
        self._session = ensure_session(session)

    def get_hawk_credentials(self, duration=None):
        """Asks for new temporary token given an OAuth token"""
        headers = {
            'Authorization': 'Bearer %s' % encode_header(self.oauth_token),
            'X-KeyID': self.key_id
        }

        params = {}

        if duration is not None:
            params['duration'] = int(duration)

        url = self.server_url.rstrip('/') + '/1.0/sync/1.5'
        raw_resp = self._session.get(url, headers=headers, params=params,
                                     verify=self.verify)

        raw_resp.raise_for_status()
        data = raw_resp.json()
        data['auth_at'] = raw_resp.headers.get('X-Timestamp', time.time())
        data.setdefault('duration', duration)
        return data


class SyncClient(object):
    """Client for the Firefox Sync server.
    """

    def __init__(self, ts_client, keys=None, verify=None, session=None,
                 sync_ttl=300, auto_renew=False, skew_secs=5):

        self._token_client = ts_client
        self._sync_ttl = sync_ttl

        self._auto_renew = auto_renew
        self._skew_secs = skew_secs

        self.verify = verify
        self._session = ensure_session(session)
        self._master_keys = keys

        self.new_session()

        if keys is not None:
            crypto_keys = self.get_record(
                'crypto', 'keys', decrypt=False, ignore_errors=[404]
                )
            if crypto_keys:
                crypto_keys = self._decrypt_bso(crypto_keys, keys)
                self._crypto_keys = json.loads(crypto_keys['payload'])

    def new_session(self, sync_ttl=None):
        if sync_ttl is None:
            sync_ttl = self._sync_ttl

        now = time.time()
        credentials = self._token_client.get_hawk_credentials(sync_ttl)

        self.user_id = credentials['uid']
        self.api_endpoint = credentials['api_endpoint']
        self.auth = HawkAuth(algorithm=credentials['hashalg'],
                             id=credentials['id'],
                             key=credentials['key'],
                             always_hash_content=False)

        self._auth_at = float(credentials['auth_at'])
        self._expires_at = self._auth_at + int(credentials['duration'])

        # verify client time
        if self._auth_at > (now + self._skew_secs):
            local_skew = str(timedelta(seconds=(self._auth_at - now)))
            raise SyncClientError(
                f'Client clock skew too high: {local_skew}'
                f' ({self._skew_secs} seconds allowed)'
                )

        return credentials

    def _request(self, method, url, **kwargs):
        """Utility to request an endpoint with the correct authentication
        setup, raises on errors and returns the JSON.

        """
        now_skewed = time.time() + self._skew_secs
        if self._auto_renew and self._expires_at < now_skewed:
            self.new_session()

        full_url = ('/' + url.lstrip('/')) if url else ''
        full_url = self.api_endpoint.rstrip('/') + full_url
        kwargs.setdefault('verify', self.verify)

        ignore_errors = kwargs.pop('ignore_errors', [])
        retry_errors = kwargs.pop('retry_errors', [])
        resp = self._session.request(method, full_url, auth=self.auth,
                                     **kwargs)

        status = resp.status_code
        if status == 401 and self._auto_renew:
            self.new_session()
            kwargs['ignore_errors'] = ignore_errors
            return self._request(method, url, **kwargs)

        self.raw_resp = resp

        if status >= 300:
            if status in retry_errors:
                kwargs = {
                    **kwargs,
                    'ignore_errors': ignore_errors,
                    'retry_errors': retry_errors
                }
                return self._request(method, url, **kwargs)
            elif status not in ignore_errors:
                resp.raise_for_status()

                if status == 304:
                    http_error_msg = '%s Client Error: %s for url: %s' % (
                        status, resp.reason, resp.url
                        )
                    raise requests.exceptions.HTTPError(
                        http_error_msg, response=resp
                        )
            else:
                return None

        return resp.text

    def _decrypt_aead_sync(self, ciphertext, iv, encryption_key):
        """Utility to decrypt an encrypted BSO record.
        """
        backend = default_backend()

        # sync (still) uses AES-CBC-256
        aes = algorithms.AES(encryption_key)
        aead_sync = Cipher(aes, modes.CBC(iv), backend=backend)

        # decrypt...
        decryptor = aead_sync.decryptor()

        cleartext = decryptor.update(ciphertext)
        decryptor.finalize()

        # remove AES padding...
        unpadder = padding.PKCS7(aes.block_size).unpadder()
        cleartext = unpadder.update(cleartext)
        return (cleartext + unpadder.finalize()).decode('utf-8')

    def _as_bso(self, content):
        """
        Utility to detect whether the given data is a BSO entry and return it
        as JSON or None in case it does not comply to a BSO record or an array
        thereof.
        """
        if content is None:
            return None

        if isinstance(content, six.string_types):
            try:
                content = json.loads(content)
            except json.JSONDecodeError:
                return None

        if isinstance(content, dict):
            if 'payload' in content:
                return content
        elif isinstance(content, list):
            if len(content) > 0:
                # check first entry
                if self._as_bso(content[0]) is not None:
                    return content
            else:
                # empty array - assume yes
                return content

        return None

    def _is_encrypted_bso(self, content):
        """Utility to detect whether some data is an encrypted BSO record or
        an array thereof.
        """
        content = self._as_bso(content)

        if content is None:
            return False

        if isinstance(content, dict):
            payload = content['payload']
        elif isinstance(content, list):
            if len(content) > 0:
                payload = content[0]['payload']
            else:
                # empty array - assume no (or at least no decryption required)
                return False

        if isinstance(payload, six.string_types):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return False

        if isinstance(payload, dict):
            # only JSON object supported
            if payload.get('ciphertext') is None:
                return False
            if payload.get('IV') is None:
                return False
            if payload.get('hmac') is None:
                return False
            return True

        return False

    def _decrypt_bso(self, content, keys=None):
        """Utility to decrypt a single BSO record or a list of BSO records.
        """
        if keys is None:
            if self._crypto_keys is None:
                raise SyncClientError('No crypto keys available')

            try:
                keys = self._crypto_keys['default']
                keys = (base64.b64decode(keys[0]), base64.b64decode(keys[1]))
                return self._decrypt_bso(content, keys=keys)
            except KeyError:
                raise SyncClientError('No default crypto keys available!')

        encryption_key = keys[0]
        hmac_key = keys[1]

        if isinstance(content, six.string_types):
            content = json.loads(content)

        if isinstance(content, dict):
            payload = json.loads(content['payload'])

            enc_ciphertext = payload['ciphertext']

            # Before attempting to decrypt, verify the HMAC
            # (please note that this is done using the base64-encoded string,
            # not the bytes that encoding represents)
            authenticator = hmac.HMAC(hmac_key, hashes.SHA256(),
                                      backend=backend)
            authenticator.update(enc_ciphertext.encode('utf-8'))
            authenticator.verify(bytes.fromhex(payload['hmac']))

            enc_ciphertext = base64.b64decode(enc_ciphertext)
            enc_iv = base64.b64decode(payload['IV'])

            payload = self._decrypt_aead_sync(enc_ciphertext, enc_iv,
                                              encryption_key)

            content['payload'] = payload
        else:
            # array...
            content = [self._decrypt_bso(bso, keys=keys) for bso in content]

        return content

    def info_configuration(self, **kwargs):
        """
        Returns an object mapping configured service limits associated with the
        actual value.

        The unit of the value depends on the specific limit but usually is
        either a maximum amount (any limit ending with 'records') or a maximum
        number of Bytes (any limit ending with 'bytes')
        """
        return self._request('get', '/info/configuration', **kwargs)

    def info_collections(self, **kwargs):
        """
        Returns an object mapping collection names associated with the account
        to the last-modified time for each collection.

        The server may allow requests to this endpoint to be authenticated
        with an expired token, so that clients can check for server-side
        changes before fetching an updated token from the Token Server.
        """
        return self._request('get', '/info/collections', **kwargs)

    def info_quota(self, **kwargs):
        """
        Returns a two-item list giving the user's current usage and quota
        (in KB). The second item will be null if the server does not enforce
        quotas.

        Note that usage numbers may be approximate.
        """
        return self._request('get', '/info/quota', **kwargs)

    def get_collection_usage(self, **kwargs):
        """
        Returns an object mapping collection names associated with the account
        to the data volume used for each collection (in KB).

        Note that these results may be very expensive as it calculates more
        detailed and accurate usage information than the info_quota method.
        """
        return self._request('get', '/info/collection_usage', **kwargs)

    def get_collection_counts(self, **kwargs):
        """
        Returns an object mapping collection names associated with the
        account to the total number of items in each collection.
        """
        return self._request('get', '/info/collection_counts', **kwargs)

    def delete_all_records(self, **kwargs):
        """Deletes all records for the user."""
        return self._request('delete', '', **kwargs)

    def get_records(self, collection, full=False, ids=None, newer=None,
                    limit=None, offset=None, sort=None, decrypt=False,
                    ignore_response=False, **kwargs):
        """
        Returns a list of the BSOs contained in a collection. For example:

        >>> ["GXS58IDC_12", "GXS58IDC_13", "GXS58IDC_15"]

        By default only the BSO ids are returned, but full objects can be
        requested using the full parameter. If the collection does not exist,
        an empty list is returned.

        :param ids:
            a comma-separated list of ids. Only objects whose id is in
            this list will be returned. A maximum of 100 ids may be provided.

        :param newer:
            a timestamp. Only objects whose last-modified time is strictly
            greater than this value will be returned.

        :param full:
            any value. If provided then the response will be a list of full
            BSO objects rather than a list of ids.

        :param limit:
            a positive integer. At most that many objects will be returned.
            If more than that many objects matched the query,
            an X-Weave-Next-Offset header will be returned.

        :param offset:
            a string, as returned in the X-Weave-Next-Offset header of a
            previous request using the limit parameter.

        :param sort:
            sorts the output:
            "newest" - orders by last-modified time, largest first
            "index" - orders by the sortindex, highest weight first
            "oldest" - orders by last-modified time, oldest first

        :param decrypt:
            decrypts the output (raises an error in case crypto keys are not
            available)
        """
        params = kwargs.pop('params', {})
        if full:
            params['full'] = 1
        if ids is not None:
            params['ids'] = ','.join(map(str, ids))
        if newer is not None:
            params['newer'] = newer
        if limit is not None:
            params['limit'] = limit
        if offset is not None:
            params['offset'] = offset
        if sort is not None and sort in ('newest', 'index', 'oldest'):
            params['sort'] = sort

        parse = kwargs.pop('parse_data', True)

        data = self._request('get', '/storage/%s' % collection.lower(),
                             params=params, **kwargs)
        if ignore_response or not data:
            return None

        if parse and collection.lower() != 'crypto':
            tempdata = data.splitlines()
            data = []
            for line in tempdata:
                if decrypt and self._is_encrypted_bso(line):
                    line = json.loads(line)
                    line = self._decrypt_bso(line)
                    data.append(line)
            data = json.dumps(data)

        if decrypt and self._is_encrypted_bso(data):
            # special case for crypto collection ...
            if collection.lower() == 'crypto':
                data = self._decrypt_bso(data, keys=self._master_keys)
            else:
                data = self._decrypt_bso(data)

        if not parse and not isinstance(data, str):
            data = json.dumps(data)

        return data

    def delete_collection(self, collection, **kwargs):
        """Deletes a complete collection
        """
        return self._request('delete', '/storage/%s' % (collection.lower()),
                             **kwargs)

    def get_record(self, collection, record_id, decrypt=False, **kwargs):
        """Returns the BSO in the collection corresponding to the requested id.

        :param decrypt:
            decrypts the output (raises an error in case crypto keys are not
            available)
        """
        data = self._request('get', '/storage/%s/%s' % (collection.lower(),
                                                        record_id), **kwargs)

        if self._is_encrypted_bso(data) and decrypt:
            # special case for crypto collection ...
            if collection.lower() == 'crypto':
                data = self._decrypt_bso(data, keys=self._master_keys)
            else:
                data = self._decrypt_bso(data)

        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data)

        return data

    def delete_record(self, collection, record_id, **kwargs):
        """Deletes the BSO at the given location.
        """
        return self._request('delete', '/storage/%s/%s' % (
            collection.lower(), record_id), **kwargs)

    def put_record(self, collection, record, **kwargs):
        """
        Creates or updates a specific BSO within a collection.
        The passed record must be a python object containing new data for the
        BSO.

        If the target BSO already exists then it will be updated with the
        data from the request body. Fields that are not provided will not be
        overwritten, so it is possible to e.g. update the ttl field of a
        BSO without re-submitting its payload. Fields that are explicitly set
        to null in the request body will be set to their default value by the
        server.

        If the target BSO does not exist, then fields that are not provided in
        the python object will be set to their default value by the server.

        Successful responses will return the new last-modified time for the
        collection.

        Note that the server may impose a limit on the amount of data
        submitted for storage in a single BSO.
        """
        # XXX: Workaround until request-hawk supports the json parameter. (#17)
        if isinstance(record, six.string_types):
            record = json.loads(record)
        record = record.copy()
        record_id = record.pop('id')
        headers = {}
        if 'headers' in kwargs:
            headers = kwargs.pop('headers')

        headers['Content-Type'] = 'application/json; charset=utf-8'

        return self._request('put', '/storage/%s/%s' % (
            collection.lower(), record_id), data=json.dumps(record),
            headers=headers, **kwargs)

    def put_file(self, collection, record_id, file_name, **kwargs):
        wrap = kwargs.pop('wrap', True)

        headers = {}
        if 'headers' in kwargs:
            headers = kwargs.pop('headers')

        headers['Content-Type'] = 'application/json; charset=utf-8'

        url = '/storage/{}/{}'.format(collection.lower(), record_id)

        payload = None
        with open(file_name, "rb") as fp:
            if wrap:
                payload = base64.b64encode(fp.read())
                payload = b'{"payload":"' + payload + b'"}'
            else:
                payload = fp.read()

        return self._request(
            'put', url, data=payload, headers=headers, **kwargs
            )

    def put_files(self, collection, *args, **kwargs):
        for f in args:
            rec_id = sha1(bytes(f, 'utf-8')).hexdigest()
            try:
                data = self.put_file(collection, rec_id, f)
                result = {
                    'file': f,
                    'id': rec_id,
                    'last_modified':  json.loads(data)
                }
                print(json.dumps(result))
            except requests.exceptions.HTTPError as e:
                if e.response.status_code != 400:
                    raise e
                error = {
                    'file': f,
                    'id': rec_id,
                    'error_code': json.loads(e.response.text),
                    'see_also': 'https://mozilla-services.readthedocs.io/en/'
                                'latest/respcodes.html#respcodes'
                }
                print(json.dumps(error))
        return None

    def _read_file_as_bso(self, file_name):
        bso = None
        file_size = os.stat(file_name).st_size
        with open(file_name, 'rb') as fp:
            try:
                bso = json.load(fp)
                if not isinstance(bso, dict) or 'payload' not in bso:
                    bso = None
                elif not BASE64_REGEXP.fullmatch(bso['payload']):
                    bso['payload'] = base64.b64encode(
                        bso['payload'].encode('utf-8')
                        ).decode('utf-8')
            except Exception:
                pass
            if bso is None:
                fp.seek(0, 0)
                bso = {
                    'payload': base64.b64encode(fp.read()).decode('utf-8')
                }

        if 'id' not in bso:
            bso['id'] = sha1(file_name.encode('utf-8')).hexdigest()

        return bso, file_size

    def _batch_upload(
            self, collection, batch_id, commit, batch, batch_bytes, bso_parse,
            headers, **kwargs
            ):
        if bso_parse:
            data = json.dumps(batch)
        else:
            data = b'[' + b','.join(batch) + b']'
            batch_bytes = len(data)

        url = '/storage/{}?batch={}'.format(collection.lower(), batch_id)
        if commit:
            url += '&commit=true'

        resp = self._request(
            'post',
            url,
            data=data,
            headers={
                **headers,
                'X-Weave-Records': str(len(batch)),
                'X-Weave-Bytes': str(batch_bytes)
            },
            **kwargs
            )

        return resp

    def post_files(self, collection, *args, **kwargs):
        batch_size = kwargs.pop('batch_size', 1000)
        max_size = kwargs.pop('max_batch_bytes', 2 * 2**20)
        quiet = kwargs.pop('quiet', False)
        bso_parse = kwargs.pop('parse', True)

        headers = kwargs.pop('headers', {})

        headers['Content-Type'] = 'application/json; charset=utf-8'

        files = args
        first_path = Path(files[0])
        if len(files) == 1 and first_path.is_dir():
            files = [str(x) for x in first_path.iterdir() if x.is_file()]
            headers['X-Weave-Total-Records'] = str(len(files))
        else:
            headers['X-Weave-Total-Records'] = str(len(files))

        # initialize a batch...
        resp = self._request(
            'post', '/storage/{}?batch=true'.format(collection.lower()),
            data='[]', headers=headers, **kwargs
            )

        if not quiet:
            print(resp)

        result = json.loads(resp)
        batch_id = result['batch']
        last_modified = self.raw_resp.headers['X-Last-Modified']
        headers['X-If-Unmodified-Since'] = last_modified

        batch = []
        batch_bytes = 2
        batch_records = 0
        for f in files:
            if bso_parse:
                bso, bso_size = self._read_file_as_bso(f)
            else:
                with open(f, 'rb') as fp:
                    bso = fp.read()
                bso_size = len(bso)

            if (
                    (batch_records + 1) >= batch_size
                    or
                    (batch_bytes + bso_size) >= max_size
                    ):
                # upload a batch and reset internals...
                resp = self._batch_upload(
                    collection, batch_id, False, batch, batch_bytes, bso_parse,
                    headers, **kwargs
                    )

                if not quiet:
                    print(resp)

                if self.raw_resp.headers['X-Last-Modified'] != last_modified:
                    raise SyncClientError('Collection was modified')

                batch = []
                batch_bytes = 2
                batch_records = 0
            elif batch_records > 0:
                batch_bytes += 2

            batch_bytes += bso_size
            batch.append(bso)
            batch_records += 1

        # commit with the last batch...
        resp = self._batch_upload(
            collection, batch_id, True, batch, batch_bytes, bso_parse,
            headers, **kwargs
            )

        if not quiet:
            print(resp)

        if (
                resp
                and
                self.raw_resp.status_code == 200
                and
                'X-Last-Modified' in self.raw_resp.headers
                and
                self.raw_resp.headers['X-Last-Modified'] <= last_modified
                ):
            raise SyncClientError('Collection was not modified')

    def post_records(self, collection, records, **kwargs):
        """
        Takes a list of BSOs in the request body and iterates over them,
        effectively doing a series of individual PUTs with the same timestamp.

        Each BSO record must include an "id" field, and the corresponding BSO
        will be created or updated according to the semantics of a PUT request
        targeting that specific record.

        In particular, this means that fields not provided will not be
        overwritten on BSOs that already exist.

        Successful responses will contain a JSON object with details of
        success or failure for each BSO. It will have the following keys:

            modified: the new last-modified time for the updated items.
            success: a (possibly empty) list of ids of BSOs that were
                     successfully stored.
            failed: a (possibly empty) object whose keys are the ids of BSOs
                    that were not stored successfully, and whose values are
                    lists of strings describing possible reasons for the
                    failure.

        For example:

        {
         "modified": 1233702554.25,
         "success": ["GXS58IDC_12", "GXS58IDC_13", "GXS58IDC_15",
                     "GXS58IDC_16", "GXS58IDC_18", "GXS58IDC_19"],
         "failed": {"GXS58IDC_11": ["invalid ttl"],
                    "GXS58IDC_14": ["invalid sortindex"]}
        }

        Posted BSOs whose ids do not appear in either "success" or "failed"
        should be treated as having failed for an unspecified reason.

        Note that the server may impose a limit on the total amount of data
        included in the request, and/or may decline to process more than a
        certain number of BSOs in a single request. The default limit on the
        number of BSOs per request is 100.
        """
        pass
