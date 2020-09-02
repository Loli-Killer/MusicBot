import aiohttp
import aiofiles
import asyncio
import base64
import logging
import time

from pathvalidate import sanitize_filename

from .exceptions import GDriveError

log = logging.getLogger(__name__)

class GDrive:
    OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token'
    API_BASE = 'https://www.googleapis.com/drive/v3/'

    def __init__(self, client_id, client_secret, refresh_token, aiosession=None, loop=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.aiosession = aiosession if aiosession else aiohttp.ClientSession()
        self.loop = loop if loop else asyncio.get_event_loop()

        self.token = None

        self.loop.run_until_complete(self.get_token())  # validate token

    async def get_info(self, uri, *args, **kwargs):
        """Get a given ID's info"""
        return await self.make_gdrive_req(self.API_BASE + 'files/{0}?fields=*'.format(uri))

    async def get_children(self, uri):
        """Get children files in a given ID"""
        return await self.make_gdrive_req(self.API_BASE + "files?q='{0}' in parents and mimeType contains 'audio'".format(uri))

    async def download_file(self, uri, *args, **kwargs):
        """Download the given ID"""
        info = await self.get_info(uri)
        name = "audio_cache\\" + sanitize_filename(info['name'])
        await self.make_gdrive_req(self.API_BASE + "files/{0}?alt=media".format(uri), download=True, name=name)
        return name

    async def make_gdrive_req(self, url, download=False, name=None):
        """Proxy method for making a GDrive req using the correct Auth headers"""
        token = await self.get_token()
        return await self.make_get(url, headers={'Authorization': 'Bearer {0}'.format(token)}, download=download, name=name)

    async def make_get(self, url, headers=None, download=False, name=None):
        """Makes a GET request and returns the results"""
        async with self.aiosession.get(url, headers=headers) as r:
            if r.status != 200:
                raise GDriveError('Issue making GET request to {0}: [{1.status}] {2}'.format(url, r, await r.text()))
            if download:
                f = await aiofiles.open(name, mode='wb')
                await f.write(await r.read())
                await f.close()
            else:
                return await r.json()

    async def make_post(self, url, payload, headers=None):
        """Makes a POST request and returns the results"""
        async with self.aiosession.post(url, data=payload, headers=headers) as r:
            if r.status != 200:
                raise GDriveError('Issue making POST request to {0}: [{1.status}] {2}'.format(url, r, await r.json()))
            return await r.json()

    async def get_token(self):
        """Gets the token or creates a new one if expired"""
        if self.token and not await self.check_token(self.token):
            return self.token['access_token']

        token = await self.request_token()
        if token is None:
            raise GDriveError('Requested a token from GDrive, did not end up getting one')
        token['expires_at'] = int(time.time()) + token['expires_in']
        self.token = token
        log.debug('Created a new access token: {0}'.format(token))
        return self.token['access_token']

    async def check_token(self, token):
        """Checks a token is valid"""
        now = int(time.time())
        return token['expires_at'] - now < 60

    async def request_token(self):
        """Obtains a token from Spotify and returns it"""
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': self.refresh_token,
            'grant_type': 'refresh_token'
        }
        r = await self.make_post(self.OAUTH_TOKEN_URL, payload=payload)
        return r
