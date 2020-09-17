# coding: utf-8
from __future__ import unicode_literals

from .gigya import GigyaBaseIE
from ..utils import (
    ExtractorError,
    urlencode_postdata,
)

class StreamzIE(GigyaBaseIE):
    IE_NAME = 'streamz.be'
    _VALID_URL = r'https?://(?:www\.)?streamz\.be/streamz/afspelen/(?P<id>[a-z0-9\-]+)'
    _APIKEY = 'auth0Client: eyJuYW1lIjoiYXV0aDAuanMiLCJ2ZXJzaW9uIjoiOS4xMy4yIn0='
    _TEST = {
        'url': 'https://yourextractor.com/watch/42',
        'md5': 'TODO: md5 sum of the first 10241 bytes of the video file (use --test)',
        'info_dict': {
            'id': '42',
            'ext': 'mp4',
            'title': 'Video title goes here',
            'thumbnail': r're:^https?://.*\.jpg$',
            # TODO more properties, either as:
            # * A value
            # * MD5 checksum; start the string with md5:
            # * A regular expression; start the string with re:
            # * Any Python type (for example int or float)
        }
    }

    def _real_initialize(self):
        self._logged_in = False

    def _login(self):
        username, password = self._get_login_info()
        if username is None:
            self.raise_login_required()

        auth_data = {
            'client_id': 'WWl9F97L9m56SrPcTmC2hYkCCKcmxevS',
            'username': username,
            'password': password,
            'realm': 'Username-Password-Authentication',
            'credential_type': 'http://auth0.com/oauth/grant-type/password-realm'
        }

        auth_info = self._download_json(
            'https://login.streamz.be/co/authenticate', None,
            note='Logging in', errnote='Unable to log in',
            data=urlencode_postdata(auth_data))

        # auth_info = self._gigya_login(auth_data)

        self._uid = auth_info['UID']
        self._uid_signature = auth_info['UIDSignature']
        self._signature_timestamp = auth_info['signatureTimestamp']

        self._logged_in = True

    def _real_extract(self, url):
        video_id = self._match_id(url)
        webpage = self._download_webpage(url, video_id)

        if not self._logged_in:
            self._login()

        # TODO more code goes here, for example ...
        title = self._html_search_regex(r'<h1>(.+?)</h1>', webpage, 'title')

        return {
            'id': video_id,
            'title': title,
            'description': self._og_search_description(webpage),
            'uploader': self._search_regex(r'<div[^>]+id="uploader"[^>]*>([^<]+)<', webpage, 'uploader', fatal=False),
            # TODO more properties (see youtube_dl/extractor/common.py)
        }