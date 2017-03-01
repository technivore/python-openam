# -*- coding: utf-8 -*-

# Python interface to OpenAM REST API
#
# Code borrowed and reworked from django-openam by nsb
# https://github.com/nsb/django-opensso
#
# For detailed usage information please see "The OpenAM REST Interface in
# Black/White"
# https://wikis.forgerock.org/confluence/display/openam/Use+OpenAM+RESTful+Services
#
# this project has been copied from https://github.com/jathanism/python-opensso

__author_name__ = 'Juan J. Brown'
__author_email__ = 'juanjbrown@gmail.com'
__author__ = '{0} <{1}>'.format(__author_name__, __author_email__)
__version__ = '1.1.0'

import urllib
import urllib2
import json
import urlparse

# REST API URIs
REST_OPENAM_AUTHENTICATE = '/json/authenticate'
REST_OPENAM_SESSIONS = '/json/sessions'

REST_OPENAM_PROTOCOL_VERSION = '1.0'
REST_OPENAM_RESOURCE_VERSION = '2.0'

# Exports
__all__ = ('OpenAM', 'OpenAMError', 'UserDetails',)


# Exceptions
class OpenAMError(Exception):
    pass


class AuthenticationFailure(OpenAMError):
    pass


# Classes
class OpenAM(object):

    """
    OpenAM Rest Interface
    https://wikis.forgerock.org/confluence/display/openam/Use+OpenAM+RESTful+Services

    Based on django-openam
    https://github.com/jathanism/django-opensso

    Example:
        >>> from openam import OpenAM
        >>> rest = OpenAM('https://mydomain.com/openam')
        >>> token = rest.authenticate('pepesmith', 'likesbananas')
        >>> rest.is_token_valid(token)
        True
        >>> rest.attributes(token).attributes['name']
        'pepesmith'
        >>> rest.logout(token)
        >>> rest.is_token_valid(token)
        False
    """

    def __init__(self, openam_url, timeout=5,
            session_header_name='iPlanetDirectoryPro'):
        """
        @param openam_url: the URL to the OpenAM server
        @param timeout: HTTP requests timeout in seconds
        """
        self.openam_url = openam_url
        self._timeout = timeout
        self._session_header_name = session_header_name

    def __repr__(self):
        """So we can see what is inside!"""
        return '{0}({1})'.format(self.__class__.__name__, self.__dict__)


    def _get_full_url(self, path):
        base_url = self.openam_url
        
        if not base_url.endswith('/'):
            base_url += '/'

        if path[0] == '/':
            path = path[1:]

        if path[-1] == '/':
            path = path[:-1]

        return base_url + path

    def _request(self, urlpath, headers={}, params={}, querystring_params={}):
        """
        Drive urllib2. Note that request method will be POST because we are
        always supplying a data parameter.
        """
        url = self._get_full_url(urlpath)

        if querystring_params:
            url += '?' + '&'.join(['%s=%s' % (k, v) for k, v in
                querystring_params.items()])

        data = urllib.urlencode(params)

        request = urllib2.Request(url=url, data=data, headers=headers)

        try:
            resp = urllib2.urlopen(request, timeout=self._timeout)
        except urllib2.HTTPError as exc:
            raise OpenAMError('HTTP Error: %s' % (exc,))

        if resp.code != 200:
            raise OpenAMError('Invalid response code %s for %s' % (resp.code, url))

        return resp.read()

    def authenticate(self, username, password):
        """
        Authenticate and return a login token.
        """
        headers = {
            'X-OpenAM-Username': username,
            'X-OpenAM-Password': password,
            "Accept-API-Version": "resource=%s, protocol=%s" % \
                    (REST_OPENAM_RESOURCE_VERSION, REST_OPENAM_PROTOCOL_VERSION)
        }

        data = self._request(REST_OPENAM_AUTHENTICATE, headers)

        if not data:
            msg = 'Invalid Credentials for user "%s".' % (username,)
            raise AuthenticationFailure(msg)

        token = json.loads(data).get("tokenId")

        return token

    def logout(self, token):
        """
        Logout by revoking the token passed. No return value.
        """
        headers = {
            self._session_header_name: token,
            'Accept': '*/*',
            'Content-type': 'application/json'
        }

        params = {'_action': 'logout'}

        data = self._request(REST_OPENAM_SESSIONS, headers,
                querystring_params=params)

    def validate_token(self, token):
        """
        Validate a token. Returns a dictionary. 'valid' field contains boolean
        True or False. If true, 'uid' field contains username and 'realm' field
        contains realm.
        """
        headers = {
            self._session_header_name: token,
            'Accept': '*/*',
            'Content-type': 'application/json'
        }

        params = {'_action': 'validate'}

        data = self._request(REST_OPENAM_SESSIONS, headers,
                querystring_params=params)

        return json.loads(data)

    def attributes(self, subjectid, attributes_names='uid', **kwargs):
        """
        Read subject attributes. Returns UserDetails object.

        The 'attributes_names' argument doesn't really seem to make a difference
        in return results, but it is included because it is part of the API.
        """
        pass

