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

__author_name__ = 'Matthew T Rich'
__author_email__ = 'matthew@matthewrich.com'
__author__ = '{0} <{1}>'.format(__author_name__, __author_email__)
__version__ = '2.0.0'

import urllib
import urllib2
import json

# REST API endpoints -- no trailing slash
REST_OPENAM_AUTHENTICATE = '/json/authenticate'
REST_OPENAM_SESSIONS = '/json/sessions'
REST_OPENAM_USERS = '/json/users'

# As of OpenAM 13.5 the sessions endpoint does not support resource version 2.0
# so pin all resource versions at 1.1 for now. The only supported protocol
# version is still 1.0.
REST_OPENAM_PROTOCOL_VERSION = '1.0'
REST_OPENAM_RESOURCE_VERSION = '1.1' 

DEBUG = False

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
    https://backstage.forgerock.com/docs/openam/13.5/dev-guide#sec-rest

    Example:
        >>> from openam import OpenAM
        >>> client = OpenAM('https://mydomain.com/openam')
        >>> token = client.authenticate('pepesmith', 'likesbananas')
        >>> client.validate_token(token)
        True
        >>> client.attributes(token, 'pepesmith')['uid']
        [u'pepesmith']
        >>> client.logout(token)
        >>> client.validate_token(token)
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

    def _request(self, urlpath, headers={}, data=None, querystring_params={}):
        """
        Drive urllib2. To force a POST request, supply an empty dict as data
        parameter.
        """
        url = self._get_full_url(urlpath)

        if querystring_params:
            url += '?' + '&'.join(['%s=%s' % (k, v) for k, v in
                querystring_params.items()])

        if data:
            data = urllib.urlencode(data)

        headers.update({
            "Accept-API-Version": "resource=%s, protocol=%s" % \
                    (REST_OPENAM_RESOURCE_VERSION, REST_OPENAM_PROTOCOL_VERSION)
        })

        request = urllib2.Request(url=url, data=data, headers=headers)

        try:
            if DEBUG:
                handler = urllib2.HTTPSHandler(debuglevel=1)
                opener = urllib2.build_opener(handler)
                urllib2.install_opener(opener)
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
        }

        data = self._request(REST_OPENAM_AUTHENTICATE, headers=headers, data={})

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

        data = self._request(REST_OPENAM_SESSIONS, headers=headers, data={},
                querystring_params=params)

    def validate_token(self, token):
        """
        Validate a token. Returns a dictionary. 'valid' field contains boolean
        True or False. If true, 'uid' field contains username and 'realm' field
        contains realm.
        """
        headers = {
            self._session_header_name: token,
            'Content-type': 'application/json'
        }

        params = {'_action': 'validate'}

        data = self._request(REST_OPENAM_SESSIONS, headers=headers, data={},
                querystring_params=params)

        return json.loads(data)

    def attributes(self, token, subjectid):
        """
        Read subject attributes. Returns dictionary mapping attributes (e.g.
        "givenName") to values. Note that values may be multi-valued, in which
        case the value is a list.
        """
        headers = {
            self._session_header_name: token,
            'Content-type': 'application/json'
        }
        
        url = '/'.join([REST_OPENAM_USERS, subjectid])

        data = self._request(url, headers)

        return json.loads(data)
