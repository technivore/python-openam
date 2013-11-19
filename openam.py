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

__author__ = 'Juan J. Brown <juanjbrown@gmail.com>'
__version__ = '0.1.5'

import urllib
import urllib2
import json

# REST API URIs
REST_OPENSSO_LOGIN = '/identity/json/authenticate'
REST_OPENSSO_LOGOUT = '/identity/logout'
REST_OPENSSO_COOKIE_NAME_FOR_TOKEN = '/identity/json/getCookieNameForToken'
REST_OPENSSO_COOKIE_NAMES_TO_FORWARD = '/identity/getCookieNamesToForward'
REST_OPENSSO_IS_TOKEN_VALID = '/identity/json/isTokenValid'
REST_OPENSSO_ATTRIBUTES = '/identity/json/attributes'


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

    def __init__(self, openam_url='',):
        """
        @param openam_url: the URL to the OpenAM server
        """
        if not openam_url:
            raise ValueError(
                'This interface needs an OpenAM URL to work!')

        self.openam_url = openam_url
        self.__token = None

    def __repr__(self):
        """So we can see what is inside!"""
        return '{0}({1})'.format(self.__class__.__name__, self.__dict__)

    def _GET(self, urlpath, params=None):
        """
        Wrapper around http_get() to save keystrokes.
        """
        if params is None:
            params = {}
        # data = GET(
        data = http_get(
            ''.join((self.openam_url, urlpath)), params
        )

        return data

    @property
    def token(self):
        return self.__token

    def authenticate(self, username, password, uri=''):
        """
        Authenticate and return a login token.
        """
        params = {'username': username, 'password': password, 'uri': uri}
        data = self._GET(REST_OPENSSO_LOGIN, params)
        if data == '':
            msg = 'Invalid Credentials for user "{0}".'.format(username)
            raise AuthenticationFailure(msg)

        self.__token = json.loads(data).get("tokenId")

        return self.token

    def logout(self, subjectid=None):
        """
        Logout by revoking the token passed. Returns nothing!
        """
        params = {'subjectid': subjectid or self.token}
        self._GET(REST_OPENSSO_LOGOUT, params)

    def is_token_valid(self, tokenid=None):
        """
        Validate a token. Returns a boolen.
        """
        params = {'tokenid': tokenid or self.token}
        data = self._GET(REST_OPENSSO_IS_TOKEN_VALID, params)

        return json.loads(data).get("boolean")

    def attributes(self, subjectid=None, attributes_names='uid', **kwargs):
        """
        Read subject attributes. Returns UserDetails object.

        The 'attributes_names' argument doesn't really seem to make a difference
        in return results, but it is included because it is part of the API.
        """
        params = {'attributes_names': attributes_names,
                  'subjectid': subjectid or self.token}
        if kwargs:
            params.update(kwargs)
        data = self._GET(REST_OPENSSO_ATTRIBUTES, params)

        token_details = json.loads(data)
        userdetails = UserDetails(token_details)

        return userdetails

    def get_cookie_name_for_token(self, tokenid=None):
        """
        Returns name of the token cookie that should be set on the client.
        """
        params = {'tokenid': tokenid or self.token}
        data = self._GET(REST_OPENSSO_COOKIE_NAME_FOR_TOKEN, params)

        return json.loads(data).get("string")

    def get_cookie_names_to_forward(self):
        """
        Returns a list of cookie names required by the server. Accepts no arguments.
        """
        data = self._GET(REST_OPENSSO_COOKIE_NAMES_TO_FORWARD)
        # => 'string=iPlanetDirectoryPro\r\nstring=amlbcookie\r\n'

        # Ditch the 'string=' crap and make into a list
        cookie_string = data.replace('string=', '')
        cookie_names = cookie_string.strip().splitlines()

        return cookie_names


class DictObject(object):

    """
    Pass it a dict and now it's an object! Great for keeping variables!
    """

    def __init__(self, data=None):
        if data is None:
            data = {}
        self.__dict__.update(data)

    def __repr__(self):
        """So we can see what is inside!"""
        return '{0}({1})'.format(self.__class__.__name__, self.__dict__)


class UserDetails(DictObject):

    """
    A dict container to make 'userdetails' keys available as attributes.
    """
    pass


def http_get(url, data):
    """
    Send a simple HTTP GET and attempt to return the response data.
    """
    params = urllib.urlencode(data)
    try:
        resp = urllib2.urlopen(url, params)
    except urllib2.HTTPError:
        return ''

    if resp.code != 200:
        # This exception could probably be more meaningful...
        raise OpenAMError('Response was not ok for {0}'.format(url))

    data = resp.read()

    return data
