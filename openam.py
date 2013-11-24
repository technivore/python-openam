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
__version__ = '1.0.0'

import urllib
import urllib2
import json
import urlparse

# REST API URIs
REST_OPENAM_LOGIN = '/identity/json/authenticate'
REST_OPENAM_LOGOUT = '/identity/logout'
REST_OPENAM_COOKIE_NAME_FOR_TOKEN = '/identity/json/getCookieNameForToken'
REST_OPENAM_COOKIE_NAMES_TO_FORWARD = '/identity/json/getCookieNamesToForward'
REST_OPENAM_IS_TOKEN_VALID = '/identity/json/isTokenValid'
REST_OPENAM_ATTRIBUTES = '/identity/json/attributes'


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

    def __init__(self, openam_url='', timeout=5):
        """
        @param openam_url: the URL to the OpenAM server
        @param timeout: HTTP requests timeout in seconds
        """
        if not openam_url:
            raise ValueError(
                'This interface needs an OpenAM URL to work!')

        self.openam_url = openam_url
        self.__timeout = timeout

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
        data = http_get(_get_full_url(self.openam_url, urlpath), params, self.__timeout
        )

        return data

    def authenticate(self, username=None, password=None, uri=''):
        """
        Authenticate and return a login token.
        """

        token = None

        if username and password:
            params = {'username': username, 'password': password, 'uri': uri}
            data = self._GET(REST_OPENAM_LOGIN, params)
            if data == '':
                msg = 'Invalid Credentials for user "{0}".'.format(username)
                raise AuthenticationFailure(msg)

            token = json.loads(data).get("tokenId")
        else:
            raise ValueError("Usename and password or a token has to provided")

        return token

    def logout(self, subjectid):
        """
        Logout by revoking the token passed. Returns nothing!
        """
        params = {'subjectid': subjectid}
        self._GET(REST_OPENAM_LOGOUT, params)

    def is_token_valid(self, tokenid):
        """
        Validate a token. Returns a boolen.
        """
        params = {'tokenid': tokenid}
        data = self._GET(REST_OPENAM_IS_TOKEN_VALID, params)

        return _get_dict_from_json(data).get("boolean") or False

    def attributes(self, subjectid, attributes_names='uid', **kwargs):
        """
        Read subject attributes. Returns UserDetails object.

        The 'attributes_names' argument doesn't really seem to make a difference
        in return results, but it is included because it is part of the API.
        """
        params = {'attributes_names': attributes_names,
                  'subjectid': subjectid}
        if kwargs:
            params.update(kwargs)
        data = self._GET(REST_OPENAM_ATTRIBUTES, params)

        token_details = _get_dict_from_json(data)

        attributes = _openam_attribute_list_to_dict(
            token_details.get('attributes'))

        if attributes:
            token_details['attributes'] = attributes

        userdetails = UserDetails(token_details)

        return userdetails

    def get_cookie_name_for_token(self, tokenid):
        """
        Returns name of the token cookie that should be set on the client.
        """
        params = {'tokenid': tokenid}
        data = self._GET(REST_OPENAM_COOKIE_NAME_FOR_TOKEN, params)

        return _get_dict_from_json(data).get("string")

    def get_cookie_names_to_forward(self):
        """
        Returns a list of cookie names required by the server. Accepts no arguments.
        """
        data = self._GET(REST_OPENAM_COOKIE_NAMES_TO_FORWARD)

        return _get_dict_from_json(data).get("string")


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

def _get_full_url(base_url, path):
    # Adding '/' at end if it doesn't have one
    processed_base_url = base_url if base_url[-1] == "/" else base_url + "/"
    # removing '/' from begining if there is one
    processed_path = path if path[0] != "/" else path[1:]

    print urlparse.urljoin(processed_base_url, processed_path)


def _set_query_parameter(url, queries):
    """
    Returns a the received URL and updates the query with the received dictionary
    """

    scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(query)

    parsed_query.update(queries)
    new_query = urllib.urlencode(parsed_query, doseq=True)

    return urlparse.urlunparse((scheme, netloc, path, params, new_query, fragment))


def _get_dict_from_json(json_data):
    """
    Wrapper for json.loads
    """

    return json.loads(json_data or '{}')


def _openam_attribute_list_to_dict(attribute_list):
    """
    This converts a list of OpenAM's attributes into a dictionary
    @param attribute_list: The list of attributes returned from the
    OpenAM's Rest JSON response
    """
    attributes = {}
    for attribute in attribute_list or []:
        attributes[attribute['name']] = attribute.get('values')

    return attributes


def http_get(url, data, timeout):
    """
    Send a simple HTTP GET and attempt to return the response data.
    """

    params = urllib.urlencode(data)
    try:
        resp = urllib2.urlopen(url, data=params, timeout=timeout)
    except urllib2.HTTPError:
        return ''

    if resp.code != 200:
        # This exception could probably be more meaningful...
        raise OpenAMError('Response was not ok for {0}'.format(url))

    data = resp.read()

    return data
