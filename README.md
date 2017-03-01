Python interface to OpenAM 13.5+ REST Services
-----------------------------------

This is a Python library for performing authentication and user attribute
lookup requests against the OpenAM 13.5 REST API.

For OpenAM REST API documentation please see the [OpenAM Developer's Guide](https://backstage.forgerock.com/docs/openam/13.5/dev-guide#sec-rest).

#### Example usage:

    >>> import openam
    >>> oam = openam.OpenAM('https://example.com/openam')
    >>> token = oam.authenticate(username='pepesmith', password='likesbananas')
    >>> oam.validate_token(token)['valid']
    True
    >>> attrs = oam.attributes(token, 'pepesmith')
    >>> attrs.keys()
    ['telephonenumber', 'distinguishedname', 'inetUserStatus', 'displayname', 'cn',
    'dn', 'samaccountname', 'useraccountcontrol', 'objectguid', 'userprincipalname',
    'name', 'objectclass', 'sun-fm-saml2-nameid-info', 'sn', 'mail',
    'sun-fm-saml2-nameid-infokey', 'givenname', 'employeenumber']
    >>> attrs.get('displayname')
    'Smith, Pepe'
    >>> oam.logout(token)
    >>> oam.validate_token(token)['valid']
    False
