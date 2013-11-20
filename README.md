Python interface to OpenAM REST Services
-----------------------------------

Code borrowed and reworked from github repositories:

 - [nsb: django-opensso](https://github.com/nsb/django-opensso)
 - [jathanism: python-opensso](https://github.com/jathanism/python-opensso)

The openam.py module provided by django-openam had a dependency upon
python-restclient which in turn had a dependency upon python-httplib2. I removed
these dependencies in favor of Python's urllib2, which is part of the Standard
Library.  Since we're just doing basic HTTP GET calls, I felt that eliminating
the external dependencies made this library as lightweight as possible.

For REST Services documentation please see [Forgerock Use OpenAM RESTful Services](https://wikis.forgerock.org/confluence/display/openam/Use+OpenAM+RESTful+Services "Use OpenAM RESTful Services")

#### Example with username and password:

    >>> import openam
    >>> oam = openam.OpenAM('https://example.com/openam')
    >>> oam.authenticate(username='pepesmith', password='likesbananas')
    PQIQ5wM5MY4Sfcy41FiSxJBxu9queZd1mTYsSDuaoREST2nP.*AAJMITACDDAEElNLABQtNTU1MDYzMjI5MjYzMTA1NTp3PQ.*
    >>> oam.is_token_valid()
    True
    >>> attrs = oam.attributes()
    >>> attrs.attributes.keys()
    ['telephonenumber', 'distinguishedname', 'inetUserStatus', 'displayname', 'cn',
    'dn', 'samaccountname', 'useraccountcontrol', 'objectguid', 'userprincipalname',
    'name', 'objectclass', 'sun-fm-saml2-nameid-info', 'sn', 'mail',
    'sun-fm-saml2-nameid-infokey', 'givenname', 'employeenumber']
    >>> attrs.attributes.get('displayname')
    'Smith, Pepe'
    >>> oam.logout()
    >>> oam.is_token_valid()
    False

#### Example with token:

    >>> import openam
    >>> oam = openam.OpenAM('https://example.com/openam')
    >>> token_cookie_name = oam.get_cookie_name_for_token()
    >>> openam_token = some_cookie_dict.get(token_cookie_name)
    >>> oam.authenticate(token=openam_token)
    >>> oam.is_token_valid()
    True
    >>> attrs = oam.attributes()
    >>> attrs.attributes.keys()
    ['telephonenumber', 'distinguishedname', 'inetUserStatus', 'displayname', 'cn',
    'dn', 'samaccountname', 'useraccountcontrol', 'objectguid', 'userprincipalname',
    'name', 'objectclass', 'sun-fm-saml2-nameid-info', 'sn', 'mail',
    'sun-fm-saml2-nameid-infokey', 'givenname', 'employeenumber']
    >>> attrs.attributes.get('displayname')
    'Smith, Pepe'
    >>> oam.logout()
    >>> oam.is_token_valid()
    False
