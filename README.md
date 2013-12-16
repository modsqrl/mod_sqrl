# mod_sqrl

Apache HTTPD module for the SQRL protocol
([https://www.grc.com/sqrl/sqrl.htm](https://www.grc.com/sqrl/sqrl.htm)).
SQRL is an authentication mechanism that offers superior security and privacy
to usernames and passwords.

mod\_sqrl can be used alone, alongside another authentication module, or
as second factor authentication. The authentication page's features will,
initially, be a subset of
[mod\_auth\_form](http://httpd.apache.org/docs/2.4/mod/mod_auth_form.html).
A full mirror of mod\_auth\_form's features are planned for a future release.

## Dependencies

* libsodium ([https://github.com/jedisct1/libsodium](https://github.com/jedisct1/libsodium))
* apreq ([http://httpd.apache.org/apreq/](http://httpd.apache.org/apreq/))

## Installation

Informal notes are in _doc/dependencies.txt_.

## Configuration

### SQRL Handler

The authentication verification handler is named "sqrl".

Example:  
```
<Location /sqrl>
    SetHandler sqrl
</Location>
```

### mod\_include Directives

| Directive | Attribute | Description |
| --------- | --------- | ----------- |
| sqrl\_gen |           | Generate a new Authentication-URL |
|           | url       | Environment variable name to hold the URL. |
|           | id        | Environment variable name to hold the sqrl id. This is not the user's session id; it only identifies the authentication session. |

Example:
```HTML
<form action="/sqrl_continue" method="POST">
    <!--#sqrl_gen url="sqrl_url" id="sqrl_id" -->

    <a href="<!--#echo var='sqrl_url' -->">Authenticate with SQRL</a>
    <br/>

    <input type="hidden" name="sid" value="<!--#echo var='sqrl_id' -->"/>
    <button type="submit">Continue</button>

</form>
```

### Configuration Directives

These are all optional.

| Directive          | Type       | Default | Description |
| ------------------ | ---------- | ------- | ----------- |
| SqrlTls            | boolean    | off     | When set to "on", the Authentication-URL will have a "sqrl://" scheme which the client will convert to "https://" for the authentication request. When set to "off", the Authentication-URL will have a "qrl://" scheme which the client will convert to "http://" for the authentication request. Set to "on" if mod\_ssl is loaded and configured. |
| SqrlDomain         | string     | The hostname used by the client in the request | The domain part of the Authentication-URL. If www.example.com is serving the website but sqrl.example.com handles authentication, SqrlDomain would be set to sqrl.example.com. |
| SqrlEncryptionKey  | hex string | Randomly generated when the server starts | 32-byte encryption key used to encrypt the nut. Set this if you are concerned with encountering the situation where an unlucky client requests an Authentication-URL, the server is restarted, then the client submits its identity but the server fails to decrypt the nut and rejects the identity. |
| SqrlRealm | string     | null    | Part of the URL's path that should be included with the domain when the client calculates its keys. If you have multiple apps running under the same domain, they can have separate authentications by putting the application's name here. Example: "app\_name" would render the Authentication-URL "sqrl://www.example.com/app_name &#x7c;sqrl?nut=1234567890123456&sid=6543210987654321". SqrlRealm/SqrlPath must match the &lt;Location> that sets the "sqrl" handler. |
| SqrlPath           | string     | sqrl    | Part of the URL's path (after the realm) that maps to the SQRL authentication handler. SqrlRealm/SqrlPath must match the &lt;Location> that sets the "sqrl" handler. |

Example:
```
# Load required modules plus SSL
LoadModule ssl_module modules/mod_ssl.so
LoadModule apreq_module modules/mod_apreq2.so
LoadModule sqrl_module modules/mod_sqrl.so

<VirtualHost _default_:443>

DocumentRoot "/usr/local/apache24/htdocs"
ServerName www.example.com:443

SSLEngine on
# ... Certificate stuff ...


# mod_sqrl configuration
# (does not have to be in <VirtualHost>, it can also be in the global scope)
SqrlTls on
SqrlDomain sqrl.example.com
SqrlEncryptionKey abcdef0123456789987654321fedcbaabcdef0123456789987654321fedcbaab
SqrlRealm /myapp
SqrlPath /sqrlauth

# Authentication-URLs look like: sqrl://sqrl.example.com/myapp|sqrlauth?nut=0123456789abcdef&sid=fedcba9876543210
# Client request-URLs look like: https://sqrl.example.com/myapp/sqrlauth?nut=0123456789abcdef&sid=fedcba9876543210

<Location /myapp/sqrlauth>
    SetHandler sqrl
</Location>

</VirtualHost>

```
  

---
# Development Progress

This module is a work-in-progress. Here are the development tasks and which
ones are complete.

&#x2714; mod\_include directive  
&#x2714; Create Authentication URL  
&#x2714; Construct "nut" with validation info  
&#x2714; Encrypt nut  
&#x2714; Test client  
&#x2714; Validate signature  
&#x2714; Validate nut info  
&#x2714; Configuration directives  
&#x26aa; Success and Fail responses  
&#x26aa; Store authenticated SQRL session  
&#x26aa; mod\_auth module for user session  
&#x26aa; Integrate with user management  

