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

In-progress

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
&#x26aa; Configuration directives  
&#x26aa; Success and Fail responses  
&#x26aa; Store authenticated SQRL session  
&#x26aa; mod\_auth module for user session  
&#x26aa; Integrate with user management  

