# OpenIDP
WS-Federation, SAML11, SAML20, OAuth, ADAL IDP / SSO

![https://i.imgur.com/hSs18xQ.png](https://i.imgur.com/hSs18xQ.png)

![https://i.imgur.com/i9C99Iw.png](https://i.imgur.com/i9C99Iw.png)

## Status

This is a agentless project migrating from an F5 IrulesLX solution to a standalone IDP to support as many federation-translations as possible, keeping the code as open as possible.  

## Working Features

* SP initiated WS-Federation - MS/Windows side requires some powershell to add OpenIDP as a trusted identity provider, endpoint configuration is handled via the configuration file.

## Goals & TODO...
* Working on IDP Initiated WS-Federation, looping through RelyingPartner / Endpoints in Config to present options
* better profile page
* management GUI
* dynamic metadata generation
* ClientSide Authentication Type support / translation
* ServerSide Authentication Type Support / translation
* LDAP Provisioning
* ADAL
* WS-Trust
* oAuth
* MFA - Smartcard
* API
