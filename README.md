# OpenIDP
WS-Federation, SAML11, SAML20 IDP / SSO

![https://i.imgur.com/hSs18xQ.png](https://i.imgur.com/hSs18xQ.png)

![https://i.imgur.com/i9C99Iw.png](https://i.imgur.com/i9C99Iw.png)

## Status

This is a agentless project migrating from an F5 IrulesLX solution to a standalone IDP to support as many federation-translations as possible, keeping the code as open as possible.  

## Working Features

* SP initiated WS-Federation - MS/Windows side requires some powershell to add OpenIDP as a trusted identity provider, endpoint configuration is handled via the configuration file.

## Goals & TODO...
* better profile page
* management GUI - Pull EndPoint / Relying Partner Apps from Config
* dynamic metadata generation
* ClientSide Authentication Type support / translation
* ServerSide Authentication Type Support / translation
* LDAP Provisioning
* WS-Trust
* oAuth
* MFA - Smartcard
* API
