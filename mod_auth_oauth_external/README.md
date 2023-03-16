---
summary: Authenticate against an external OAuth 2 IdP
labels:
- Stage-Alpha
---

This module provides external authentication via an external [AOuth
2](https://datatracker.ietf.org/doc/html/rfc7628) authorization server
and supports the [SASL OAUTHBEARER authentication][rfc7628]
mechanism.

# How it works

Clients retrieve tokens somehow, then show them to Prosody, which asks
the Authorization server to validate them, returning info about the user
back to Prosody.

# Configuration

`oauth_external_discovery_url`
:   Optional URL string pointing to [OAuth 2.0 Authorization Server
    Metadata](https://oauth.net/2/authorization-server-metadata/). Lets
    clients discover where they should retrieve access tokens from if
    they don't have one yet.

`oauth_external_validation_endpoint`
:   URL string. The token validation endpoint, should validate the token
    and return a JSON structure containing the username of the user
    logging in the field specified by `oauth_external_username_field`.
    Commonly the [OpenID `UserInfo`
    endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)

`oauth_external_username_field`
:   String. Default is `"preferred_username"`. Field in the JSON
    structure returned by the validation endpoint that contains the XMPP
    localpart.

# Compatibility

  Version   Status
  --------- ---------------
  trunk     works
  0.12.x    does not work
  0.11.x    does not work
