---
labels:
- Stage-Alpha
summary: 'OAuth2 API'
rockspec:
  build:
    copy_directories:
    - html
...

## Introduction

This module implements an [OAuth2](https://oauth.net/2/)/[OpenID Connect
(OIDC)](https://openid.net/connect/) provider HTTP frontend on top of
Prosody's usual internal authentication backend.

OAuth and OIDC are web standards that allow you to provide clients and
third-party applications limited access to your account, without sharing your
password with them.

With this module deployed, software that supports OAuth can obtain "access
tokens" from Prosody which can then be used to connect to XMPP accounts using
the 'OAUTHBEARER' SASL mechanism or via non-XMPP interfaces such as [mod_rest].

Although this module has been around for some time, it has recently been
significantly extended and largely rewritten to support OAuth/OIDC more fully.

As of April 2023, it should be considered **alpha** stage. It works, we have
tested it, but it has not yet seen wider review, testing and deployment. At
this stage we recommend it for experimental and test deployments only. For
specific information, see the [deployment notes section](#deployment-notes)
below.

Known client implementations:

-   [example shell script for mod_rest](https://hg.prosody.im/prosody-modules/file/tip/mod_rest/example/rest.sh)
-   *(we need you!)*

Support for OAUTHBEARER has been added to the Lua XMPP library, [verse](https://code.matthewwild.co.uk/verse).
If you know of additional implementations, or are motivated to work on one,
please let us know! We'd be happy to help (e.g. by providing a test server).

## Standards support

Notable supported standards:

- [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7628: A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth](https://www.rfc-editor.org/rfc/rfc7628)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) & [RFC 7591: OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

## Configuration

### Interface

The module presents a web page to users to allow them to authenticate when
a client requests access. Built-in pages are provided, but you may also theme
or entirely override them.

This module honours the 'site_name' configuration option that is also used by
a number of other modules:

```lua
site_name = "My XMPP Server"
```

To provide custom templates, specify the path to the template directory:

```lua
oauth2_template_path = "/etc/prosody/custom-oauth2-templates"
```

Some templates support additional variables, that can be provided by the
'oauth2_template_style' option:

```lua
oauth2_template_style = {
  background_colour = "#ffffff";
}
```

### Token parameters

The following options configure the lifetime of tokens issued by the module.
The defaults are recommended.

```lua
oauth2_access_token_ttl = 86400 -- 24 hours
oauth2_refresh_token_ttl = nil -- unlimited unless revoked by the user
```

### Dynamic client registration

To allow users to connect any compatible software, you should enable dynamic
client registration.

Dynamic client registration can be enabled by configuring a JWT key. Algorithm
defaults to *HS256*.

```lua
oauth2_registration_key = "securely generated JWT key here"
oauth2_registration_algorithm = "HS256"
oauth2_registration_options = { default_ttl = 60 * 60 * 24 * 90 }
```

### Supported flows

Various flows can be disabled and enabled with
`allowed_oauth2_grant_types` and `allowed_oauth2_response_types`:

```lua
allowed_oauth2_grant_types = {
	"authorization_code"; -- authorization code grant
	"password"; -- resource owner password grant
}

allowed_oauth2_response_types = {
	"code"; -- authorization code flow
    -- "token"; -- implicit flow disabled by default
}
```

## Deployment notes

### Access management

This module does not provide an interface for users to manage what they have
granted access to their account! (e.g. to view and revoke clients they have
previously authorized). It is recommended to join this module with
mod_client_management to provide such access. However, at the time of writing,
no XMPP clients currently support the protocol used by that module. We plan to
work on additional interfaces in the future.

### Scopes

OAuth supports "scopes" as a way to grant clients limited access.

There are currently no standard scopes defined for XMPP. This is something
that we intend to change, e.g. by definitions provided in a future XEP. This
means that clients you authorize currently have unrestricted access to your
account (including the ability to change your password and lock you out!). So,
for now, while using OAuth clients can prevent leaking your password to them,
it is not currently suitable for connecting untrusted clients to your account.

## Compatibility

Requires Prosody trunk (April 2023), **not** compatible with Prosody 0.12 or
earlier.
