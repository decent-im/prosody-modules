---
labels:
- Stage-Alpha
summary: "Unified Push provider"
---

This module implements a [Unified Push](https://unifiedpush.org/) Provider
that uses XMPP to talk to a Push Distributor (e.g. [Conversations](http://codeberg.org/iNPUTmice/Conversations)).

It allows push notifications to be delivered to apps on your device over XMPP.
This means notifications can be delivered quickly and efficiently (apps don't
need to repeatedly poll for new notifications).

For a list of compatible apps, see the [UnifiedPush apps list](https://unifiedpush.org/users/apps/).

A server-independent external component is also available - see [the 'up'
project](https://codeberg.org/inputmice/up). That project also contains a
description of the protocol between the XMPP server and the client.

This module and the protocol it implements is at an experimental prototype
stage.

Note that this module is **not related** to XEP-0357 push notifications for
XMPP. It does not send push notifications to disconnected XMPP clients. For
that, see [mod_cloud_notify](https://modules.prosody.im/mod_cloud_notify).

## Configuration

| Name                          | Description                                            | Default               |
|-------------------------------|--------------------------------------------------------|-----------------------|
| unified_push_secret           | A random secret string (32+ bytes), used for auth      |                       |
| unified_push_registration_ttl | Maximum lifetime of a push registration (seconds)      | `86400` (1 day)       |

A random push secret can be generated with the command
`openssl rand -base64 32`. Changing the secret will invalidate all existing
push registrations.

This module exposes a HTTP endpoint (to receive push notifications from app
servers). For more information on configuring HTTP services in Prosody, see
[Prosody HTTP documentation](https://prosody.im/doc/http).

### Example configuration

This example creates a push notification component called
'notify.example.com'.

The 'http_host' line instructs Prosody to expose this module's HTTP services
on the 'example.com' host, which avoids needing to create/update DNS records
and HTTPS certificates if example.com is already set up.

``` {.lua}
Component "notify.example.com" "unified_push"
    unified_push_secret = "<secret string here>"
    http_host = "example.com"
```

## Compatibility

Requires Prosody trunk (not compatible with 0.12).
