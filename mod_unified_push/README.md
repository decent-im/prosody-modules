---
labels:
- Stage-Alpha
summary: "Unified Push provider"
---

This module implements a [Unified Push](https://unifiedpush.org/) Provider
that uses XMPP to talk to a Push Distributor (e.g. [Conversations](http://codeberg.org/iNPUTmice/Conversations)).

For a server-independent external component, or details about the protocol,
see [the 'up' project](https://codeberg.org/inputmice/up).

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

## Compatibility

Requires Prosody trunk (not compatible with 0.12).
