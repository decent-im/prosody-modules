---
labels:
- 'Stage-Alpha'
summary: 'Support for encrypted payloads in push notifications'
rockspec:
  dependencies:
  - mod_cloud_notify
...

Introduction
============

This module implements support for a [Encrypted Push Notifications](https://xeps.tigase.net//docs/push-notifications/encrypt/),
a custom extension to [XEP-0357: Push Notifications](https://xmpp.org/extensions/xep-0357.html).

It is planned that this will evolve to a XEP in the near future.

Details
=======

Add to modules_enabled, there are no configuration options.

Depends on
[luaossl](http://25thandclement.com/~william/projects/luaossl.html)
which is available in Debian as
[`lua-luaossl`](https://tracker.debian.org/pkg/lua-luaossl) or via
`luarocks install luaossl`.

Compatibility
=============

Not tested, but hopefully works on 0.11.x and later.
