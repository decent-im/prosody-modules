---
labels:
- 'Stage-Merged'
summary: Synchronise bookmarks between Private XML, legacy PEP, and PEP
...

::: {.alert .alert-info}
**Deprecatation notice:** This module has been merged into Prosody as
[mod_bookmarks][doc:modules:mod_bookmarks]. Users of Prosody **0.12**
and later should switch to that.
:::

Introduction
------------

This module fetches users’ bookmarks from Private XML (or legacy PEP) and
pushes them to PEP on login, and then redirects any Private XML query (or
legacy PEP) to PEP.  This allows interoperability between older clients that
use [XEP-0048](https://xmpp.org/extensions/xep-0048.html) and recent clients
which use [XEP-0402](https://xmpp.org/extensions/xep-0402.html).

Configuration
-------------

Simply [enable it like most other
modules](https://prosody.im/doc/installing_modules#prosody-modules), no
further configuration is needed.

Compatibility
-------------

  ------- -----------------------------------------
  0.12    [Use the official mod_bookmarks module instead][doc:modules:mod_bookmarks]
  0.11    Works
  0.10    Does not work
  0.9     Does not work
  ------- -----------------------------------------
