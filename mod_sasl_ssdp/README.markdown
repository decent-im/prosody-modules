---
labels:
- 'Stage-Alpha'
summary: 'XEP-0474: SASL SCRAM Downgrade Protection'
...

Introduction
============

This module implements the experimental XEP-0474: SASL SCRAM Downgrade
Protection. It provides an alternative downgrade protection mechanism to
client-side pinning which is currently the most common method of downgrade
protection.

**Note:** This module implements version 0.3.0 of XEP-0474. As of 2023-12-05,
this version is not yet published on xmpp.org. Version 0.3.0 of the XEP is
implemented in Monal 6.0.1. No other clients are currently known to implement
the XEP at the time of writing.

# Configuration

There are no configuration options for this module, just load it as normal.

# Compatibility

For SASL2 (XEP-0388) clients, it is compatible with the mod_sasl2 community module.

For clients using RFC 6120 SASL, it requires Prosody trunk 33e5edbd6a4a or
later. It is not compatible with Prosody 0.12 (it will load, but simply
won't do anything) for "legacy SASL".
