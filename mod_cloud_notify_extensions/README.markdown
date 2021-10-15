---
summary: "Tigase custom push extensions for iOS"
labels:
- 'Stage-Beta'
rockspec:
  dependencies:
	- mod_cloud_notify_encrypted
	- mod_cloud_notify_priority_tag
	- mod_cloud_notify_filters
...

Introduction
============

This is a meta-module that simply enables all the modules required to support
Siskin or Snikket iOS on a Prosody server.

These are currently:

- mod_cloud_notify_encrypted
- mod_cloud_notify_priority_tag
- mod_cloud_notify_filters

See the individual module pages for more details.

Note: On MUC services you should also load mod_muc_offline_delivery directly
under the MUC component in your config file, that is not handled by this
module.

Configuration
=============

There is no configuration for this module, just add it to
modules\_enabled as normal.

Compatibility
=============

  ----- -------
  0.11  Should work
  ----- -------
  trunk Works
  ----- -------
