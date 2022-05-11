---
summary: Audit Logging
rockspec: {}
...

This module provides infrastructure for audit logging inside Prosody.

## What is audit logging?

Audit logs will contain security sensitive events, both for server-wide
incidents as well as user-specific.

This module, however, only provides the infrastructure for audit logging. It
does not, by itself, generate such logs. For that, other modules, such as
`mod_audit_auth` or `mod_audit_register` need to be loaded.

## A note on privacy

Audit logging is intended to ensure the security of a system. As such, its
contents are often at the same time highly sensitive (containing user names
and IP addresses, for instance) and allowed to be stored under common privacy
regulations.

Before using these modules, you may want to ensure that you are legally
allowed to store the data for the amount of time these modules will store it.
Note that it is currently not possible to store different event types with
different expiration times.
