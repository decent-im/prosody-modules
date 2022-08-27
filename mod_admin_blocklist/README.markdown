---
summary: Block s2s connections based on admin blocklists
...

This module uses the blocklists set by admins for blocking s2s
connections.

So if an admin blocks a bare domain using [Blocking Command][xep191]
via [mod\_blocklist][doc:modules:mod_blocklist] then no s2s connections
will be allowed to or from that domain.

# Configuring

## Prosody 0.12

Starting with Prosody 0.12, the role or roles that determine whether a
particular users blocklist is used can be configured:

```lua
-- This is the default:
admin_blocklist_roles = { "prosody:operator", "prosody:admin" }
```

## Prosody 0.11

In Prosody 0.11 the [`admins`][doc:admins] setting is used.
