---
summary: Yet another MUC reliability module
rockspec:
  dependencies:
  - mod_track_muc_joins
labels:
- Stage-Alpha
...


This module reacts to [server-to-server][doc:s2s] connections closing by
performing [XEP-0410: MUC Self-Ping] from the server side to check if
users are still connected to MUCs they have joined according
[mod_track_muc_joins].  If it can't be confirmed that the user is still
joined then their client devices are notified about this allowing them
to re-join.

# Installing

```
prosodyctl install mod_ping_muc
```

# Configuring

No configuration.  Enable as a regular module in
[`modules_enabled`][doc:modules_enabled] globally or under a
`VirtualHost`:

```lua
modules_enabled = {
	-- other modules etc
	"track_muc_joins",
	"ping_muc",
}
```

# Compatibility

Requires Prosody 0.12.x or trunk
