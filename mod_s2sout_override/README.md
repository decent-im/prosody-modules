---
summary: Override s2s connection targets
---

This module replaces [mod_s2soutinjection] and uses more modern and
reliable methods for overriding connection targets.

# Configuration

Enable the module as usual, then specify a map of XMPP remote hostnames
to URIs like `"tcp://host.example:port"`, to have Prosody connect there
instead of doing normal DNS SRV resolution.

Currently supported schemes are `tcp://` and `tls://`.  A future version
could support more methods including alternate SRV lookup targets or
even UNIX sockets.

URIs with IP addresses like `tcp://127.0.0.1:9999` will bypass A/AAAA
DNS lookups.

```lua
-- Global section
modules_enabled = {
    -- other global modules
    "s2sout_override";
}

s2sout_override = {
    ["example.com"] = "tcp://other.host.example:5299";
    ["xmpp.example.net"] = "tcp://localhost:5999";
    ["secure.example"] = = "tls://127.0.0.1:5270";
}
```

# Compatibility

Prosody version   status
---------------   ----------
0.12.4            Will work
0.12.3            Will not work
0.11              Will not work
