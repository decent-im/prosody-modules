Simple module adding an endpoint meant to be used for health checks.

# Configuration

After installing, enable by adding to [`modules_enabled`][doc:modules_enabled] like many other modules:

``` lua
-- in the global section
modules_enabled = {
    -- Other globally enabled modules here...
    "http_health"; -- add
}
```

# Details

Adds a `http://your.prosody.example:5280/health` endpoint that returns either HTTP status code 200 when all appears to be good or 500 when any module
[status][doc:developers:moduleapi#logging-and-status] has been set to `error`.

# See also

- [mod_measure_modules] provides module statues via OpenMetrics
- [mod_http_status] provides all module status details as JSON via HTTP
