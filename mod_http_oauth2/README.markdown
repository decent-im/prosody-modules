---
labels:
- Stage-Alpha
summary: 'OAuth2 API'
rockspec:
  build:
    copy_directories:
    - html
...

Introduction
============

This module is a work-in-progress intended for developers only!

Configuration
=============

Dynamic client registration enabled by configuring a JWT key. Algorithm
defaults to *HS256*.

```lua
oauth2_registration_key = "securely generated JWT key here"
oauth2_registration_algorithm = "HS256"
oauth2_registration_options = { default_ttl = 60 * 60 * 24 * 90 }
```

Various flows can be disabled and enabled with
`allowed_oauth2_grant_types` and `allowed_oauth2_response_types`:

```lua
allowed_oauth2_grant_types = {
	"authorization_code"; -- authorization code grant
	"password"; -- resource owner password grant
}

allowed_oauth2_response_types = {
	"code"; -- authorization code flow
    -- "token"; -- implicit flow disabled by default
}
```


Compatibility
=============

Requires Prosody 0.12+ or trunk.
